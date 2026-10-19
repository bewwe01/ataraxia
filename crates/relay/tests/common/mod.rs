//! Test harness: an in-process relay on 127.0.0.1 with a fresh self-signed certificate, and a
//! client that pins the relay's SPKI exactly as the Phase 4 client will (no CA trust at all).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::Signer as _;
use futures_util::{SinkExt as _, StreamExt as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use veil_relay::server::{Clock, Config, Shared};
use veil_relay::store::Store;
use veil_wire::{ClientFrame, ErrorCode, Request, Response, ServerFrame, VERSION};

pub struct TestRelay {
    pub addr: SocketAddr,
    pub pin: [u8; 32],
    pub dir: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestRelay {
    pub async fn start(cfg: Config) -> Self {
        Self::start_with_clock(cfg, veil_relay::server::system_clock()).await
    }

    pub async fn start_with_clock(cfg: Config, clock: Clock) -> Self {
        let dir = std::env::temp_dir().join(format!("veil-relay-test-{}", rand::random::<u64>()));
        let pin = veil_relay::tls::generate(&dir.join("tls"), vec!["relay.test".into(), "127.0.0.1".into()])
            .unwrap();
        let (tls, loaded) =
            veil_relay::tls::load(&dir.join("tls/cert.pem"), &dir.join("tls/key.pem")).unwrap();
        assert_eq!(pin, loaded);
        let store = Store::open(&dir.join("relay.redb"), cfg.quotas).unwrap();
        let shared = Shared::new(store, cfg, pin, clock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(veil_relay::server::serve(listener, tls, shared, async {
            let _ = rx.await;
        }));
        Self {
            addr,
            pin,
            dir,
            stop: Some(tx),
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.join("relay.redb")
    }

    pub async fn client(&self) -> Client {
        Client::connect(self.addr, self.pin).await.expect("connect")
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---- SPKI pinning (the client-side half of INV-NET-2) ----------------------------------

/// Reads one DER TLV at `at`; returns (tag, header length, content length).
fn der_tlv(b: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *b.get(at)?;
    let first = *b.get(at + 1)?;
    if first < 0x80 {
        return Some((tag, 2, usize::from(first)));
    }
    let n = usize::from(first & 0x7F);
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | usize::from(*b.get(at + 2 + i)?);
    }
    Some((tag, 2 + n, len))
}

/// Extracts the `SubjectPublicKeyInfo` DER from an X.509 certificate.
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (_, h, _) = der_tlv(cert, 0)?; // Certificate SEQUENCE
    let tbs = h;
    let (_, th, _) = der_tlv(cert, tbs)?; // TBSCertificate SEQUENCE
    let mut at = tbs + th;
    if der_tlv(cert, at)?.0 == 0xA0 {
        let (_, vh, vl) = der_tlv(cert, at)?; // [0] version
        at += vh + vl;
    }
    for _ in 0..5 {
        // serial, signature, issuer, validity, subject
        let (_, eh, el) = der_tlv(cert, at)?;
        at += eh + el;
    }
    let (tag, sh, sl) = der_tlv(cert, at)?;
    (tag == 0x30).then(|| cert.get(at..at + sh + sl)).flatten()
}

#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = spki_of(end_entity.as_ref()).ok_or(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))?;
        let got: [u8; 32] = Sha256::digest(spki).into();
        if bool::from(subtle::ConstantTimeEq::ct_eq(&got[..], &self.pin[..])) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    /// A real TLS 1.2 check, so a TLS 1.2 probe fails only if the *server* refuses 1.2
    /// (review P3-7: refusing here made the "TLS 1.3 only" test pass vacuously).
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_tls(
    pin: [u8; 32],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth()
}

// ---- client ------------------------------------------------------------------------------

/// TLS handshake against the relay with the given versions; the rustls error if it fails.
pub async fn tls_handshake(
    addr: SocketAddr,
    pin: [u8; 32],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<(), rustls::Error> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let res = tokio_rustls::TlsConnector::from(Arc::new(client_tls(pin, versions)))
        .connect(ServerName::try_from("relay.test").unwrap(), tcp)
        .await;
    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(e
            .get_ref()
            .and_then(|i| i.downcast_ref::<rustls::Error>())
            .cloned()
            .unwrap_or(rustls::Error::General(e.to_string()))),
    }
}

pub struct Client {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    next: u64,
    pub pushes: Vec<ServerFrame>,
    /// Every frame this client sent, for INV-META-1 checks.
    pub sent: Vec<Vec<u8>>,
}

impl Client {
    pub async fn connect(addr: SocketAddr, pin: [u8; 32]) -> Result<Self, String> {
        Self::connect_from(addr, pin, std::net::Ipv4Addr::LOCALHOST).await
    }

    /// Connects from a chosen loopback address (127.0.0.0/8 is all local on Linux), so tests
    /// can act as a second source.
    pub async fn connect_from(
        addr: SocketAddr,
        pin: [u8; 32],
        local: std::net::Ipv4Addr,
    ) -> Result<Self, String> {
        let socket = tokio::net::TcpSocket::new_v4().map_err(|e| e.to_string())?;
        socket
            .bind(SocketAddr::new(local.into(), 0))
            .map_err(|e| e.to_string())?;
        let tcp = socket.connect(addr).await.map_err(|e| e.to_string())?;
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(client_tls(pin, &[&rustls::version::TLS13])));
        let tls = connector
            .connect(ServerName::try_from("relay.test").unwrap(), tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (ws, _) = tokio_tungstenite::client_async("wss://relay.test/", tls)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            ws,
            next: 1,
            pushes: Vec::new(),
            sent: Vec::new(),
        })
    }

    pub async fn send_raw(&mut self, bytes: Vec<u8>) {
        self.sent.push(bytes.clone());
        self.ws.send(Message::Binary(bytes.into())).await.unwrap();
    }

    /// Next non-push frame (pushes are collected in `self.pushes`).
    pub async fn recv(&mut self) -> Option<ServerFrame> {
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(10), self.ws.next())
                .await
                .ok()??
                .ok()?;
            let Message::Binary(b) = msg else { continue };
            let f = ServerFrame::decode_strict(&b).expect("relay frames must decode strictly");
            if f.id == 0 && matches!(f.resp, Some(Response::NewEnvelopes(_))) {
                self.pushes.push(f);
                continue;
            }
            return Some(f);
        }
    }

    pub async fn call(&mut self, req: Request) -> Result<Response, ErrorCode> {
        let id = self.next;
        self.next += 1;
        let frame = ClientFrame {
            v: VERSION,
            id,
            req: Some(req),
        };
        frame.validate().expect("test sends valid frames");
        self.send_raw(frame.encode()).await;
        let f = self.recv().await.expect("response");
        assert_eq!(f.id, id, "response id echoes the request");
        match f.resp.unwrap() {
            Response::Error(e) => Err(ErrorCode::try_from(e.code).unwrap()),
            r => Ok(r),
        }
    }

    /// Creates a mailbox and authenticates for it. Returns the signing key.
    pub async fn new_mailbox(&mut self, pin: [u8; 32], mailbox: [u8; 32]) -> ed25519_dalek::SigningKey {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        self.call(Request::CreateMailbox(veil_wire::CreateMailbox {
            mailbox_id: mailbox.to_vec(),
            auth_pub: key.verifying_key().to_bytes().to_vec(),
        }))
        .await
        .unwrap();
        self.auth(pin, mailbox, &key).await.unwrap();
        key
    }

    pub async fn auth(
        &mut self,
        pin: [u8; 32],
        mailbox: [u8; 32],
        key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ErrorCode> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.auth_at(pin, mailbox, key, now).await
    }

    /// Authenticates with an explicit timestamp (for relays on a test clock).
    pub async fn auth_at(
        &mut self,
        pin: [u8; 32],
        mailbox: [u8; 32],
        key: &ed25519_dalek::SigningKey,
        now: u64,
    ) -> Result<(), ErrorCode> {
        let Response::Challenge(c) = self
            .call(Request::Challenge(veil_wire::MailboxRef {
                mailbox_id: mailbox.to_vec(),
            }))
            .await?
        else {
            panic!("expected challenge")
        };
        let sig = key.sign(&veil_wire::auth_message(&pin, &mailbox, &c.nonce, now));
        self.call(Request::Authenticate(veil_wire::Authenticate {
            mailbox_id: mailbox.to_vec(),
            unix_secs: now,
            signature: sig.to_bytes().to_vec(),
        }))
        .await
        .map(|_| ())
    }

    pub async fn add_token(&mut self, mailbox: [u8; 32], token: [u8; 32]) {
        self.call(Request::UpdateTokens(veil_wire::UpdateTokens {
            mailbox_id: mailbox.to_vec(),
            add: vec![veil_relay::server::token_hash(&token).to_vec()],
            remove: vec![],
        }))
        .await
        .unwrap();
    }

    pub async fn deposit(
        &mut self,
        mailbox: [u8; 32],
        token: [u8; 32],
        envelope: Vec<u8>,
    ) -> Result<Response, ErrorCode> {
        self.call(Request::Deposit(veil_wire::Deposit {
            mailbox_id: mailbox.to_vec(),
            token: token.to_vec(),
            envelope,
        }))
        .await
    }

    pub async fn fetch(&mut self, mailbox: [u8; 32], after: u64) -> Result<veil_wire::Envelopes, ErrorCode> {
        match self
            .call(Request::Fetch(veil_wire::Fetch {
                mailbox_id: mailbox.to_vec(),
                after_seq: after,
                limit: 32,
            }))
            .await?
        {
            Response::Envelopes(e) => Ok(e),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Sends an application-level `Ping`; false if the relay has hung up.
    pub async fn try_ping(&mut self) -> bool {
        let frame = ClientFrame {
            v: VERSION,
            id: 99_999,
            req: Some(Request::Ping(veil_wire::Empty {})),
        };
        if self
            .ws
            .send(Message::Binary(frame.encode().into()))
            .await
            .is_err()
        {
            return false;
        }
        matches!(self.recv().await, Some(f) if f.id == 99_999)
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
