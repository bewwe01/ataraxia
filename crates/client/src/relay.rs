//! Relay transport: TLS 1.3 with the relay's SPKI pinned (no CA trust at all; INV-NET-2),
//! WebSocket, one strict protobuf frame per message (PROTOCOL §6.3).
//!
//! A pin mismatch is a hard failure with no override. The relay is untrusted: every frame it
//! sends is decoded strictly, and a response whose type does not fit the request is an error.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use veil_wire::{ClientFrame, ErrorCode, Request, Response, ServerFrame, VERSION};

use crate::ClientError;

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Reads one DER TLV at `at`: (tag, header length, content length).
fn der_tlv(b: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *b.get(at)?;
    let first = *b.get(at.checked_add(1)?)?;
    if first < 0x80 {
        return Some((tag, 2, usize::from(first)));
    }
    let n = usize::from(first & 0x7F);
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        let byte = *b.get(at.checked_add(2)?.checked_add(i)?)?;
        len = len.checked_mul(256)?.checked_add(usize::from(byte))?;
    }
    Some((tag, n.checked_add(2)?, len))
}

/// The DER `SubjectPublicKeyInfo` of an X.509 certificate.
pub(crate) fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (_, h, _) = der_tlv(cert, 0)?; // Certificate SEQUENCE
    let tbs = h;
    let (_, th, _) = der_tlv(cert, tbs)?; // TBSCertificate SEQUENCE
    let mut at = tbs.checked_add(th)?;
    if der_tlv(cert, at)?.0 == 0xA0 {
        let (_, vh, vl) = der_tlv(cert, at)?; // [0] version
        at = at.checked_add(vh)?.checked_add(vl)?;
    }
    for _ in 0..5 {
        // serial, signature, issuer, validity, subject
        let (_, eh, el) = der_tlv(cert, at)?;
        at = at.checked_add(eh)?.checked_add(el)?;
    }
    let (tag, sh, sl) = der_tlv(cert, at)?;
    if tag != 0x30 {
        return None;
    }
    cert.get(at..at.checked_add(sh)?.checked_add(sl)?)
}

/// Accepts exactly the certificate whose SPKI hashes to the pin; TLS 1.3 signatures only.
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

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable: the client config offers TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
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

fn tls_config(pin: [u8; 32]) -> Result<rustls::ClientConfig, ClientError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ClientError::Relay)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth())
}

/// Splits `host:port`, accepting `[v6]:port`. An IPv6 host must be bracketed.
pub(crate) fn split_host_port(addr: &str) -> Result<(String, u16), ClientError> {
    let (host, port) = addr.rsplit_once(':').ok_or(ClientError::BadInput)?;
    let host = match host.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']').ok_or(ClientError::BadInput)?,
        None if host.contains([':', '[', ']']) => return Err(ClientError::BadInput),
        None => host,
    };
    let port: u16 = port.parse().map_err(|_| ClientError::BadInput)?;
    if host.is_empty() || host.len() > 253 || port == 0 {
        return Err(ClientError::BadInput);
    }
    Ok((host.to_owned(), port))
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<ServerFrame>>>>;

/// A live, pinned connection to the relay.
pub struct Relay {
    out: mpsc::Sender<Vec<u8>>,
    pending: Pending,
    next: AtomicU64,
}

impl core::fmt::Debug for Relay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Relay")
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Relay {
    /// Connects and returns the connection plus a channel of pushes (`NewEnvelopes`), which
    /// closes when the connection drops.
    pub async fn connect(
        addr: &str,
        pin: [u8; 32],
    ) -> Result<(Self, mpsc::Receiver<ServerFrame>), ClientError> {
        let (host, port) = split_host_port(addr)?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| ClientError::Unreachable)?
            .map_err(|_| ClientError::Unreachable)?;
        let name = ServerName::try_from(host.clone()).map_err(|_| ClientError::BadInput)?;
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_rustls::TlsConnector::from(Arc::new(tls_config(pin)?)).connect(name, tcp),
        )
        .await
        .map_err(|_| ClientError::Unreachable)?
        .map_err(|_| ClientError::PinMismatch)?;
        let cfg = WebSocketConfig::default()
            .max_message_size(Some(veil_wire::MAX_FRAME))
            .max_frame_size(Some(veil_wire::MAX_FRAME));
        let (ws, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async_with_config(
                if host.contains(':') {
                    format!("wss://[{host}]/")
                } else {
                    format!("wss://{host}/")
                },
                tls,
                Some(cfg),
            ),
        )
        .await
        .map_err(|_| ClientError::Unreachable)?
        .map_err(|_| ClientError::Relay)?;
        let (mut sink, mut source) = ws.split();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (push_tx, push_rx) = mpsc::channel::<ServerFrame>(64);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let reader_pending = Arc::clone(&pending);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = out_rx.recv() => {
                        let Some(bytes) = msg else { break };
                        if sink.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    incoming = source.next() => {
                        let bytes = match incoming {
                            Some(Ok(Message::Binary(b))) => b,
                            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                            _ => break,
                        };
                        // Anything that is not a strict, valid frame ends the connection.
                        let Ok(frame) = ServerFrame::decode_strict(&bytes) else { break };
                        if frame.id == 0 {
                            if push_tx.try_send(frame).is_err() {
                                // Pushes are hints; a full queue only delays the next fetch.
                            }
                        } else if let Some(tx) = lock(&reader_pending).remove(&frame.id) {
                            let _ = tx.send(frame);
                        }
                    }
                }
            }
            lock(&reader_pending).clear();
            let _ = sink.close().await;
        });
        Ok((
            Self {
                out: out_tx,
                pending,
                next: AtomicU64::new(1),
            },
            push_rx,
        ))
    }

    /// Sends one request and waits for its response. Relay error codes become
    /// [`ClientError::Rejected`].
    pub async fn call(&self, req: Request) -> Result<Response, ClientError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let frame = ClientFrame {
            v: VERSION,
            id,
            req: Some(req),
        };
        frame.validate().map_err(|_| ClientError::BadInput)?;
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);
        if self.out.send(frame.encode()).await.is_err() {
            lock(&self.pending).remove(&id);
            return Err(ClientError::Unreachable);
        }
        let reply = tokio::time::timeout(CALL_TIMEOUT, rx).await;
        lock(&self.pending).remove(&id);
        let frame = reply
            .map_err(|_| ClientError::Unreachable)?
            .map_err(|_| ClientError::Unreachable)?;
        match frame.resp {
            Some(Response::Error(e)) => Err(ClientError::Rejected(
                ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
            )),
            Some(r) => Ok(r),
            None => Err(ClientError::Relay),
        }
    }

    /// Whether the connection is still up.
    pub fn is_open(&self) -> bool {
        !self.out.is_closed()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parsing() {
        assert_eq!(
            split_host_port("relay.example.org:8443").unwrap(),
            ("relay.example.org".into(), 8443)
        );
        assert_eq!(split_host_port("[::1]:8443").unwrap(), ("::1".into(), 8443));
        for bad in [
            "relay",
            ":8443",
            "relay:0",
            "relay:99999",
            "relay:x",
            "[::1:8443",
            "::1]:8443",
            "::1:8443",
            "[]:8443",
        ] {
            assert!(split_host_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn der_walker_never_panics() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i: u8| i.wrapping_mul(37)).collect();
            let _ = spki_of(&junk);
        }
        assert!(spki_of(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_none());
    }
}
