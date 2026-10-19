//! Relay integration tests over real TLS 1.3 + WebSocket (Phase 3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

mod common;

use common::{Client, TestRelay};
use ed25519_dalek::Signer as _;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use veil_core::account::{Account, IntroFields, Opened};
use veil_core::content::{Body, Content, Text};
use veil_core::invite::{Invite, InviteMode};
use veil_core::store::MemoryBackend;
use veil_relay::limits::Rate;
use veil_relay::server::Config;
use veil_wire::{ErrorCode, Request, Response};

fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn text(s: &str) -> Content {
    Content {
        id: veil_core::account::random_id(&mut rng()),
        sent_at_ms: 1,
        body: Some(Body::Text(Text {
            body: s.into(),
            ..Default::default()
        })),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// INV-META-1 + INV-PAIR-2 + the core path end to end: Bob invites, Alice takes the invite
/// from the relay, redeems it, deposits her intro into Bob's mailbox; Bob fetches, opens,
/// replies into Alice's mailbox. Every byte either client sent, and the relay's database
/// file, are then searched for identity keys, addresses and display names.
#[tokio::test]
async fn pairing_and_messages_through_the_relay_reveal_no_identity() {
    let relay = TestRelay::start(Config::default()).await;
    let (alice, bob) = (
        Account::create(MemoryBackend::new(), &mut rng()).unwrap(),
        Account::create(MemoryBackend::new(), &mut rng()).unwrap(),
    );
    let (bob_mbox, bob_token): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let (alice_mbox, alice_token): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());

    // Bob: mailbox + token for the invite, then the invite itself.
    let mut b = relay.client().await;
    b.new_mailbox(relay.pin, bob_mbox).await;
    b.add_token(bob_mbox, bob_token).await;
    let created = bob
        .create_invite(
            &mut rng(),
            InviteMode::Remote,
            "wss://relay.test",
            relay.pin,
            bob_mbox,
            bob_token,
            now(),
            3600,
        )
        .await
        .unwrap();
    let put = Request::PutInvite(veil_wire::PutInvite {
        mailbox_id: bob_mbox.to_vec(),
        invite_id: created.invite.id.to_vec(),
        sealed: created.sealed_package.clone(),
        expires_at: now() + 3600,
    });
    b.call(put).await.unwrap();

    // Alice: her own mailbox, then take + redeem the invite from the link alone.
    let mut a = relay.client().await;
    a.new_mailbox(relay.pin, alice_mbox).await;
    a.add_token(alice_mbox, alice_token).await;
    let link = created.invite.to_link();
    let invite = Invite::from_link(&link).unwrap();
    let take = Request::TakeInvite(veil_wire::TakeInvite {
        invite_id: invite.id.to_vec(),
    });
    let Response::Invite(pkg) = a.call(take.clone()).await.unwrap() else {
        panic!()
    };
    // INV-PAIR-2: served once.
    assert_eq!(a.call(take).await, Err(ErrorCode::NotFound));
    let fields = IntroFields {
        mailbox_id: alice_mbox,
        delivery_token: alice_token,
        display_name: Some("Alice Canary-7e11".into()),
        rekey: None,
    };
    let red = alice
        .redeem_invite(&mut rng(), &invite, &pkg.sealed, fields, now())
        .await
        .unwrap();
    assert_eq!(red.contact_mailbox_id, bob_mbox);
    a.deposit(red.contact_mailbox_id, red.contact_delivery_token, red.envelope)
        .await
        .unwrap();

    // Bob gets a push, fetches and opens the intro.
    let env = b.fetch(bob_mbox, 0).await.unwrap();
    assert_eq!(env.items.len(), 1);
    assert_eq!(env.last_seq, 1);
    let Opened::NewContact { intro, .. } = bob.open(&mut rng(), &env.items[0].envelope, now()).await.unwrap()
    else {
        panic!("expected a new contact")
    };
    b.call(Request::Ack(veil_wire::Ack {
        mailbox_id: bob_mbox.to_vec(),
        up_to_seq: 1,
    }))
    .await
    .unwrap();
    assert!(
        b.fetch(bob_mbox, 0).await.unwrap().items.is_empty(),
        "acked envelopes are deleted"
    );

    // Bob replies into Alice's mailbox with the token from her intro.
    let to_alice: [u8; 32] = intro.mailbox_id.as_slice().try_into().unwrap();
    let alice_tok: [u8; 32] = intro.delivery_token.as_slice().try_into().unwrap();
    for i in 0..3 {
        let env = bob
            .seal(
                &mut rng(),
                &alice.identity().address(),
                &text(&format!("hello {i}")),
                now(),
            )
            .await
            .unwrap();
        b.deposit(to_alice, alice_tok, env).await.unwrap();
    }
    let got = a.fetch(alice_mbox, 0).await.unwrap();
    assert_eq!(got.items.iter().map(|i| i.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    for (i, item) in got.items.iter().enumerate() {
        match alice.open(&mut rng(), &item.envelope, now()).await.unwrap() {
            Opened::Message { content, .. } => {
                assert!(matches!(content.body, Some(Body::Text(t)) if t.body == format!("hello {i}")));
            }
            Opened::NewContact { .. } => panic!("unexpected"),
        }
    }

    // ---- INV-META-1: nothing identifying in anything sent to the relay ----
    let secrets: Vec<(&str, Vec<u8>)> = vec![
        (
            "alice identity key",
            alice.identity().public().serialize().to_vec(),
        ),
        ("bob identity key", bob.identity().public().serialize().to_vec()),
        (
            "alice identity key (raw 32)",
            alice.identity().public().serialize()[1..].to_vec(),
        ),
        (
            "bob identity key (raw 32)",
            bob.identity().public().serialize()[1..].to_vec(),
        ),
        (
            "alice address",
            alice.identity().address().as_str().as_bytes().to_vec(),
        ),
        (
            "bob address",
            bob.identity().address().as_str().as_bytes().to_vec(),
        ),
        ("display name", b"Canary-7e11".to_vec()),
        ("message text", b"hello 1".to_vec()),
    ];
    for frame in a.sent.iter().chain(&b.sent) {
        for (what, needle) in &secrets {
            assert!(!contains(frame, needle), "{what} sent to the relay");
        }
    }
    a.close().await;
    b.close().await;

    // ---- INV-META-2: the relay's database holds none of that, and no client IP ----
    drop(relay.client().await); // touch, then read the file
    let db = std::fs::read(relay.db_path()).unwrap();
    for (what, needle) in &secrets {
        assert!(!contains(&db, needle), "{what} found in the relay database");
    }
    for (what, needle) in [
        ("IPv4 text", b"127.0.0.1".to_vec()),
        ("IPv4 bytes", vec![127, 0, 0, 1]),
    ] {
        assert!(!contains(&db, &needle), "{what} found in the relay database");
    }
}

async fn challenge_for(c: &mut Client, m: [u8; 32]) -> Vec<u8> {
    let req = Request::Challenge(veil_wire::MailboxRef {
        mailbox_id: m.to_vec(),
    });
    let Response::Challenge(ch) = c.call(req).await.unwrap() else {
        panic!()
    };
    ch.nonce
}

/// PROTOCOL §2: challenge-response auth. Bad signature, replayed nonce, stale timestamp, a
/// nonce for another mailbox, and unauthenticated access are all refused.
#[tokio::test]
async fn mailbox_authentication_is_strict() {
    let relay = TestRelay::start(Config::default()).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    let key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    c.call(Request::CreateMailbox(veil_wire::CreateMailbox {
        mailbox_id: m.to_vec(),
        auth_pub: key.verifying_key().to_bytes().to_vec(),
    }))
    .await
    .unwrap();
    // Not authenticated yet.
    assert_eq!(c.fetch(m, 0).await.unwrap_err(), ErrorCode::Unauthorized);

    let authenticate = |sig: Vec<u8>, secs: u64| {
        Request::Authenticate(veil_wire::Authenticate {
            mailbox_id: m.to_vec(),
            unix_secs: secs,
            signature: sig,
        })
    };
    let sign = |pin: &[u8; 32], nonce: &[u8], secs: u64, k: &ed25519_dalek::SigningKey| {
        k.sign(&veil_wire::auth_message(pin, &m, nonce, secs))
            .to_bytes()
            .to_vec()
    };

    // Wrong key.
    let n = challenge_for(&mut c, m).await;
    let other = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    assert_eq!(
        c.call(authenticate(sign(&relay.pin, &n, now(), &other), now()))
            .await,
        Err(ErrorCode::Unauthorized)
    );
    // That nonce is now spent: even the right signature over it fails.
    assert_eq!(
        c.call(authenticate(sign(&relay.pin, &n, now(), &key), now()))
            .await,
        Err(ErrorCode::Unauthorized)
    );
    // Wrong relay pin in the signed message (a signature made for another relay).
    let n = challenge_for(&mut c, m).await;
    assert_eq!(
        c.call(authenticate(sign(&[0; 32], &n, now(), &key), now())).await,
        Err(ErrorCode::Unauthorized)
    );
    // Stale timestamp (beyond ±120 s).
    let n = challenge_for(&mut c, m).await;
    let old = now() - 500;
    assert_eq!(
        c.call(authenticate(sign(&relay.pin, &n, old, &key), old)).await,
        Err(ErrorCode::Unauthorized)
    );
    // Authenticate without any outstanding challenge.
    assert_eq!(
        c.call(authenticate(sign(&relay.pin, &[0; 32], now(), &key), now()))
            .await,
        Err(ErrorCode::Unauthorized)
    );
    // Correct.
    let n = challenge_for(&mut c, m).await;
    c.call(authenticate(sign(&relay.pin, &n, now(), &key), now()))
        .await
        .unwrap();
    assert!(c.fetch(m, 0).await.is_ok());

    // Another connection is not authenticated, and a nonce cannot be moved between them.
    let mut d = relay.client().await;
    assert_eq!(d.fetch(m, 0).await.unwrap_err(), ErrorCode::Unauthorized);
    let n = challenge_for(&mut c, m).await;
    assert_eq!(
        d.call(authenticate(sign(&relay.pin, &n, now(), &key), now()))
            .await,
        Err(ErrorCode::Unauthorized)
    );
    // Challenges are issued for unknown mailboxes too (no existence oracle).
    let unknown: [u8; 32] = rand::random();
    assert!(matches!(
        d.call(Request::Challenge(veil_wire::MailboxRef {
            mailbox_id: unknown.to_vec()
        }))
        .await,
        Ok(Response::Challenge(_))
    ));
    // Creating an existing mailbox fails; an invalid Ed25519 key is refused.
    let dup = Request::CreateMailbox(veil_wire::CreateMailbox {
        mailbox_id: m.to_vec(),
        auth_pub: key.verifying_key().to_bytes().to_vec(),
    });
    assert_eq!(d.call(dup).await, Err(ErrorCode::Conflict));
}

/// PROTOCOL §2: deposits need a registered token; unknown mailbox and unknown token are
/// indistinguishable; blocking (removing the token) stops a sender; pushes arrive.
#[tokio::test]
async fn deposits_need_a_token_and_trigger_pushes() {
    let relay = TestRelay::start(Config::default()).await;
    let mut owner = relay.client().await;
    let m: [u8; 32] = rand::random();
    owner.new_mailbox(relay.pin, m).await;
    let (tok, other_tok): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    owner.add_token(m, tok).await;

    let mut sender = relay.client().await;
    assert_eq!(
        sender.deposit(m, other_tok, vec![0; 1024]).await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        sender.deposit(rand::random(), tok, vec![0; 1024]).await,
        Err(ErrorCode::Unauthorized)
    );
    sender.deposit(m, tok, vec![7; 1024]).await.unwrap();

    // The owner's connection receives a push without asking.
    let push = owner.recv_any().await;
    assert!(
        matches!(push.resp, Some(Response::NewEnvelopes(ref n)) if n.mailbox_id == m.to_vec() && n.last_seq == 1)
    );

    owner
        .call(Request::UpdateTokens(veil_wire::UpdateTokens {
            mailbox_id: m.to_vec(),
            add: vec![],
            remove: vec![veil_relay::server::token_hash(&tok).to_vec()],
        }))
        .await
        .unwrap();
    assert_eq!(
        sender.deposit(m, tok, vec![0; 1024]).await,
        Err(ErrorCode::Unauthorized),
        "blocked"
    );
    // Envelopes that are not exactly a bucket size never reach the relay logic.
    assert_eq!(sender.deposit_raw_invalid(m, tok).await, ErrorCode::Malformed);
}

impl Client {
    async fn recv_any(&mut self) -> veil_wire::ServerFrame {
        if let Some(p) = self.pushes.pop() {
            return p;
        }
        // Pushes are filed by `recv`; send a ping to give the push a chance to arrive.
        let _ = self.call(Request::Ping(veil_wire::Empty {})).await;
        self.pushes.pop().expect("a push")
    }

    async fn deposit_raw_invalid(&mut self, m: [u8; 32], tok: [u8; 32]) -> ErrorCode {
        let frame = veil_wire::ClientFrame {
            v: veil_wire::VERSION,
            id: 999,
            req: Some(Request::Deposit(veil_wire::Deposit {
                mailbox_id: m.to_vec(),
                token: tok.to_vec(),
                envelope: vec![0; 1000],
            })),
        };
        self.send_raw(prost_encode(&frame)).await;
        let f = self.recv().await.unwrap();
        match f.resp.unwrap() {
            Response::Error(e) => ErrorCode::try_from(e.code).unwrap(),
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn prost_encode(f: &veil_wire::ClientFrame) -> Vec<u8> {
    f.encode()
}

/// Rate limits are per delivery token and per connection, never per IP.
#[tokio::test]
async fn deposits_are_rate_limited_per_token() {
    let mut cfg = Config::default();
    cfg.limits.deposit_per_token = Rate {
        burst: 3,
        per_sec: 0.001,
    };
    let relay = TestRelay::start(cfg).await;
    let mut owner = relay.client().await;
    let m: [u8; 32] = rand::random();
    owner.new_mailbox(relay.pin, m).await;
    let (t1, t2): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    owner.add_token(m, t1).await;
    owner.add_token(m, t2).await;
    let mut s = relay.client().await;
    for _ in 0..3 {
        s.deposit(m, t1, vec![0; 1024]).await.unwrap();
    }
    assert_eq!(s.deposit(m, t1, vec![0; 1024]).await, Err(ErrorCode::RateLimited));
    // Another token (another contact) is unaffected, even from the same connection.
    s.deposit(m, t2, vec![0; 1024]).await.unwrap();
}

/// PROTOCOL §9: resumable blob upload with a one-time token; download only when complete.
#[tokio::test]
async fn blobs_upload_resume_and_download() {
    let relay = TestRelay::start(Config::default()).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    c.new_mailbox(relay.pin, m).await;
    let Response::UploadToken(t) = c
        .call(Request::BlobUploadToken(veil_wire::MailboxRef {
            mailbox_id: m.to_vec(),
        }))
        .await
        .unwrap()
    else {
        panic!()
    };
    let blob: [u8; 32] = rand::random();
    let chunk = |i: u32, data: Vec<u8>| {
        Request::BlobPut(veil_wire::BlobPut {
            upload_token: t.upload_token.clone(),
            blob_id: blob.to_vec(),
            chunk_index: i,
            total_chunks: 2,
            data,
        })
    };
    let full = vec![0xAB; veil_wire::MAX_BLOB_CHUNK];
    c.call(chunk(0, full.clone())).await.unwrap();
    // Not downloadable until complete; anyone may download once complete (the key is E2EE).
    let mut other = relay.client().await;
    let get = |i: u32| {
        Request::BlobGet(veil_wire::BlobGet {
            blob_id: blob.to_vec(),
            chunk_index: i,
        })
    };
    assert_eq!(other.call(get(0)).await, Err(ErrorCode::NotFound));
    c.call(chunk(0, full.clone())).await.unwrap(); // resume: re-send
    c.call(chunk(1, vec![0xCD; 100])).await.unwrap();
    let Response::BlobChunk(b0) = other.call(get(0)).await.unwrap() else {
        panic!()
    };
    assert_eq!((b0.total_chunks, b0.data), (2, full));
    let Response::BlobChunk(b1) = other.call(get(1)).await.unwrap() else {
        panic!()
    };
    assert_eq!(b1.data, vec![0xCD; 100]);
    // The token is consumed.
    assert_eq!(
        c.call(chunk(1, vec![0xCD; 100])).await,
        Err(ErrorCode::Unauthorized)
    );
    // An unauthenticated connection cannot get an upload token.
    assert_eq!(
        other
            .call(Request::BlobUploadToken(veil_wire::MailboxRef {
                mailbox_id: m.to_vec()
            }))
            .await,
        Err(ErrorCode::Unauthorized)
    );
}

/// PROTOCOL §8: TURN credentials only for authenticated mailboxes; no identity inside.
#[tokio::test]
async fn turn_credentials() {
    let cfg = Config {
        turn: Some(veil_relay::turn::TurnConfig {
            secret: zeroize::Zeroizing::new(vec![7; 32]),
            urls: vec!["turns:turn.relay.test:5349".into()],
            ttl_secs: 3600,
        }),
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    let req = Request::TurnCredentials(veil_wire::MailboxRef {
        mailbox_id: m.to_vec(),
    });
    assert_eq!(c.call(req.clone()).await, Err(ErrorCode::Unauthorized));
    c.new_mailbox(relay.pin, m).await;
    let Response::Turn(t) = c.call(req).await.unwrap() else {
        panic!()
    };
    let (exp, _) = t.username.split_once(':').unwrap();
    assert!(exp.parse::<u64>().unwrap() > now());
    assert!(!t.username.contains(&common_hex(&m[..4])));
    assert_eq!(t.urls, vec!["turns:turn.relay.test:5349".to_owned()]);
    // Without TURN configured the request is refused cleanly.
    let plain = TestRelay::start(Config::default()).await;
    let mut d = plain.client().await;
    d.new_mailbox(plain.pin, m).await;
    assert_eq!(
        d.call(Request::TurnCredentials(veil_wire::MailboxRef {
            mailbox_id: m.to_vec()
        }))
        .await,
        Err(ErrorCode::Unsupported)
    );
}

fn common_hex(b: &[u8]) -> String {
    veil_relay::tls::hex(b)
}

/// INV-NET-2 (relay side): only TLS 1.3, and a client pinning another key cannot connect.
#[tokio::test]
async fn tls_is_1_3_only_and_pinned() {
    let relay = TestRelay::start(Config::default()).await;
    assert!(
        Client::connect(relay.addr, [0x42; 32]).await.is_err(),
        "wrong pin must fail"
    );
    // A TLS 1.2-only client is refused.
    let tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let cfg = common::client_tls(relay.pin, &[&rustls::version::TLS12]);
    let res = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from("relay.test").unwrap(),
            tcp,
        )
        .await;
    assert!(res.is_err(), "TLS 1.2 must be refused");
    // Plain TCP (no TLS): the relay never answers in plaintext. A TLS server replies to a
    // non-TLS ClientHello with an alert record (content type 0x15) or closes.
    let mut tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut tcp, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut tcp, &mut buf),
    )
    .await;
    if let Ok(Ok(n)) = read {
        assert!(n == 0 || buf[0] == 0x15, "plaintext answer: {:?}", &buf[..n]);
        assert!(!contains(&buf[..n], b"HTTP"), "no plaintext HTTP service");
    }
}

/// Hostile frames: garbage, wrong version, oversize and text frames never crash the relay,
/// and a valid client keeps working afterwards.
#[tokio::test]
async fn hostile_frames_are_refused_without_harm() {
    let relay = TestRelay::start(Config::default()).await;
    let mut c = relay.client().await;
    c.send_raw(vec![0xFF; 100]).await;
    assert!(
        matches!(c.recv().await.unwrap().resp, Some(Response::Error(e)) if e.code == ErrorCode::Malformed as i32)
    );
    let v2 = veil_wire::ClientFrame {
        v: 2,
        id: 5,
        req: Some(Request::Ping(veil_wire::Empty {})),
    };
    c.send_raw(v2.encode()).await;
    assert!(
        matches!(c.recv().await.unwrap().resp, Some(Response::Error(e)) if e.code == ErrorCode::Unsupported as i32)
    );
    // Oversize: the WebSocket layer drops the connection before parsing.
    let mut big = relay.client().await;
    big.send_raw(vec![0; veil_wire::MAX_CLIENT_FRAME + 10]).await;
    assert!(big.recv().await.is_none(), "oversize frame closes the connection");
    // The relay is still up for everyone else.
    let mut d = relay.client().await;
    assert!(matches!(
        d.call(Request::Ping(veil_wire::Empty {})).await,
        Ok(Response::Ok(_))
    ));
}

/// Mailbox creation is rate limited relay-wide (anti-abuse without IPs).
#[tokio::test]
async fn mailbox_creation_is_rate_limited() {
    let mut cfg = Config::default();
    cfg.limits.create_mailbox = Rate {
        burst: 2,
        per_sec: 0.001,
    };
    let relay = TestRelay::start(cfg).await;
    let mut c = relay.client().await;
    let create = |id: [u8; 32]| {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        Request::CreateMailbox(veil_wire::CreateMailbox {
            mailbox_id: id.to_vec(),
            auth_pub: key.verifying_key().to_bytes().to_vec(),
        })
    };
    c.call(create(rand::random())).await.unwrap();
    c.call(create(rand::random())).await.unwrap();
    assert_eq!(c.call(create(rand::random())).await, Err(ErrorCode::RateLimited));
}

/// INV-META-2 (logs): during a full session (create, auth, tokens, deposits, fetch, ack,
/// invites, blobs, errors) the relay logs nothing that identifies a client: no IP, no
/// mailbox id, no token, no size. Captured with a test subscriber at DEBUG level.
#[tokio::test(flavor = "current_thread")]
async fn relay_logs_nothing_about_clients() {
    use std::sync::{Arc, Mutex};
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let sink = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let relay = TestRelay::start(Config::default()).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    let tok: [u8; 32] = rand::random();
    c.new_mailbox(relay.pin, m).await;
    c.add_token(m, tok).await;
    let mut s = relay.client().await;
    s.deposit(m, tok, vec![0x5A; 4096]).await.unwrap();
    let _ = s.deposit(m, [9; 32], vec![0; 1024]).await;
    c.fetch(m, 0).await.unwrap();
    c.call(Request::Ack(veil_wire::Ack {
        mailbox_id: m.to_vec(),
        up_to_seq: 1,
    }))
    .await
    .unwrap();
    let inv = Request::PutInvite(veil_wire::PutInvite {
        mailbox_id: m.to_vec(),
        invite_id: vec![3; 16],
        sealed: vec![1; veil_wire::SEALED_INVITE_LEN],
        expires_at: now() + 100,
    });
    c.call(inv).await.unwrap();
    s.call(Request::TakeInvite(veil_wire::TakeInvite {
        invite_id: vec![3; 16],
    }))
    .await
    .unwrap();
    s.send_raw(vec![0xFF; 10]).await;
    let _ = s.recv().await;
    c.close().await;
    s.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let addr = relay.addr.to_string();
    for (what, needle) in [
        ("client IP", "127.0.0.1".to_owned()),
        ("relay port (connection info)", relay.addr.port().to_string()),
        ("listen address", addr),
        ("mailbox id (hex)", veil_relay::tls::hex(&m)),
        ("mailbox id prefix (hex)", veil_relay::tls::hex(&m[..6])),
        ("token (hex)", veil_relay::tls::hex(&tok[..6])),
        ("envelope size", "4096".to_owned()),
        ("invite size", veil_wire::SEALED_INVITE_LEN.to_string()),
    ] {
        assert!(!logs.contains(&needle), "{what} in relay logs:\n{logs}");
    }
}
