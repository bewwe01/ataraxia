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
    // Positive control: a client able to do both 1.2 and 1.3 (with a working 1.2 signature
    // check) connects, so the refusal below can only come from the server.
    let both = [&rustls::version::TLS13, &rustls::version::TLS12];
    common::tls_handshake(relay.addr, relay.pin, &both).await.unwrap();
    // A TLS 1.2-only client is refused by the server with a protocol_version alert.
    let res = common::tls_handshake(relay.addr, relay.pin, &[&rustls::version::TLS12]).await;
    assert_eq!(
        res,
        Err(rustls::Error::AlertReceived(
            rustls::AlertDescription::ProtocolVersion
        )),
        "TLS 1.2 must be refused by the relay"
    );
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

fn fetch_frame(m: [u8; 32], id: u64) -> Vec<u8> {
    veil_wire::ClientFrame {
        v: veil_wire::VERSION,
        id,
        req: Some(Request::Fetch(veil_wire::Fetch {
            mailbox_id: m.to_vec(),
            after_seq: 0,
            limit: 32,
        })),
    }
    .encode()
}

/// P3-3: a client that requests large responses and never reads them is dropped after the
/// write timeout, releasing its connection slot (here the only one).
#[tokio::test]
async fn a_client_that_stops_reading_is_dropped() {
    let cfg = Config {
        max_connections: 1,
        write_timeout: std::time::Duration::from_secs(1),
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut a = relay.client().await;
    let (m, tok): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    a.new_mailbox(relay.pin, m).await;
    a.add_token(m, tok).await;
    for _ in 0..32 {
        a.deposit(m, tok, vec![0; 65_536]).await.unwrap();
    }
    // ~40 × 2 MiB of responses, never read: far more than the socket buffers hold.
    for i in 0..40 {
        a.send_raw(fetch_frame(m, 1_000 + i)).await;
    }
    assert!(
        Client::connect(relay.addr, relay.pin).await.is_err(),
        "the only slot is held"
    );
    let start = std::time::Instant::now();
    loop {
        if let Ok(mut b) = Client::connect(relay.addr, relay.pin).await
            && b.try_ping().await
        {
            break;
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "the non-reading client still holds the slot"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    drop(a);
}

/// P3-4: one source cannot hold more than its share of connections, and a connection that
/// never authenticates or delivers anything is closed, keep-alives notwithstanding.
#[tokio::test]
async fn connections_are_capped_per_source_and_must_authenticate() {
    let cfg = Config {
        max_connections_per_source: 2,
        pre_auth_timeout: std::time::Duration::from_secs(1),
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut idle = relay.client().await;
    let mut authed = relay.client().await;
    assert!(
        Client::connect(relay.addr, relay.pin).await.is_err(),
        "third connection from 127.0.0.1"
    );
    authed.new_mailbox(relay.pin, rand::random()).await;
    // Ping both for 2.5 s: only the authenticated one survives.
    let mut idle_alive = true;
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        idle_alive = idle_alive && idle.try_ping().await;
        assert!(authed.try_ping().await, "authenticated connection closed");
    }
    assert!(
        !idle_alive,
        "unauthenticated connection outlived the pre-auth timeout"
    );
    // Its slot is free again.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut again = relay.client().await;
    assert!(again.try_ping().await);
}

/// P3-5: invalid or conflicting creations do not spend the relay-wide budget, and one
/// connection cannot drain it.
#[tokio::test]
async fn mailbox_creation_budget_cannot_be_drained_by_bad_requests() {
    let mut cfg = Config::default();
    cfg.limits.create_mailbox = Rate {
        burst: 2,
        per_sec: 0.001,
    };
    let relay = TestRelay::start(cfg).await;
    let bad_key = (0u8..=255)
        .map(|b| [b; 32])
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .unwrap();
    let create = |id: [u8; 32], key: [u8; 32]| {
        Request::CreateMailbox(veil_wire::CreateMailbox {
            mailbox_id: id.to_vec(),
            auth_pub: key.to_vec(),
        })
    };
    let good = || {
        ed25519_dalek::SigningKey::from_bytes(&rand::random())
            .verifying_key()
            .to_bytes()
    };
    let mut flood = relay.client().await;
    for _ in 0..4 {
        assert_eq!(
            flood.call(create(rand::random(), bad_key)).await,
            Err(ErrorCode::Malformed)
        );
    }
    assert_eq!(
        flood.call(create(rand::random(), good())).await,
        Err(ErrorCode::RateLimited),
        "per-connection limit"
    );
    let mut b = relay.client().await;
    let id: [u8; 32] = rand::random();
    b.call(create(id, good())).await.unwrap();
    assert_eq!(b.call(create(id, good())).await, Err(ErrorCode::Conflict));
    b.call(create(rand::random(), good())).await.unwrap();
    let mut c = relay.client().await;
    assert_eq!(
        c.call(create(rand::random(), good())).await,
        Err(ErrorCode::RateLimited),
        "relay-wide budget (2) spent only by the two real creations"
    );
}

/// P3-11: deleting a mailbox revokes every connection's authentication for it, also when
/// the id is re-created with a new key.
#[tokio::test]
async fn deleting_a_mailbox_revokes_other_connections() {
    let relay = TestRelay::start(Config::default()).await;
    let m: [u8; 32] = rand::random();
    let mut one = relay.client().await;
    let key = one.new_mailbox(relay.pin, m).await;
    let mut two = relay.client().await;
    two.auth(relay.pin, m, &key).await.unwrap();
    two.fetch(m, 0).await.unwrap();
    one.call(Request::DeleteMailbox(veil_wire::MailboxRef {
        mailbox_id: m.to_vec(),
    }))
    .await
    .unwrap();
    one.new_mailbox(relay.pin, m).await; // same id, new key
    // P3R2-6: no pushes for the re-created mailbox reach the revoked connection.
    let tok: [u8; 32] = rand::random();
    one.add_token(m, tok).await;
    let mut sender = relay.client().await;
    sender.deposit(m, tok, vec![0; 1024]).await.unwrap();
    sender.deposit(m, tok, vec![0; 1024]).await.unwrap();
    assert!(two.try_ping().await && two.try_ping().await);
    assert!(two.pushes.is_empty(), "revoked connection got {:?}", two.pushes);
    assert_eq!(two.fetch(m, 0).await.unwrap_err(), ErrorCode::Unauthorized);
    assert_eq!(
        two.call(Request::UpdateTokens(veil_wire::UpdateTokens {
            mailbox_id: m.to_vec(),
            add: vec![vec![1; 32]],
            remove: vec![],
        }))
        .await,
        Err(ErrorCode::Unauthorized)
    );
    one.fetch(m, 0).await.unwrap();
}

/// P3-3: large responses draw on a relay-wide byte budget; a request that would exceed it is
/// refused with `RateLimited` instead of being buffered.
#[tokio::test]
async fn responses_draw_on_a_relay_wide_budget() {
    let cfg = Config {
        response_budget_bytes: 1024 * 1024,
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut c = relay.client().await;
    let m: [u8; 32] = rand::random();
    c.new_mailbox(relay.pin, m).await;
    let fetch = |limit| {
        Request::Fetch(veil_wire::Fetch {
            mailbox_id: m.to_vec(),
            after_seq: 0,
            limit,
        })
    };
    // 32 × 64 KiB worst case is 2 MiB, more than the whole budget.
    assert_eq!(c.call(fetch(32)).await, Err(ErrorCode::RateLimited));
    // 8 × 64 KiB fits, and the budget is returned after each reply.
    for _ in 0..5 {
        c.call(fetch(8)).await.unwrap();
    }
}

/// The per-connection frame limit answers with the request's id (not the push id 0), so a
/// client can tell which request was refused.
#[tokio::test]
async fn frame_rate_limit_echoes_the_request_id() {
    let mut cfg = Config::default();
    cfg.limits.frames_per_conn = Rate {
        burst: 3,
        per_sec: 0.001,
    };
    let relay = TestRelay::start(cfg).await;
    let mut c = relay.client().await;
    for _ in 0..3 {
        c.call(Request::Ping(veil_wire::Empty {})).await.unwrap();
    }
    // `call` asserts that the reply echoes the request id.
    assert_eq!(
        c.call(Request::Ping(veil_wire::Empty {})).await,
        Err(ErrorCode::RateLimited)
    );
}

/// P3R2-6: a mailbox that idles out and is re-created by someone else under the same id
/// never pushes to connections of the previous owner (no explicit delete is involved).
#[tokio::test]
async fn pushes_follow_the_current_mailbox_key() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    let t = Arc::new(AtomicU64::new(now()));
    let clock: veil_relay::server::Clock = {
        let t = Arc::clone(&t);
        Arc::new(move || t.load(Ordering::Relaxed))
    };
    let cfg = Config {
        sweep_interval: std::time::Duration::from_millis(50),
        ..Config::default()
    };
    let relay = TestRelay::start_with_clock(cfg, clock).await;
    let m: [u8; 32] = rand::random();
    let old_key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let mut old = relay.client().await;
    old.call(Request::CreateMailbox(veil_wire::CreateMailbox {
        mailbox_id: m.to_vec(),
        auth_pub: old_key.verifying_key().to_bytes().to_vec(),
    }))
    .await
    .unwrap();
    old.auth_at(relay.pin, m, &old_key, t.load(Ordering::Relaxed))
        .await
        .unwrap();
    // 61 days later the sweeper removes the idle mailbox; someone else takes the id.
    t.fetch_add(61 * 24 * 3600, Ordering::Relaxed);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let new_key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let mut new = Client::connect_from(relay.addr, relay.pin, std::net::Ipv4Addr::new(127, 0, 0, 2))
        .await
        .unwrap();
    new.call(Request::CreateMailbox(veil_wire::CreateMailbox {
        mailbox_id: m.to_vec(),
        auth_pub: new_key.verifying_key().to_bytes().to_vec(),
    }))
    .await
    .unwrap();
    new.auth_at(relay.pin, m, &new_key, t.load(Ordering::Relaxed))
        .await
        .unwrap();
    let tok: [u8; 32] = rand::random();
    new.add_token(m, tok).await;
    new.deposit(m, tok, vec![0; 1024]).await.unwrap();
    assert!(new.try_ping().await);
    assert_eq!(new.pushes.len(), 1, "the current owner is notified");
    assert!(old.try_ping().await && old.try_ping().await);
    assert!(old.pushes.is_empty(), "previous owner got {:?}", old.pushes);
}

/// P3R2-2: one source cannot hold the whole response budget: with 31 connections pipelining
/// full-size fetches and never reading, another source can still fetch.
#[tokio::test]
async fn one_source_cannot_hold_the_response_budget() {
    let cfg = Config {
        max_connections_per_source: 64,
        ..Config::default()
    };
    let relay = TestRelay::start(cfg).await;
    let mut owner = relay.client().await;
    let (m, tok): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let key = owner.new_mailbox(relay.pin, m).await;
    owner.add_token(m, tok).await;
    for _ in 0..32 {
        owner.deposit(m, tok, vec![0; 65_536]).await.unwrap();
    }
    let mut hogs = Vec::new();
    for i in 0..31u64 {
        let mut c = relay.client().await;
        c.auth(relay.pin, m, &key).await.unwrap();
        for j in 0..5 {
            c.send_raw(fetch_frame(m, 10_000 + i * 10 + j)).await;
        }
        hogs.push(c);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut victim = Client::connect_from(relay.addr, relay.pin, std::net::Ipv4Addr::new(127, 0, 0, 2))
        .await
        .unwrap();
    let v: [u8; 32] = rand::random();
    victim.new_mailbox(relay.pin, v).await;
    for _ in 0..5 {
        victim.fetch(v, 0).await.expect("another source can still fetch");
    }
    drop(hogs);
}

/// P3R2-3: reconnecting does not reset the creation limit: one source is capped, while
/// another source can still create.
#[tokio::test]
async fn mailbox_creation_is_limited_per_source() {
    let relay = TestRelay::start(Config::default()).await;
    let create = || {
        Request::CreateMailbox(veil_wire::CreateMailbox {
            mailbox_id: rand::random::<[u8; 32]>().to_vec(),
            auth_pub: ed25519_dalek::SigningKey::from_bytes(&rand::random())
                .verifying_key()
                .to_bytes()
                .to_vec(),
        })
    };
    let mut made = 0;
    let mut refused = false;
    for _ in 0..5 {
        let mut c = relay.client().await; // a fresh connection each time
        for _ in 0..4 {
            match c.call(create()).await {
                Ok(_) => made += 1,
                Err(ErrorCode::RateLimited) => refused = true,
                Err(e) => panic!("{e:?}"),
            }
        }
    }
    assert_eq!(made, 10, "per-source burst");
    assert!(refused);
    let mut other = Client::connect_from(relay.addr, relay.pin, std::net::Ipv4Addr::new(127, 0, 0, 2))
        .await
        .unwrap();
    other.call(create()).await.expect("another source is unaffected");
}
