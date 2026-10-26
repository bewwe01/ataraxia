//! Milestone 1 end to end through the real relay: blocking, deleting, the key-change warning,
//! disappearing messages, and the opt-in read receipts and typing indicators.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect,
    clippy::too_many_lines
)]

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use veil_client::ClientError;
use veil_client::service::{ChangeKind, Client, ContactView, PrivacyView, SetupInput};
use veil_core::vault::KdfParams;
use veil_relay::server::{Config, Shared};
use veil_relay::store::Store;
use zeroize::Zeroizing;

struct Relay {
    addr: String,
    pin: String,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn relay() -> Relay {
    relay_with(|_| {}).await
}

async fn relay_with(tune: impl FnOnce(&mut Config)) -> Relay {
    let dir = tempfile::tempdir().unwrap();
    let pin = veil_relay::tls::generate(&dir.path().join("tls"), vec!["127.0.0.1".into()]).unwrap();
    let (tls, _) =
        veil_relay::tls::load(&dir.path().join("tls/cert.pem"), &dir.path().join("tls/key.pem")).unwrap();
    let mut cfg = Config::default();
    tune(&mut cfg);
    let store = Store::open(&dir.path().join("relay.redb"), cfg.quotas).unwrap();
    let shared = Shared::new(store, cfg, pin, veil_relay::server::system_clock());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(veil_relay::server::serve(
        listener,
        tls,
        Arc::clone(&shared),
        async {
            let _ = rx.await;
        },
    ));
    let pin = pin.iter().map(|b| format!("{b:02x}")).collect();
    Relay {
        addr,
        pin,
        _dir: dir,
        _stop: tx,
    }
}

type Events = Arc<Mutex<Vec<(ChangeKind, Option<i64>)>>>;

struct User {
    client: Client,
    events: Events,
    _dir: tempfile::TempDir,
}

/// A TCP hop between a client and the relay that can be cut, to take the client offline.
struct Proxy {
    addr: String,
    up: Arc<AtomicBool>,
    cut: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Proxy {
    async fn to(target: &str) -> Self {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let up = Arc::new(AtomicBool::new(true));
        let cut = Arc::new(tokio::sync::watch::channel(0u64).0);
        let (target, up2, cut2) = (target.to_owned(), Arc::clone(&up), Arc::clone(&cut));
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = l.accept().await else {
                    continue;
                };
                if !up2.load(Ordering::SeqCst) {
                    continue;
                }
                let (target, mut stop) = (target.clone(), cut2.subscribe());
                tokio::spawn(async move {
                    let Ok(mut out) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut out) => {}
                        _ = stop.changed() => {}
                    }
                });
            }
        });
        Self { addr, up, cut }
    }

    fn cut(&self) {
        self.up.store(false, Ordering::SeqCst);
        self.cut.send_modify(|g| *g = g.wrapping_add(1));
    }

    fn restore(&self) {
        self.up.store(true, Ordering::SeqCst);
    }
}

async fn user(r: &Relay, name: &str) -> User {
    user_at(r, &r.addr, name, None).await
}

/// A user reaching the relay at `addr`, optionally with short-lived invites.
async fn user_at(r: &Relay, addr: &str, name: &str, invite_ttl: Option<Duration>) -> User {
    let dir = tempfile::tempdir().unwrap();
    let events: Events = Arc::default();
    let sink = Arc::clone(&events);
    let client = match invite_ttl {
        None => start(dir.path(), sink),
        Some(ttl) => Client::start_with_invite_ttl(
            dir.path().to_path_buf(),
            KdfParams::FLOOR,
            Arc::new(move |k, c| sink.lock().unwrap().push((k, c))),
            ttl,
        )
        .unwrap(),
    };
    client
        .setup(SetupInput {
            relay: addr.to_owned(),
            pin: r.pin.clone(),
            name: name.into(),
            kind: veil_client::unlock::SecretKind::Password,
            passphrase: Zeroizing::new("correct horse battery".into()),
        })
        .await
        .unwrap();
    User {
        client,
        events,
        _dir: dir,
    }
}

fn start(dir: &Path, events: Events) -> Client {
    Client::start(
        dir.to_path_buf(),
        KdfParams::FLOOR,
        Arc::new(move |k, c| events.lock().unwrap().push((k, c))),
    )
    .unwrap()
}

async fn eventually<T, F: Future<Output = Option<T>>>(f: impl FnMut() -> F) -> T {
    within(Duration::from_secs(10), f).await
}

async fn within<T, F: Future<Output = Option<T>>>(limit: Duration, mut f: impl FnMut() -> F) -> T {
    let end = tokio::time::Instant::now().checked_add(limit).unwrap();
    while tokio::time::Instant::now() < end {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached in {limit:?}");
}

async fn online(c: &Client, want: bool) {
    within(Duration::from_secs(40), || async {
        let on = c.me().await.unwrap().connection == veil_client::service::Connection::Online;
        (on == want).then_some(())
    })
    .await;
}

/// `inviter` invites, `joiner` accepts. Returns (inviter's contact, joiner's contact).
async fn pair(inviter: &Client, joiner: &Client) -> (ContactView, ContactView) {
    let before: Vec<i64> = inviter.contacts().await.unwrap().iter().map(|c| c.id).collect();
    let inv = inviter.create_invite().await.unwrap();
    let j = joiner.accept_invite(inv.link).await.unwrap();
    let i = eventually(|| async {
        inviter
            .contacts()
            .await
            .unwrap()
            .into_iter()
            .find(|c| !before.contains(&c.id))
    })
    .await;
    (i, j)
}

async fn texts(c: &Client, contact: i64) -> Vec<String> {
    c.messages(contact)
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == "text")
        .map(|m| m.text)
        .collect()
}

async fn arrives(c: &Client, contact: i64, text: &str) {
    eventually(|| async { texts(c, contact).await.iter().any(|t| t == text).then_some(()) }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_unblock_and_delete() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client.send(b_alice.id, "hello".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "hello").await;

    // Blocked: the relay refuses Bob's deposits, and Alice cannot send to him.
    alice.client.set_blocked(a_bob.id, true).await.unwrap();
    assert!(alice.client.contacts().await.unwrap()[0].blocked);
    assert_eq!(
        alice.client.send(a_bob.id, "x".into()).await.unwrap_err(),
        ClientError::Blocked
    );
    let m = bob.client.send(b_alice.id, "while blocked".into()).await.unwrap();
    assert_eq!(m.status, "failed");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !texts(&alice.client, a_bob.id)
            .await
            .contains(&"while blocked".to_owned())
    );

    // Unblocked: Bob gets a new token in a mailbox update and can write again.
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    assert!(!alice.client.contacts().await.unwrap()[0].blocked);
    eventually(|| async {
        let m = bob.client.send(b_alice.id, "after unblock".into()).await.ok()?;
        (m.status == "sent").then_some(())
    })
    .await;
    arrives(&alice.client, a_bob.id, "after unblock").await;
    alice.client.send(a_bob.id, "welcome back".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "welcome back").await;

    // Deleted: the contact, the conversation and the session are gone, and so is Bob's
    // token at the relay.
    alice.client.delete_contact(a_bob.id).await.unwrap();
    assert!(alice.client.contacts().await.unwrap().is_empty());
    assert_eq!(
        alice.client.messages(a_bob.id).await.unwrap().len(),
        0,
        "messages deleted with the contact"
    );
    let m = bob.client.send(b_alice.id, "after delete".into()).await.unwrap();
    assert_eq!(m.status, "failed");

    // Only a new invite brings them together again, with a new session.
    let (a_bob2, b_alice2) = pair(&alice.client, &bob.client).await;
    assert_eq!(b_alice2.id, b_alice.id, "Bob's side keeps its contact");
    assert!(!a_bob2.key_warning);
    bob.client.send(b_alice.id, "new start".into()).await.unwrap();
    arrives(&alice.client, a_bob2.id, "new start").await;
    assert!(
        !texts(&alice.client, a_bob2.id)
            .await
            .contains(&"after delete".to_owned())
    );
    alice.client.send(a_bob2.id, "hi again".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "hi again").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookalike_name_gets_a_key_warning() {
    let r = relay().await;
    let alice = user(&r, "Alice").await;
    let bob = user(&r, "Bob").await;
    // Someone else, using Bob's name (or Bob after a reinstall: a new key either way).
    let imposter = user(&r, " bob ").await;
    let (a_bob, _) = pair(&alice.client, &bob.client).await;
    assert!(!a_bob.key_warning);
    let (a_imp, _) = pair(&alice.client, &imposter.client).await;
    assert!(a_imp.key_warning, "same name, new key: warn");
    assert_ne!(a_imp.id, a_bob.id, "never merged into the existing contact");
    assert!(texts(&alice.client, a_imp.id).await.is_empty());

    // Verifying the safety number clears it; so does dismissing.
    alice.client.set_verified(a_imp.id, true).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(!c.iter().find(|c| c.id == a_imp.id).unwrap().key_warning);
    let imposter2 = user(&r, "BOB").await;
    let (a_imp2, _) = pair(&alice.client, &imposter2.client).await;
    assert!(a_imp2.key_warning);
    alice.client.dismiss_key_warning(a_imp2.id).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(!c.iter().find(|c| c.id == a_imp2.id).unwrap().key_warning);
    assert!(
        !c.iter().find(|c| c.id == a_imp2.id).unwrap().verified,
        "dismissing is not verifying"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disappearing_messages() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    assert_eq!(
        alice.client.set_timer(a_bob.id, 2_419_201).await.unwrap_err(),
        ClientError::BadInput
    );
    alice.client.set_timer(a_bob.id, 1).await.unwrap();
    // Bob's side follows, with a notice in the conversation.
    eventually(|| async {
        let c = bob.client.contacts().await.unwrap();
        (c[0].timer_secs == 1).then_some(())
    })
    .await;
    let notice = bob.client.messages(b_alice.id).await.unwrap();
    assert!(
        notice
            .iter()
            .any(|m| m.kind == "timer" && m.timer_secs == Some(1))
    );

    let sent = bob.client.send(b_alice.id, "self destruct".into()).await.unwrap();
    assert!(sent.expires_at_ms.is_some());
    // Gone on both sides once the timer runs out (the sweeper runs on the tick).
    eventually(|| async { texts(&bob.client, b_alice.id).await.is_empty().then_some(()) }).await;
    eventually(|| async {
        let got = alice.client.messages(a_bob.id).await.unwrap();
        (!got.iter().any(|m| m.text == "self destruct")).then_some(())
    })
    .await;

    // Off again: messages stay.
    alice.client.set_timer(a_bob.id, 0).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 0).then_some(()) }).await;
    let m = bob.client.send(b_alice.id, "stays".into()).await.unwrap();
    assert!(m.expires_at_ms.is_none());
    arrives(&alice.client, a_bob.id, "stays").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(texts(&alice.client, a_bob.id).await.contains(&"stays".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipts_and_typing_are_opt_in() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let p = alice.client.privacy().await.unwrap();
    assert!(!p.read_receipts && !p.typing, "off by default");

    // Off: nothing beyond "sent", and no typing events.
    bob.client.typing(b_alice.id, true).await.unwrap();
    let m = bob.client.send(b_alice.id, "one".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "one").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.id == m.id).unwrap().status, "sent");
    assert!(
        !alice
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == ChangeKind::Typing)
    );

    // On for both: delivered, then read; typing shows.
    let on = PrivacyView {
        read_receipts: true,
        typing: true,
    };
    alice.client.set_privacy(on).await.unwrap();
    bob.client.set_privacy(on).await.unwrap();
    bob.client.typing(b_alice.id, true).await.unwrap();
    eventually(|| async {
        alice
            .events
            .lock()
            .unwrap()
            .contains(&(ChangeKind::Typing, Some(a_bob.id)))
            .then_some(())
    })
    .await;
    let m = bob.client.send(b_alice.id, "two".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "two").await;
    let status = |want: &'static str| {
        let bob = bob.client.clone();
        let (cid, mid) = (b_alice.id, m.id);
        async move {
            eventually(|| async {
                let s = bob.messages(cid).await.unwrap();
                (s.iter().find(|x| x.id == mid).unwrap().status == want).then_some(())
            })
            .await;
        }
    };
    status("delivered").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    status("read").await;
    // "one" arrived and was read while Alice had receipts off: turning them on later does not
    // report it (review M1-4).
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.text == "one").unwrap().status, "sent");

    // Alice turns receipts off again: Bob's next message stays at "sent".
    alice
        .client
        .set_privacy(PrivacyView {
            read_receipts: false,
            typing: false,
        })
        .await
        .unwrap();
    let m3 = bob.client.send(b_alice.id, "three".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "three").await;
    alice.client.mark_read(a_bob.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = bob.client.messages(b_alice.id).await.unwrap();
    assert_eq!(st.iter().find(|x| x.id == m3.id).unwrap().status, "sent");
}

/// Blocking while offline: queued messages to them are never sent, and their token is
/// withdrawn once the relay is back (INV-CONT-1, review M1-2, M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_while_offline() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    bob.client.send(b_alice.id, "hi".into()).await.unwrap();
    arrives(&alice.client, a_bob.id, "hi").await;

    hop.cut();
    online(&alice.client, false).await;
    let m = alice
        .client
        .send(a_bob.id, "queued before the block".into())
        .await
        .unwrap();
    assert_eq!(m.status, "failed");
    alice.client.set_blocked(a_bob.id, true).await.unwrap();
    // The relay has not heard of the block yet.
    let m = bob
        .client
        .send(b_alice.id, "still accepted".into())
        .await
        .unwrap();
    assert_eq!(m.status, "sent");

    hop.restore();
    online(&alice.client, true).await;
    within(Duration::from_secs(20), || async {
        let m = bob.client.send(b_alice.id, "refused?".into()).await.unwrap();
        (m.status == "failed").then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !texts(&bob.client, b_alice.id)
            .await
            .contains(&"queued before the block".to_owned())
    );
    let mine = alice.client.messages(a_bob.id).await.unwrap();
    assert!(
        !mine
            .iter()
            .any(|m| m.text == "still accepted" || m.text == "refused?")
    );
}

/// An unsent message whose timer runs out is deleted unsent, from the database (the list
/// does not filter expired rows, so this sees the sweeper) (INV-REST-9, review M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_unsent_message_is_never_sent() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.set_timer(a_bob.id, 1).await.unwrap();
    eventually(|| async { (bob.client.contacts().await.unwrap()[0].timer_secs == 1).then_some(()) }).await;

    hop.cut();
    online(&alice.client, false).await;
    let m = alice.client.send(a_bob.id, "too late".into()).await.unwrap();
    assert_eq!(m.status, "failed");
    eventually(|| async { texts(&alice.client, a_bob.id).await.is_empty().then_some(()) }).await;
    hop.restore();
    online(&alice.client, true).await;
    alice.client.set_timer(a_bob.id, 0).await.unwrap();
    alice.client.send(a_bob.id, "on time".into()).await.unwrap();
    arrives(&bob.client, b_alice.id, "on time").await;
    assert!(
        !texts(&bob.client, b_alice.id)
            .await
            .contains(&"too late".to_owned())
    );
}

/// Expired invites give their tokens back: with room for one batch of 8 tokens, a ninth
/// invite only fits once the first eight have expired and been withdrawn (review M1-8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_invites_release_their_tokens() {
    let r = relay_with(|c| {
        c.quotas.max_tokens_per_mailbox = 8;
        c.quotas.token_floor_per_mailbox = 8;
    })
    .await;
    let alice = user_at(&r, &r.addr, "Alice", Some(Duration::from_secs(4))).await;
    for _ in 0..8 {
        alice.client.create_invite().await.unwrap();
    }
    assert!(alice.client.create_invite().await.is_err(), "no token left");
    // Each failed try costs one of the relay's token updates (1 per second), so try slowly
    // and leave room for the withdrawal itself.
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if alice.client.create_invite().await.is_ok() {
            return;
        }
    }
    panic!("expired invites never gave their tokens back");
}

/// An unblock update that waited while offline must not reach them after a newer one: it
/// names a token that was withdrawn since (review M1R2-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_unblock_update_is_never_delivered() {
    let r = relay().await;
    let hop = Proxy::to(&r.addr).await;
    let alice = user_at(&r, &hop.addr, "Alice", None).await;
    let bob = user(&r, "Bob").await;
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    alice.client.set_blocked(a_bob.id, true).await.unwrap();

    // Offline: unblock (token from the local spare pool, update queued), then block again.
    hop.cut();
    online(&alice.client, false).await;
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    let c = alice.client.contacts().await.unwrap();
    assert!(c[0].unblock_pending, "the update is still waiting");
    alice.client.set_blocked(a_bob.id, true).await.unwrap();

    // Online: unblock for real, then reconnect so anything pending is retried.
    hop.restore();
    online(&alice.client, true).await;
    alice.client.set_blocked(a_bob.id, false).await.unwrap();
    hop.cut();
    online(&alice.client, false).await;
    hop.restore();
    online(&alice.client, true).await;
    assert!(!alice.client.contacts().await.unwrap()[0].unblock_pending);

    tokio::time::sleep(Duration::from_secs(1)).await;
    within(Duration::from_secs(20), || async {
        let m = bob.client.send(b_alice.id, "can you hear me".into()).await.ok()?;
        (m.status == "sent").then_some(())
    })
    .await;
    arrives(&alice.client, a_bob.id, "can you hear me").await;
}
