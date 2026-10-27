//! Shared harness for the client integration tests: an in-process relay, a cuttable proxy,
//! users and polling helpers.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::format_collect
)]

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use veil_client::service::{ChangeKind, Client, ContactView, SetupInput};
use veil_core::vault::KdfParams;
use veil_relay::server::{Config, Shared};
use veil_relay::store::Store;
use zeroize::Zeroizing;

pub struct Relay {
    pub addr: String,
    pub pin: String,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

pub async fn relay() -> Relay {
    relay_with(|_| {}).await
}

pub async fn relay_with(tune: impl FnOnce(&mut Config)) -> Relay {
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

pub type Events = Arc<Mutex<Vec<(ChangeKind, Option<i64>)>>>;

pub struct User {
    pub client: Client,
    pub events: Events,
    dir: tempfile::TempDir,
}

/// A TCP hop between a client and the relay that can be cut, to take the client offline.
pub struct Proxy {
    pub addr: String,
    up: Arc<AtomicBool>,
    cut: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Proxy {
    pub async fn to(target: &str) -> Self {
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

    pub fn cut(&self) {
        self.up.store(false, Ordering::SeqCst);
        self.cut.send_modify(|g| *g = g.wrapping_add(1));
    }

    pub fn restore(&self) {
        self.up.store(true, Ordering::SeqCst);
    }
}

impl User {
    /// The user's data folder (database, keystore, everything Veil writes).
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
}

/// Whether any file under `dir` (recursively) contains `needle`.
pub fn tree_contains(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            tree_contains(&p, needle)
        } else {
            std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
        }
    })
}

pub async fn user(r: &Relay, name: &str) -> User {
    user_at(r, &r.addr, name, None).await
}

/// A user reaching the relay at `addr`, optionally with short-lived invites.
pub async fn user_at(r: &Relay, addr: &str, name: &str, invite_ttl: Option<Duration>) -> User {
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
    User { client, events, dir }
}

pub fn start(dir: &Path, events: Events) -> Client {
    Client::start(
        dir.to_path_buf(),
        KdfParams::FLOOR,
        Arc::new(move |k, c| events.lock().unwrap().push((k, c))),
    )
    .unwrap()
}

pub async fn eventually<T, F: Future<Output = Option<T>>>(f: impl FnMut() -> F) -> T {
    within(Duration::from_secs(10), f).await
}

pub async fn within<T, F: Future<Output = Option<T>>>(limit: Duration, mut f: impl FnMut() -> F) -> T {
    let end = tokio::time::Instant::now().checked_add(limit).unwrap();
    while tokio::time::Instant::now() < end {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached in {limit:?}");
}

pub async fn online(c: &Client, want: bool) {
    within(Duration::from_secs(40), || async {
        let on = c.me().await.unwrap().connection == veil_client::service::Connection::Online;
        (on == want).then_some(())
    })
    .await;
}

/// `inviter` invites, `joiner` accepts. Returns (inviter's contact, joiner's contact).
pub async fn pair(inviter: &Client, joiner: &Client) -> (ContactView, ContactView) {
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

pub async fn texts(c: &Client, contact: i64) -> Vec<String> {
    c.messages(contact)
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == "text")
        .map(|m| m.text)
        .collect()
}

pub async fn arrives(c: &Client, contact: i64, text: &str) {
    eventually(|| async { texts(c, contact).await.iter().any(|t| t == text).then_some(()) }).await;
}

/// Waits for a message with this text and returns its id.
pub async fn arrives_id(c: &Client, contact: i64, text: &str) -> i64 {
    eventually(|| async {
        c.messages(contact)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.text == text)
            .map(|m| m.id)
    })
    .await
}
