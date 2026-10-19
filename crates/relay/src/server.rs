//! The relay server: TLS 1.3 → WebSocket → one strict [`ClientFrame`] per binary message.
//!
//! The relay is assumed hostile by clients (CLAUDE.md non-negotiable 3), but it must also
//! defend itself against hostile clients:
//! * sizes are limited before parsing (WebSocket frame and message limits, then
//!   [`ClientFrame::decode_strict`]);
//! * handshake, idle, pre-authentication and write timeouts, a connection cap, and
//!   per-connection frame rate limits;
//! * a relay-wide budget for response bytes in flight, so slow readers cannot exhaust memory;
//! * rate limits keyed by delivery token, mailbox or connection, **never by IP**.
//!
//! The one use of the peer address is an in-memory count of *concurrent* connections per
//! source (IPv4 address or IPv6 /64), so one host cannot take every connection slot
//! (review P3-4). The count exists only while a connection is open; it is never logged or
//! stored, and an entry is removed when it reaches zero.
//!
//! Nothing about a connection is logged: no address, no mailbox id, no size (INV-META-2).

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use veil_wire::{
    ChallengeResponse, ClientFrame, Envelopes, ErrorCode, InviteResponse, MAX_BLOB_CHUNK, MAX_CLIENT_FRAME,
    MAX_ENVELOPE, MAX_FRAME, NewEnvelopes, Request, Response, ServerFrame, StoredEnvelope, TurnResponse,
    UploadTokenResponse, VERSION,
};

use crate::limits::{KeyedLimiter, Limiter, Rate};
use crate::store::{Quotas, Store, StoreError};
use crate::turn::{self, TurnConfig};

/// Clock source (unix seconds); injectable for tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Rate limits. Defaults suit a small personal relay (Raspberry Pi).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Frames per connection.
    pub frames_per_conn: Rate,
    /// Mailbox creations, relay-wide.
    pub create_mailbox: Rate,
    /// Mailbox creations per connection (so one connection cannot drain the relay-wide bucket).
    pub create_mailbox_per_conn: Rate,
    /// Deposits per delivery token.
    pub deposit_per_token: Rate,
    /// Invite uploads per authenticated mailbox.
    pub put_invite_per_mailbox: Rate,
    /// Invite fetches per connection.
    pub take_invite_per_conn: Rate,
    /// Upload tokens per mailbox.
    pub upload_token_per_mailbox: Rate,
    /// TURN credentials per mailbox.
    pub turn_per_mailbox: Rate,
    /// Mailboxes one connection may be authenticated for.
    pub max_auth_per_conn: usize,
    /// Outstanding challenges per connection.
    pub max_pending_challenges: usize,
    /// Allowed clock difference for authentication (PROTOCOL §2: ±120 s).
    pub auth_skew_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frames_per_conn: Rate {
                burst: 200,
                per_sec: 50.0,
            },
            create_mailbox: Rate {
                burst: 20,
                per_sec: 1.0,
            },
            create_mailbox_per_conn: Rate {
                burst: 4,
                per_sec: 1.0 / 60.0,
            },
            deposit_per_token: Rate {
                burst: 60,
                per_sec: 1.0,
            },
            put_invite_per_mailbox: Rate {
                burst: 10,
                per_sec: 1.0 / 60.0,
            },
            take_invite_per_conn: Rate {
                burst: 10,
                per_sec: 0.2,
            },
            upload_token_per_mailbox: Rate {
                burst: 20,
                per_sec: 0.1,
            },
            turn_per_mailbox: Rate {
                burst: 10,
                per_sec: 1.0 / 60.0,
            },
            max_auth_per_conn: 64,
            max_pending_challenges: 64,
            auth_skew_secs: 120,
        }
    }
}

pub struct Config {
    pub quotas: Quotas,
    pub limits: Limits,
    pub turn: Option<TurnConfig>,
    pub max_connections: usize,
    /// Concurrent connections from one source (IPv4 address or IPv6 /64).
    pub max_connections_per_source: u32,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    /// A connection that has not authenticated a mailbox or completed a deposit, invite take
    /// or blob transfer within this time is closed, whatever keep-alives it sends.
    pub pre_auth_timeout: Duration,
    /// Longest a single write to a client may take; a client that stops reading is dropped.
    pub write_timeout: Duration,
    /// Response bytes (fetches, blob chunks) that may be in flight relay-wide.
    pub response_budget_bytes: usize,
    pub sweep_interval: Duration,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("max_connections", &self.max_connections)
            .finish_non_exhaustive()
    }
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_mailboxes: 100_000,
            max_envelopes_per_mailbox: 5_000,
            max_envelope_bytes_total: 1024 * 1024 * 1024,
            max_tokens_per_mailbox: 512,
            max_invites: 50_000,
            max_blob_bytes_total: 4 * 1024 * 1024 * 1024,
            envelope_ttl_secs: 14 * 24 * 3600,
            invite_max_ttl_secs: 7 * 24 * 3600,
            blob_ttl_secs: 30 * 24 * 3600,
            upload_token_ttl_secs: 24 * 3600,
            mailbox_idle_secs: 60 * 24 * 3600,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            quotas: Quotas::default(),
            limits: Limits::default(),
            turn: None,
            max_connections: 1024,
            max_connections_per_source: 32,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(5),
            pre_auth_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            response_budget_bytes: 64 * 1024 * 1024,
            sweep_interval: Duration::from_mins(1),
        }
    }
}

type Subscribers = HashMap<[u8; 32], Vec<(u64, mpsc::Sender<ServerFrame>)>>;

/// State shared by all connections.
pub struct Shared {
    store: Arc<Store>,
    cfg: Config,
    spki_pin: [u8; 32],
    clock: Clock,
    create_mailbox: Mutex<Limiter>,
    deposits: Mutex<KeyedLimiter>,
    put_invite: Mutex<KeyedLimiter>,
    upload_tokens: Mutex<KeyedLimiter>,
    turn: Mutex<KeyedLimiter>,
    subscribers: Mutex<Subscribers>,
    next_conn: AtomicU64,
    /// Response bytes in flight, in KiB units.
    response_budget: Arc<Semaphore>,
}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Shared")
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

const LIMITER_KEYS: usize = 100_000;

impl Shared {
    pub fn new(store: Store, cfg: Config, spki_pin: [u8; 32], clock: Clock) -> Arc<Self> {
        let l = cfg.limits;
        Arc::new(Self {
            store: Arc::new(store),
            spki_pin,
            clock,
            create_mailbox: Mutex::new(Limiter::new(l.create_mailbox)),
            deposits: Mutex::new(KeyedLimiter::new(l.deposit_per_token, LIMITER_KEYS)),
            put_invite: Mutex::new(KeyedLimiter::new(l.put_invite_per_mailbox, LIMITER_KEYS)),
            upload_tokens: Mutex::new(KeyedLimiter::new(l.upload_token_per_mailbox, LIMITER_KEYS)),
            turn: Mutex::new(KeyedLimiter::new(l.turn_per_mailbox, LIMITER_KEYS)),
            subscribers: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            response_budget: Arc::new(Semaphore::new(
                (cfg.response_budget_bytes / 1024).min(Semaphore::MAX_PERMITS),
            )),
            cfg,
        })
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Runs a store operation off the async runtime.
    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|_| StoreError::Io)?
    }

    fn subscribe(&self, mailbox: [u8; 32], conn: u64, tx: mpsc::Sender<ServerFrame>) {
        let mut subs = lock(&self.subscribers);
        let list = subs.entry(mailbox).or_default();
        if !list.iter().any(|(c, _)| *c == conn) {
            list.push((conn, tx));
        }
    }

    fn unsubscribe_all(&self, conn: u64) {
        let mut subs = lock(&self.subscribers);
        subs.retain(|_, list| {
            list.retain(|(c, _)| *c != conn);
            !list.is_empty()
        });
    }

    fn notify(&self, mailbox: [u8; 32], last_seq: u64) {
        let subs = lock(&self.subscribers);
        if let Some(list) = subs.get(&mailbox) {
            let push = ServerFrame {
                v: VERSION,
                id: 0,
                resp: Some(Response::NewEnvelopes(NewEnvelopes {
                    mailbox_id: mailbox.to_vec(),
                    last_seq,
                })),
            };
            for (_, tx) in list {
                // A slow client misses a push, not data: it fetches by sequence number.
                let _ = tx.try_send(push.clone());
            }
        }
    }
}

/// Connection source for the concurrency cap: the IPv4 address, or the IPv6 /64.
fn source_key(ip: IpAddr) -> [u8; 8] {
    match ip {
        IpAddr::V4(v4) => {
            let mut k = [0u8; 8];
            if let Some(dst) = k.get_mut(4..) {
                dst.copy_from_slice(&v4.octets());
            }
            k
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return source_key(IpAddr::V4(v4));
            }
            let o = v6.octets();
            let mut k = [0u8; 8];
            if let (Some(dst), Some(src)) = (k.get_mut(..), o.get(..8)) {
                dst.copy_from_slice(src);
            }
            // Never equal to an IPv4 key, whose first four bytes are zero.
            if let Some(first) = k.first_mut() {
                *first |= 0x80;
            }
            k
        }
    }
}

type Sources = Arc<Mutex<HashMap<[u8; 8], u32>>>;

/// Holds one source slot; releases it (and forgets the source at zero) on drop.
struct SourceSlot {
    sources: Sources,
    key: [u8; 8],
}

impl SourceSlot {
    fn take(sources: &Sources, key: [u8; 8], max: u32) -> Option<Self> {
        let mut map = lock(sources);
        let n = map.entry(key).or_insert(0);
        if *n >= max {
            if *n == 0 {
                map.remove(&key);
            }
            return None;
        }
        *n = n.saturating_add(1);
        Some(Self {
            sources: Arc::clone(sources),
            key,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut map = lock(&self.sources);
        if let Some(n) = map.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

/// Accepts connections until `shutdown` resolves. TLS is mandatory: there is no plaintext mode.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    shared: Arc<Shared>,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(shared.cfg.max_connections));
    let sources: Sources = Arc::new(Mutex::new(HashMap::new()));
    let sweeper = tokio::spawn(sweep_loop(Arc::clone(&shared)));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, addr)) = accepted else { continue };
                // Only a truncated source key survives, in memory, for the concurrency cap;
                // the address itself is dropped here and never stored or logged.
                let key = source_key(addr.ip());
                let Some(source) = SourceSlot::take(&sources, key, shared.cfg.max_connections_per_source) else {
                    drop(stream); // this source already holds its share of connections
                    continue;
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(stream); // over the connection cap
                    continue;
                };
                let acceptor = acceptor.clone();
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    connection(stream, acceptor, shared).await;
                    drop(permit);
                    drop(source);
                });
            }
        }
    }
    sweeper.abort();
}

async fn sweep_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(shared.cfg.sweep_interval);
    loop {
        tick.tick().await;
        let now = shared.now();
        if shared.db(move |s| s.sweep(now)).await.is_err() {
            tracing::warn!("expiry sweep failed");
        }
    }
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_CLIENT_FRAME))
        .max_frame_size(Some(MAX_CLIENT_FRAME))
        // One largest response plus slack; writes beyond that fail instead of buffering.
        .max_write_buffer_size(MAX_FRAME.saturating_add(256 * 1024))
}

async fn connection(stream: TcpStream, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    let hs = shared.cfg.handshake_timeout;
    let Ok(Ok(tls)) = tokio::time::timeout(hs, acceptor.accept(stream)).await else {
        return;
    };
    let Ok(Ok(ws)) = tokio::time::timeout(
        hs,
        tokio_tungstenite::accept_async_with_config(tls, Some(ws_config())),
    )
    .await
    else {
        return;
    };
    let (mut sink, mut source) = ws.split();
    let (push_tx, mut push_rx) = mpsc::channel::<ServerFrame>(64);
    let mut conn = Conn::new(Arc::clone(&shared), push_tx);
    let (idle, write) = (shared.cfg.idle_timeout, shared.cfg.write_timeout);
    let start = tokio::time::Instant::now();
    let pre_auth_deadline = start.checked_add(shared.cfg.pre_auth_timeout).unwrap_or(start);
    loop {
        // Until the connection does something useful, keep-alives do not keep it open.
        let wait = if conn.established {
            idle
        } else {
            pre_auth_deadline.saturating_duration_since(tokio::time::Instant::now())
        };
        tokio::select! {
            incoming = tokio::time::timeout(wait, source.next()) => {
                let (reply, budget) = match incoming {
                    Ok(Some(Ok(Message::Binary(bytes)))) => conn.handle(&bytes).await,
                    Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                    // Text frames, close, errors, end of stream or timeout: hang up.
                    _ => break,
                };
                let sent = tokio::time::timeout(write, sink.send(Message::Binary(reply.encode().into()))).await;
                drop(budget); // the response bytes have left (or the connection is going)
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            }
            Some(push) = push_rx.recv() => {
                let sent = tokio::time::timeout(write, sink.send(Message::Binary(push.encode().into()))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            }
        }
    }
    shared.unsubscribe_all(conn.id);
    let _ = tokio::time::timeout(write, sink.close()).await;
}

fn arr32(b: &[u8]) -> Option<[u8; 32]> {
    b.try_into().ok()
}

fn code(e: StoreError) -> ErrorCode {
    match e {
        StoreError::NotFound => ErrorCode::NotFound,
        StoreError::Conflict => ErrorCode::Conflict,
        StoreError::Quota => ErrorCode::QuotaExceeded,
        StoreError::Unauthorized => ErrorCode::Unauthorized,
        StoreError::Corrupt | StoreError::Io => ErrorCode::Internal,
    }
}

/// `SHA-256("veil/v1/tok" || token)`: what mailbox owners register (PROTOCOL §2).
pub fn token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"veil/v1/tok")
        .chain_update(token)
        .finalize()
        .into()
}

/// `SHA-256("veil/v1/upload" || token)`: how upload tokens are stored.
fn upload_hash(token: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"veil/v1/upload")
        .chain_update(token)
        .finalize()
        .into()
}

/// Per-connection state.
struct Conn {
    id: u64,
    shared: Arc<Shared>,
    push: mpsc::Sender<ServerFrame>,
    frames: Limiter,
    take_invite: Limiter,
    create_mailbox: Limiter,
    /// Mailbox → (nonce, issued at).
    challenges: HashMap<[u8; 32], ([u8; 32], u64)>,
    /// Mailbox → the auth key it was authenticated with (re-checked on use, P3-11).
    authed: HashMap<[u8; 32], [u8; 32]>,
    /// Set by the first authentication, deposit, invite take or blob transfer.
    established: bool,
}

impl Conn {
    fn new(shared: Arc<Shared>, push: mpsc::Sender<ServerFrame>) -> Self {
        let l = shared.cfg.limits;
        Self {
            id: shared.next_conn.fetch_add(1, Ordering::Relaxed),
            push,
            frames: Limiter::new(l.frames_per_conn),
            take_invite: Limiter::new(l.take_invite_per_conn),
            create_mailbox: Limiter::new(l.create_mailbox_per_conn),
            challenges: HashMap::new(),
            authed: HashMap::new(),
            established: false,
            shared,
        }
    }

    /// One request → one reply, plus the response-budget share the reply holds until sent.
    async fn handle(&mut self, bytes: &[u8]) -> (ServerFrame, Option<OwnedSemaphorePermit>) {
        // Every frame counts, decodable or not. Decoding first (the size is already capped by
        // the WebSocket limits) lets a refusal echo the request id, so clients can match it.
        let allowed = self.frames.allow();
        let frame = match ClientFrame::decode_strict(bytes) {
            Ok(f) => f,
            Err(_) if !allowed => return (ServerFrame::error(0, ErrorCode::RateLimited), None),
            Err(veil_wire::WireError::UnsupportedVersion) => {
                return (ServerFrame::error(0, ErrorCode::Unsupported), None);
            }
            Err(_) => return (ServerFrame::error(0, ErrorCode::Malformed), None),
        };
        let id = frame.id;
        if !allowed {
            return (ServerFrame::error(id, ErrorCode::RateLimited), None);
        }
        let Some(req) = frame.req else {
            return (ServerFrame::error(id, ErrorCode::Malformed), None);
        };
        let mut budget = None;
        match self.dispatch(req, &mut budget).await {
            Ok(resp) => (
                ServerFrame {
                    v: VERSION,
                    id,
                    resp: Some(resp),
                },
                budget,
            ),
            Err(code) => (ServerFrame::error(id, code), None),
        }
    }

    /// The mailbox must be authenticated on this connection *and* still carry the key it
    /// was authenticated with: a deleted and re-created mailbox needs a new authentication
    /// (P3-11).
    async fn require_auth(&mut self, mailbox: &[u8]) -> Result<[u8; 32], ErrorCode> {
        let m = arr32(mailbox).ok_or(ErrorCode::Malformed)?;
        let Some(&key) = self.authed.get(&m) else {
            return Err(ErrorCode::Unauthorized);
        };
        match self.shared.db(move |s| s.mailbox_auth_key(&m)).await {
            Ok(current) if current == key => Ok(m),
            Ok(_) | Err(StoreError::NotFound) => {
                self.authed.remove(&m);
                Err(ErrorCode::Unauthorized)
            }
            Err(e) => Err(code(e)),
        }
    }

    /// Reserves `bytes` of the relay-wide response budget, or refuses with `RateLimited`.
    fn reserve(&self, bytes: usize) -> Result<OwnedSemaphorePermit, ErrorCode> {
        let kib = u32::try_from(bytes.div_ceil(1024)).map_err(|_| ErrorCode::Internal)?;
        Arc::clone(&self.shared.response_budget)
            .try_acquire_many_owned(kib)
            .map_err(|_| ErrorCode::RateLimited)
    }

    #[allow(clippy::too_many_lines)]
    async fn dispatch(
        &mut self,
        req: Request,
        budget: &mut Option<OwnedSemaphorePermit>,
    ) -> Result<Response, ErrorCode> {
        let sh = Arc::clone(&self.shared);
        let now = sh.now();
        let ok = || Response::Ok(veil_wire::Empty {});
        match req {
            Request::Ping(_) => Ok(ok()),

            Request::CreateMailbox(c) => {
                if !self.create_mailbox.allow() {
                    return Err(ErrorCode::RateLimited);
                }
                let (m, k) = (
                    arr32(&c.mailbox_id).ok_or(ErrorCode::Malformed)?,
                    arr32(&c.auth_pub).ok_or(ErrorCode::Malformed)?,
                );
                // Reject keys that are not valid Ed25519 points now rather than at every auth.
                ed25519_dalek::VerifyingKey::from_bytes(&k).map_err(|_| ErrorCode::Malformed)?;
                // Only requests that would succeed spend the relay-wide budget (P3-5).
                if sh.db(move |s| s.mailbox_exists(&m)).await.map_err(code)? {
                    return Err(ErrorCode::Conflict);
                }
                if !lock(&sh.create_mailbox).allow() {
                    return Err(ErrorCode::RateLimited);
                }
                sh.db(move |s| s.create_mailbox(&m, &k, now))
                    .await
                    .map_err(code)?;
                Ok(ok())
            }

            Request::Challenge(c) => {
                let m = arr32(&c.mailbox_id).ok_or(ErrorCode::Malformed)?;
                // Issued for any id, so a challenge does not reveal whether a mailbox exists.
                if !self.challenges.contains_key(&m)
                    && self.challenges.len() >= sh.cfg.limits.max_pending_challenges
                {
                    return Err(ErrorCode::RateLimited);
                }
                let mut nonce = [0u8; 32];
                rand::rng().fill(&mut nonce);
                self.challenges.insert(m, (nonce, now));
                Ok(Response::Challenge(ChallengeResponse {
                    nonce: nonce.to_vec(),
                }))
            }

            Request::Authenticate(a) => {
                let m = arr32(&a.mailbox_id).ok_or(ErrorCode::Malformed)?;
                // Single use: the nonce is consumed whatever the outcome.
                let (nonce, issued) = self.challenges.remove(&m).ok_or(ErrorCode::Unauthorized)?;
                let skew = sh.cfg.limits.auth_skew_secs;
                if now.abs_diff(a.unix_secs) > skew || now.saturating_sub(issued) > skew {
                    return Err(ErrorCode::Unauthorized);
                }
                if !self.authed.contains_key(&m) && self.authed.len() >= sh.cfg.limits.max_auth_per_conn {
                    return Err(ErrorCode::RateLimited);
                }
                let key = match sh.db(move |s| s.mailbox_auth_key(&m)).await {
                    Ok(k) => k,
                    Err(StoreError::NotFound) => return Err(ErrorCode::Unauthorized),
                    Err(e) => return Err(code(e)),
                };
                let vk =
                    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| ErrorCode::Unauthorized)?;
                let sig = ed25519_dalek::Signature::from_slice(&a.signature)
                    .map_err(|_| ErrorCode::Unauthorized)?;
                let msg = veil_wire::auth_message(&sh.spki_pin, &m, &nonce, a.unix_secs);
                // Strict verification: rejects small-order keys and non-canonical signatures.
                vk.verify_strict(&msg, &sig)
                    .map_err(|_| ErrorCode::Unauthorized)?;
                sh.db(move |s| s.touch_mailbox(&m, now)).await.map_err(code)?;
                self.authed.insert(m, key);
                self.established = true;
                sh.subscribe(m, self.id, self.push.clone());
                Ok(ok())
            }

            Request::UpdateTokens(u) => {
                let m = self.require_auth(&u.mailbox_id).await?;
                let to32 = |v: &[Vec<u8>]| {
                    v.iter()
                        .map(|t| arr32(t).ok_or(ErrorCode::Malformed))
                        .collect::<Result<Vec<_>, _>>()
                };
                let (add, remove) = (to32(&u.add)?, to32(&u.remove)?);
                sh.db(move |s| s.update_tokens(&m, &add, &remove))
                    .await
                    .map_err(code)?;
                Ok(ok())
            }

            Request::Deposit(d) => {
                let m = arr32(&d.mailbox_id).ok_or(ErrorCode::Malformed)?;
                let h = token_hash(&d.token);
                if !lock(&sh.deposits).allow(&h) {
                    return Err(ErrorCode::RateLimited);
                }
                let envelope = d.envelope;
                let seq = sh
                    .db(move |s| s.deposit(&m, &h, &envelope, now))
                    .await
                    .map_err(code)?;
                sh.notify(m, seq);
                self.established = true;
                Ok(ok())
            }

            Request::Fetch(f) => {
                let m = self.require_auth(&f.mailbox_id).await?;
                let limit = usize::try_from(f.limit).map_err(|_| ErrorCode::Malformed)?;
                *budget = Some(self.reserve(limit.saturating_mul(MAX_ENVELOPE + 64))?);
                let after = f.after_seq;
                let (items, last_seq) = sh
                    .db(move |s| s.fetch(&m, after, limit, now))
                    .await
                    .map_err(code)?;
                Ok(Response::Envelopes(Envelopes {
                    items: items
                        .into_iter()
                        .map(|i| StoredEnvelope {
                            seq: i.seq,
                            received_minute: i.received_minute,
                            envelope: i.envelope,
                        })
                        .collect(),
                    last_seq,
                }))
            }

            Request::Ack(a) => {
                let m = self.require_auth(&a.mailbox_id).await?;
                let up_to = a.up_to_seq;
                sh.db(move |s| s.ack(&m, up_to)).await.map_err(code)?;
                Ok(ok())
            }

            Request::DeleteMailbox(d) => {
                let m = self.require_auth(&d.mailbox_id).await?;
                sh.db(move |s| s.delete_mailbox(&m)).await.map_err(code)?;
                self.authed.remove(&m);
                Ok(ok())
            }

            Request::PutInvite(p) => {
                let m = self.require_auth(&p.mailbox_id).await?;
                if !lock(&sh.put_invite).allow(&m) {
                    return Err(ErrorCode::RateLimited);
                }
                let id: [u8; 16] = p
                    .invite_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| ErrorCode::Malformed)?;
                let (sealed, exp) = (p.sealed, p.expires_at);
                // The mailbox is used for rate limiting only; it is not stored with the invite.
                sh.db(move |s| s.put_invite(&id, &sealed, exp, now))
                    .await
                    .map_err(code)?;
                Ok(ok())
            }

            Request::TakeInvite(t) => {
                if !self.take_invite.allow() {
                    return Err(ErrorCode::RateLimited);
                }
                let id: [u8; 16] = t
                    .invite_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| ErrorCode::Malformed)?;
                let sealed = sh.db(move |s| s.take_invite(&id, now)).await.map_err(code)?;
                self.established = true;
                Ok(Response::Invite(InviteResponse { sealed }))
            }

            Request::BlobUploadToken(b) => {
                let m = self.require_auth(&b.mailbox_id).await?;
                if !lock(&sh.upload_tokens).allow(&m) {
                    return Err(ErrorCode::RateLimited);
                }
                let mut token = [0u8; 32];
                rand::rng().fill(&mut token);
                let h = upload_hash(&token);
                sh.db(move |s| s.add_upload_token(&h, now)).await.map_err(code)?;
                Ok(Response::UploadToken(UploadTokenResponse {
                    upload_token: token.to_vec(),
                }))
            }

            Request::BlobPut(b) => {
                let h = upload_hash(&b.upload_token);
                let blob = arr32(&b.blob_id).ok_or(ErrorCode::Malformed)?;
                let (idx, total, data) = (b.chunk_index, b.total_chunks, b.data);
                sh.db(move |s| s.put_chunk(&h, &blob, idx, total, &data, MAX_BLOB_CHUNK, now))
                    .await
                    .map_err(code)?;
                self.established = true;
                Ok(ok())
            }

            Request::BlobGet(b) => {
                let blob = arr32(&b.blob_id).ok_or(ErrorCode::Malformed)?;
                let idx = b.chunk_index;
                *budget = Some(self.reserve(MAX_BLOB_CHUNK + 64)?);
                let (total_chunks, data) =
                    sh.db(move |s| s.get_chunk(&blob, idx, now)).await.map_err(code)?;
                self.established = true;
                Ok(Response::BlobChunk(veil_wire::BlobChunk { total_chunks, data }))
            }

            Request::TurnCredentials(t) => {
                let m = self.require_auth(&t.mailbox_id).await?;
                let cfg = sh.cfg.turn.as_ref().ok_or(ErrorCode::Unsupported)?;
                if !lock(&sh.turn).allow(&m) {
                    return Err(ErrorCode::RateLimited);
                }
                let (username, credential) =
                    turn::credentials(cfg, now, &mut rand::rng()).ok_or(ErrorCode::Internal)?;
                Ok(Response::Turn(TurnResponse {
                    username,
                    credential,
                    ttl_secs: cfg.ttl_secs,
                    urls: cfg.urls.clone(),
                }))
            }
        }
    }
}
