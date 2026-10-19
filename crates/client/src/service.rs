//! The client service: a single-threaded actor that owns the account, the database and the relay
//! connection. Callers (the Tauri commands) talk to it through [`Client`], whose methods return
//! display data only.
//!
//! Lifecycle: `New` → setup → `Unlocked` ⇄ `Locked`. Locking drops the account and the open
//! database; it also happens after [`AUTO_LOCK`] without any command.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::Signer as _;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use rusqlite::{OptionalExtension as _, params};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use veil_core::account::{Account, IntroFields, Opened, random_id};
use veil_core::content::{Body, Content, Text};
use veil_core::invite::{Invite, InviteMode};
use veil_core::vault::{self, KdfParams, VaultHeader};
use veil_wire::{ENVELOPE_BUCKETS, ErrorCode, Request, Response, ServerFrame};
use zeroize::Zeroizing;

use crate::db::{Db, SqlBackend};
use crate::relay::{Relay, split_host_port};
use crate::{ClientError, Result, keystore, now_ms, now_secs, qr};

/// Lock after this long without a command.
pub const AUTO_LOCK: Duration = Duration::from_mins(5);
const TICK: Duration = Duration::from_secs(5);
const INVITE_TTL_SECS: u64 = 24 * 3600;
const MIN_PASSPHRASE: usize = 12;
const MAX_NAME: usize = 64;
/// Delivery tokens registered with the relay per batch.
const TOKEN_BATCH: usize = 8;
const SPARE_TOKENS: &str = "spare_tokens";
const HEADER_FILE: &str = "vault.hdr";
const DB_FILE: &str = "veil.db";

fn rng() -> rand::rand_core::UnwrapErr<OsRng> {
    OsRng.unwrap_err()
}

// ---- display data (the only things that cross to the UI) ---------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppState {
    New,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Connection {
    Online,
    Connecting,
    Offline,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeView {
    pub name: String,
    pub fingerprint: String,
    pub relay: String,
    pub connection: Connection,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    pub id: i64,
    pub name: String,
    pub verified: bool,
    pub initials: String,
    pub hue: i64,
    pub last_text: Option<String>,
    pub last_mine: bool,
    pub last_at_ms: Option<i64>,
    pub unread: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    pub id: i64,
    pub mine: bool,
    pub text: String,
    pub at_ms: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    pub link: String,
    pub qr_modules: String,
    pub qr_size: usize,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyView {
    pub groups: Vec<String>,
    pub verified: bool,
    pub name: String,
}

/// What changed, for the UI to refetch. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Contacts,
    Messages,
    Connection,
    Locked,
}

pub type Notify = Arc<dyn Fn(ChangeKind, Option<i64>) + Send + Sync>;

pub struct SetupInput {
    pub relay: String,
    pub pin: String,
    pub name: String,
    pub passphrase: Zeroizing<String>,
}

impl core::fmt::Debug for SetupInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SetupInput { .. }")
    }
}

// ---- commands ----------------------------------------------------------------------------

type Reply<T> = oneshot::Sender<Result<T>>;

enum Cmd {
    State(Reply<AppState>),
    Setup(SetupInput, Reply<()>),
    Unlock(Zeroizing<String>, Reply<()>),
    Lock(Reply<()>),
    Me(Reply<MeView>),
    Contacts(Reply<Vec<ContactView>>),
    Messages(i64, Reply<Vec<MessageView>>),
    Send(i64, String, Reply<MessageView>),
    MarkRead(i64, Reply<()>),
    CreateInvite(Reply<InviteView>),
    AcceptInvite(String, Reply<ContactView>),
    Safety(i64, Reply<SafetyView>),
    SetVerified(i64, bool, Reply<()>),
    Rename(i64, String, Reply<()>),
}

/// Handle to the client actor. Cheap to clone; `Send + Sync`.
#[derive(Clone)]
pub struct Client {
    tx: mpsc::Sender<Cmd>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Client")
    }
}

macro_rules! ask {
    ($self:ident, $variant:ident $(, $arg:expr)*) => {{
        let (tx, rx) = oneshot::channel();
        $self.tx.send(Cmd::$variant($($arg,)* tx)).await.map_err(|_| ClientError::Storage)?;
        rx.await.map_err(|_| ClientError::Storage)?
    }};
}

impl Client {
    /// Starts the actor on its own thread. `dir` is the app's private data directory.
    pub fn start(dir: PathBuf, kdf: KdfParams, notify: Notify) -> Result<Self> {
        let (tx, rx) = mpsc::channel(32);
        std::thread::Builder::new()
            .name("veil-client".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                    return;
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, Actor::new(dir, kdf, notify).run(rx));
            })
            .map_err(|_| ClientError::Storage)?;
        Ok(Self { tx })
    }

    pub async fn state(&self) -> Result<AppState> {
        ask!(self, State)
    }
    pub async fn setup(&self, input: SetupInput) -> Result<()> {
        ask!(self, Setup, input)
    }
    pub async fn unlock(&self, passphrase: Zeroizing<String>) -> Result<()> {
        ask!(self, Unlock, passphrase)
    }
    pub async fn lock(&self) -> Result<()> {
        ask!(self, Lock)
    }
    pub async fn me(&self) -> Result<MeView> {
        ask!(self, Me)
    }
    pub async fn contacts(&self) -> Result<Vec<ContactView>> {
        ask!(self, Contacts)
    }
    pub async fn messages(&self, contact: i64) -> Result<Vec<MessageView>> {
        ask!(self, Messages, contact)
    }
    pub async fn send(&self, contact: i64, text: String) -> Result<MessageView> {
        ask!(self, Send, contact, text)
    }
    pub async fn mark_read(&self, contact: i64) -> Result<()> {
        ask!(self, MarkRead, contact)
    }
    pub async fn create_invite(&self) -> Result<InviteView> {
        ask!(self, CreateInvite)
    }
    pub async fn accept_invite(&self, link: String) -> Result<ContactView> {
        ask!(self, AcceptInvite, link)
    }
    pub async fn safety(&self, contact: i64) -> Result<SafetyView> {
        ask!(self, Safety, contact)
    }
    pub async fn set_verified(&self, contact: i64, v: bool) -> Result<()> {
        ask!(self, SetVerified, contact, v)
    }
    pub async fn rename(&self, contact: i64, name: String) -> Result<()> {
        ask!(self, Rename, contact, name)
    }
}

// ---- the actor ---------------------------------------------------------------------------

struct Session {
    account: Account<SqlBackend>,
    db: Db,
    relay_addr: String,
    pin: [u8; 32],
    mailbox: [u8; 32],
    mbox_key: ed25519_dalek::SigningKey,
    name: String,
    relay: Option<Relay>,
    pushes: Option<mpsc::Receiver<ServerFrame>>,
    next_attempt: Instant,
    backoff: Duration,
}

struct Actor {
    dir: PathBuf,
    kdf: KdfParams,
    notify: Notify,
    session: Option<Box<Session>>,
    last_activity: Instant,
}

/// Normalises a display name from the network or the user: trimmed, no control characters,
/// at most [`MAX_NAME`] characters.
fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn parse_pin(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(ClientError::BadInput);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2).ok_or(ClientError::BadInput)?;
        let pair = s.get(at..at.saturating_add(2)).ok_or(ClientError::BadInput)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| ClientError::BadInput)?;
    }
    Ok(out)
}

fn token_hash(token: &[u8; 32]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"veil/v1/tok")
        .chain_update(token)
        .finalize()
        .to_vec()
}

fn arr32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| ClientError::Storage)
}

fn initials(name: &str) -> String {
    let mut out: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();
    if out.is_empty() {
        out.push('?');
    }
    out
}

async fn authenticate(
    relay: &Relay,
    pin: &[u8; 32],
    mailbox: &[u8; 32],
    key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let Response::Challenge(ch) = relay
        .call(Request::Challenge(veil_wire::MailboxRef {
            mailbox_id: mailbox.to_vec(),
        }))
        .await?
    else {
        return Err(ClientError::Relay);
    };
    let now = now_secs();
    let sig = key.sign(&veil_wire::auth_message(pin, mailbox, &ch.nonce, now));
    relay
        .call(Request::Authenticate(veil_wire::Authenticate {
            mailbox_id: mailbox.to_vec(),
            unix_secs: now,
            signature: sig.to_bytes().to_vec(),
        }))
        .await?;
    Ok(())
}

impl Actor {
    fn new(dir: PathBuf, kdf: KdfParams, notify: Notify) -> Self {
        Self {
            dir,
            kdf,
            notify,
            session: None,
            last_activity: Instant::now(),
        }
    }

    fn emit(&self, kind: ChangeKind, contact: Option<i64>) {
        (self.notify)(kind, contact);
    }

    fn state(&self) -> AppState {
        if self.session.is_some() {
            AppState::Unlocked
        } else if self.dir.join(HEADER_FILE).exists() {
            AppState::Locked
        } else {
            AppState::New
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>) {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    self.handle(cmd).await;
                }
                push = async {
                    match self.session.as_mut().and_then(|s| s.pushes.as_mut()) {
                        Some(p) => p.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match push {
                        Some(_) => self.sync().await,
                        None => self.disconnected(),
                    }
                }
                _ = tick.tick() => self.on_tick().await,
            }
        }
    }

    async fn on_tick(&mut self) {
        if self.session.is_some() && self.last_activity.elapsed() >= AUTO_LOCK {
            self.session = None;
            self.emit(ChangeKind::Locked, None);
            return;
        }
        let due = self
            .session
            .as_ref()
            .is_some_and(|s| s.relay.is_none() && Instant::now() >= s.next_attempt);
        if due {
            self.connect().await;
        }
    }

    fn disconnected(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.relay = None;
            s.pushes = None;
            s.next_attempt = Instant::now().checked_add(s.backoff).unwrap_or_else(Instant::now);
        }
        self.emit(ChangeKind::Connection, None);
    }

    async fn connect(&mut self) {
        let Some(s) = self.session.as_mut() else { return };
        let attempt = async {
            let (relay, pushes) = Relay::connect(&s.relay_addr, s.pin).await?;
            authenticate(&relay, &s.pin, &s.mailbox, &s.mbox_key).await?;
            Ok::<_, ClientError>((relay, pushes))
        };
        if let Ok((relay, pushes)) = attempt.await {
            s.relay = Some(relay);
            s.pushes = Some(pushes);
            s.backoff = Duration::from_secs(2);
            self.emit(ChangeKind::Connection, None);
            self.sync().await;
            self.retry_failed().await;
        } else {
            s.backoff = s.backoff.saturating_mul(2).min(Duration::from_mins(1));
            s.next_attempt = Instant::now().checked_add(s.backoff).unwrap_or_else(Instant::now);
        }
    }

    async fn handle(&mut self, cmd: Cmd) {
        if !matches!(cmd, Cmd::State(_)) {
            self.last_activity = Instant::now();
        }
        match cmd {
            Cmd::State(r) => {
                let _ = r.send(Ok(self.state()));
            }
            Cmd::Setup(input, r) => {
                let res = self.setup(input).await;
                let _ = r.send(res);
            }
            Cmd::Unlock(p, r) => {
                let res = self.unlock(&p).await;
                let _ = r.send(res);
            }
            Cmd::Lock(r) => {
                self.session = None;
                let _ = r.send(Ok(()));
            }
            Cmd::Me(r) => {
                let _ = r.send(self.me());
            }
            Cmd::Contacts(r) => {
                let _ = r.send(self.contacts());
            }
            Cmd::Messages(c, r) => {
                let _ = r.send(self.messages(c));
            }
            Cmd::Send(c, t, r) => {
                let res = self.send(c, &t).await;
                let _ = r.send(res);
            }
            Cmd::MarkRead(c, r) => {
                let _ = r.send(self.mark_read(c));
            }
            Cmd::CreateInvite(r) => {
                let res = self.create_invite().await;
                let _ = r.send(res);
            }
            Cmd::AcceptInvite(l, r) => {
                let res = self.accept_invite(&l).await;
                let _ = r.send(res);
            }
            Cmd::Safety(c, r) => {
                let _ = r.send(self.safety(c));
            }
            Cmd::SetVerified(c, v, r) => {
                let _ = r.send(self.set_verified(c, v));
            }
            Cmd::Rename(c, n, r) => {
                let _ = r.send(self.rename(c, &n));
            }
        }
    }

    fn s(&self) -> Result<&Session> {
        self.session.as_deref().ok_or(ClientError::Locked)
    }

    // ---- setup / unlock ----

    async fn setup(&mut self, input: SetupInput) -> Result<()> {
        if self.state() != AppState::New {
            return Err(ClientError::AlreadySetUp);
        }
        split_host_port(input.relay.trim())?;
        let pin = parse_pin(&input.pin)?;
        if input.passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(ClientError::BadInput);
        }
        let name = clean_name(&input.name);
        let relay_addr = input.relay.trim().to_owned();

        // 1. The relay first: nothing is written locally unless the relay works and accepts us.
        let (relay, pushes) = Relay::connect(&relay_addr, pin).await?;
        let mailbox: [u8; 32] = rand::random();
        let mbox_key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        relay
            .call(Request::CreateMailbox(veil_wire::CreateMailbox {
                mailbox_id: mailbox.to_vec(),
                auth_pub: mbox_key.verifying_key().to_bytes().to_vec(),
            }))
            .await?;
        authenticate(&relay, &pin, &mailbox, &mbox_key).await?;

        // 2. The vault: device secret + passphrase wrap the database key.
        std::fs::create_dir_all(&self.dir).map_err(|_| ClientError::Storage)?;
        let mut device = Zeroizing::new([0u8; 32]);
        rand::Rng::fill(&mut rng(), &mut device[..]);
        keystore::store(&self.dir, &device)?;
        let (header, key) = vault::create(&mut rng(), input.passphrase.as_bytes(), &device, self.kdf)?;
        let db = Db::open(&self.dir.join(DB_FILE), key.expose())?;
        let account = Account::create(SqlBackend(db.clone()), &mut rng())?;
        db.set_setting("relay", relay_addr.as_bytes())?;
        db.set_setting("pin", &pin)?;
        db.set_setting("name", name.as_bytes())?;
        db.set_setting("mailbox", &mailbox)?;
        db.set_setting("mailbox_key", mbox_key.as_bytes())?;
        // The header is written last: its presence is what marks setup as complete.
        std::fs::write(self.dir.join(HEADER_FILE), header.encode()).map_err(|_| ClientError::Storage)?;

        self.session = Some(Box::new(Session {
            account,
            db,
            relay_addr,
            pin,
            mailbox,
            mbox_key,
            name,
            relay: Some(relay),
            pushes: Some(pushes),
            next_attempt: Instant::now(),
            backoff: Duration::from_secs(2),
        }));
        self.emit(ChangeKind::Connection, None);
        Ok(())
    }

    async fn unlock(&mut self, passphrase: &str) -> Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        let raw = std::fs::read(self.dir.join(HEADER_FILE)).map_err(|_| ClientError::Storage)?;
        let header = VaultHeader::decode(&raw).map_err(|_| ClientError::Storage)?;
        let device = keystore::load(&self.dir)?;
        let key = vault::unlock(&header, passphrase.as_bytes(), &device)?;
        let db = Db::open(&self.dir.join(DB_FILE), key.expose())?;
        let get = |k: &str| db.setting(k)?.ok_or(ClientError::Storage);
        let relay_addr = String::from_utf8(get("relay")?.to_vec()).map_err(|_| ClientError::Storage)?;
        let pin = arr32(&get("pin")?)?;
        let name = String::from_utf8(get("name")?.to_vec()).map_err(|_| ClientError::Storage)?;
        let mailbox = arr32(&get("mailbox")?)?;
        let mbox_key = ed25519_dalek::SigningKey::from_bytes(&arr32(&get("mailbox_key")?)?);
        let account = Account::load(SqlBackend(db.clone()))?;
        self.session = Some(Box::new(Session {
            account,
            db,
            relay_addr,
            pin,
            mailbox,
            mbox_key,
            name,
            relay: None,
            pushes: None,
            next_attempt: Instant::now(),
            backoff: Duration::from_secs(2),
        }));
        self.connect().await;
        Ok(())
    }

    // ---- queries ----

    fn me(&self) -> Result<MeView> {
        let s = self.s()?;
        Ok(MeView {
            name: s.name.clone(),
            fingerprint: s.account.identity().display_fingerprint(),
            relay: s.relay_addr.clone(),
            connection: if s.relay.as_ref().is_some_and(Relay::is_open) {
                Connection::Online
            } else if s.next_attempt <= Instant::now() {
                Connection::Connecting
            } else {
                Connection::Offline
            },
        })
    }

    fn contact_view(db: &Db, id: i64) -> Result<ContactView> {
        let conn = db.conn();
        let (name, verified, unread): (String, bool, i64) = conn
            .query_row(
                "SELECT name, verified, unread FROM contacts WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(ClientError::UnknownContact)?;
        let last: Option<(String, bool, i64)> = conn
            .query_row(
                "SELECT body, mine, at_ms FROM messages WHERE contact = ?1 ORDER BY id DESC LIMIT 1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(ContactView {
            id,
            initials: initials(&name),
            hue: id.rem_euclid(8),
            name,
            verified,
            last_text: last.as_ref().map(|l| l.0.chars().take(120).collect()),
            last_mine: last.as_ref().is_some_and(|l| l.1),
            last_at_ms: last.map(|l| l.2),
            unread,
        })
    }

    fn contacts(&self) -> Result<Vec<ContactView>> {
        let s = self.s()?;
        let mut stmt = s.db.conn().prepare(
            "SELECT c.id FROM contacts c LEFT JOIN messages m ON m.contact = c.id
             GROUP BY c.id ORDER BY max(coalesce(m.at_ms, c.added_ms)) DESC",
        )?;
        let ids = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<core::result::Result<Vec<_>, _>>()?;
        ids.into_iter().map(|id| Self::contact_view(&s.db, id)).collect()
    }

    fn messages(&self, contact: i64) -> Result<Vec<MessageView>> {
        let s = self.s()?;
        let mut stmt = s.db.conn().prepare(
            "SELECT id, mine, body, at_ms, status FROM messages WHERE contact = ?1 ORDER BY id DESC LIMIT 500",
        )?;
        let mut out = stmt
            .query_map([contact], |r| {
                Ok(MessageView {
                    id: r.get(0)?,
                    mine: r.get(1)?,
                    text: r.get(2)?,
                    at_ms: r.get(3)?,
                    status: r.get(4)?,
                })
            })?
            .collect::<core::result::Result<Vec<_>, _>>()?;
        out.reverse();
        Ok(out)
    }

    fn mark_read(&self, contact: i64) -> Result<()> {
        self.s()?
            .db
            .conn()
            .execute("UPDATE contacts SET unread = 0 WHERE id = ?1", [contact])?;
        Ok(())
    }

    fn safety(&self, contact: i64) -> Result<SafetyView> {
        let s = self.s()?;
        let (address, name, verified): (String, String, bool) =
            s.db.conn()
                .query_row(
                    "SELECT address, name, verified FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let sn = s.account.safety_number(&addr)?;
        Ok(SafetyView {
            groups: sn.groups().into_iter().map(str::to_owned).collect(),
            verified,
            name,
        })
    }

    fn set_verified(&self, contact: i64, v: bool) -> Result<()> {
        let n = self.s()?.db.conn().execute(
            "UPDATE contacts SET verified = ?2 WHERE id = ?1",
            params![contact, v],
        )?;
        if n == 0 {
            return Err(ClientError::UnknownContact);
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    fn rename(&self, contact: i64, name: &str) -> Result<()> {
        let name = clean_name(name);
        if name.is_empty() {
            return Err(ClientError::BadInput);
        }
        let n = self.s()?.db.conn().execute(
            "UPDATE contacts SET name = ?2 WHERE id = ?1",
            params![contact, name],
        )?;
        if n == 0 {
            return Err(ClientError::UnknownContact);
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    // ---- relay operations ----

    fn relay(&self) -> Result<&Relay> {
        self.s()?
            .relay
            .as_ref()
            .filter(|r| r.is_open())
            .ok_or(ClientError::Unreachable)
    }

    /// Returns a fresh delivery token for our mailbox that the relay already accepts.
    ///
    /// Tokens are registered in batches of [`TOKEN_BATCH`] real tokens and handed out one at a
    /// time, so the relay only learns the number of invites rounded up to a batch, and no relay
    /// token slot is wasted on padding (`THREAT_MODEL` §5).
    async fn take_token(&self) -> Result<[u8; 32]> {
        let s = self.s()?;
        let mut spare = s.db.setting(SPARE_TOKENS)?.unwrap_or_default();
        if spare.len() < 32 {
            let mut batch = Zeroizing::new(vec![0u8; TOKEN_BATCH.saturating_mul(32)]);
            rand::Rng::fill(&mut rng(), &mut batch[..]);
            let add = batch
                .chunks_exact(32)
                .map(|t| token_hash(&arr32(t).unwrap_or_default()))
                .collect();
            self.relay()?
                .call(Request::UpdateTokens(veil_wire::UpdateTokens {
                    mailbox_id: s.mailbox.to_vec(),
                    add,
                    remove: vec![],
                }))
                .await?;
            spare = batch;
        }
        let token = arr32(spare.get(..32).ok_or(ClientError::Storage)?)?;
        s.db.set_setting(SPARE_TOKENS, spare.get(32..).unwrap_or_default())?;
        Ok(token)
    }

    async fn create_invite(&mut self) -> Result<InviteView> {
        let s = self.s()?;
        let token = self.take_token().await?;
        let now = now_secs();
        let created = s
            .account
            .create_invite(
                &mut rng(),
                InviteMode::Remote,
                &format!("wss://{}", s.relay_addr),
                s.pin,
                s.mailbox,
                token,
                now,
                INVITE_TTL_SECS,
            )
            .await?;
        let expires = now.saturating_add(INVITE_TTL_SECS);
        self.relay()?
            .call(Request::PutInvite(veil_wire::PutInvite {
                mailbox_id: s.mailbox.to_vec(),
                invite_id: created.invite.id.to_vec(),
                sealed: created.sealed_package.clone(),
                expires_at: expires,
            }))
            .await?;
        s.db.conn().execute(
            "INSERT INTO invites (id, token, expires) VALUES (?1, ?2, ?3)",
            params![
                created.invite.id.to_vec(),
                token.to_vec(),
                i64::try_from(expires).unwrap_or(i64::MAX)
            ],
        )?;
        let link = created.invite.to_link();
        let (qr_size, qr_modules) = qr::modules(&link)?;
        Ok(InviteView {
            link,
            qr_modules,
            qr_size,
            expires_at_ms: i64::try_from(expires).unwrap_or(i64::MAX).saturating_mul(1000),
        })
    }

    async fn accept_invite(&mut self, link: &str) -> Result<ContactView> {
        let invite = Invite::from_link(link.trim()).map_err(|_| ClientError::InviteInvalid)?;
        let s = self.s()?;
        if invite.relay_url.strip_prefix("wss://") != Some(s.relay_addr.as_str())
            || invite.relay_spki_sha256 != s.pin
        {
            return Err(ClientError::OtherRelay);
        }
        let now = now_secs();
        if invite.is_expired(now) {
            return Err(ClientError::InviteInvalid);
        }
        let Response::Invite(pkg) = self
            .relay()?
            .call(Request::TakeInvite(veil_wire::TakeInvite {
                invite_id: invite.id.to_vec(),
            }))
            .await
            .map_err(|e| match e {
                ClientError::Rejected(ErrorCode::NotFound) => ClientError::InviteInvalid,
                other => other,
            })?
        else {
            return Err(ClientError::Relay);
        };
        let my_token = self.take_token().await?;
        let s = self.s()?;
        let fields = IntroFields {
            mailbox_id: s.mailbox,
            delivery_token: my_token,
            display_name: (!s.name.is_empty()).then(|| s.name.clone()),
            rekey: None,
        };
        let red = s
            .account
            .redeem_invite(&mut rng(), &invite, &pkg.sealed, fields, now)
            .await?;
        self.relay()?
            .call(Request::Deposit(veil_wire::Deposit {
                mailbox_id: red.contact_mailbox_id.to_vec(),
                token: red.contact_delivery_token.to_vec(),
                envelope: red.envelope,
            }))
            .await?;
        let name = format!(
            "Contact {}",
            veil_core::identity::display_fingerprint(&red.contact_identity)
                .chars()
                .take(4)
                .collect::<String>()
        );
        let id = self.upsert_contact(
            red.contact.as_str(),
            &name,
            &red.contact_mailbox_id,
            &red.contact_delivery_token,
            &my_token,
        )?;
        self.emit(ChangeKind::Contacts, Some(id));
        Self::contact_view(&self.s()?.db, id)
    }

    fn upsert_contact(
        &self,
        address: &str,
        name: &str,
        mailbox: &[u8; 32],
        token: &[u8; 32],
        my_token: &[u8; 32],
    ) -> Result<i64> {
        let db = &self.s()?.db;
        db.conn().execute(
            "INSERT INTO contacts (address, name, mailbox, token, my_token, added_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(address) DO UPDATE SET mailbox = excluded.mailbox, token = excluded.token, my_token = excluded.my_token",
            params![address, name, mailbox.to_vec(), token.to_vec(), my_token.to_vec(), now_ms()],
        )?;
        Ok(db
            .conn()
            .query_row("SELECT id FROM contacts WHERE address = ?1", [address], |r| {
                r.get(0)
            })?)
    }

    async fn send(&mut self, contact: i64, text: &str) -> Result<MessageView> {
        let body = text.trim();
        if body.is_empty() {
            return Err(ClientError::BadInput);
        }
        let s = self.s()?;
        let address: String =
            s.db.conn()
                .query_row("SELECT address FROM contacts WHERE id = ?1", [contact], |r| {
                    r.get(0)
                })
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let content = Content {
            id: random_id(&mut rng()),
            sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            body: Some(Body::Text(Text {
                body: body.to_owned(),
                ..Default::default()
            })),
        };
        let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
        let at = now_ms();
        s.db.conn().execute(
            "INSERT INTO messages (contact, mine, body, at_ms, status, envelope) VALUES (?1, 1, ?2, ?3, 'sending', ?4)",
            params![contact, body, at, envelope],
        )?;
        let id = s.db.conn().last_insert_rowid();
        let status = if self.deliver(id).await { "sent" } else { "failed" };
        Ok(MessageView {
            id,
            mine: true,
            text: body.to_owned(),
            at_ms: at,
            status: status.to_owned(),
        })
    }

    /// Deposits a stored outgoing envelope. On success the envelope is erased.
    async fn deliver(&self, message: i64) -> bool {
        let Ok(s) = self.s() else { return false };
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = s
            .db
            .conn()
            .query_row(
                "SELECT c.mailbox, c.token, m.envelope FROM messages m JOIN contacts c ON c.id = m.contact
                 WHERE m.id = ?1 AND m.envelope IS NOT NULL",
                [message],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()
            .flatten();
        let Some((mailbox, token, envelope)) = row else {
            return false;
        };
        let Ok(relay) = self.relay() else {
            let _ =
                s.db.conn()
                    .execute("UPDATE messages SET status = 'failed' WHERE id = ?1", [message]);
            return false;
        };
        let ok = relay
            .call(Request::Deposit(veil_wire::Deposit {
                mailbox_id: mailbox,
                token,
                envelope,
            }))
            .await
            .is_ok();
        let sql = if ok {
            "UPDATE messages SET status = 'sent', envelope = NULL WHERE id = ?1"
        } else {
            "UPDATE messages SET status = 'failed' WHERE id = ?1"
        };
        let _ = s.db.conn().execute(sql, [message]);
        ok
    }

    async fn retry_failed(&mut self) {
        let Ok(s) = self.s() else { return };
        let ids: Vec<i64> = s
            .db
            .conn()
            .prepare("SELECT id FROM messages WHERE status IN ('failed', 'sending') AND envelope IS NOT NULL ORDER BY id")
            .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
            .unwrap_or_default();
        let mut any = false;
        for id in ids {
            any |= self.deliver(id).await;
        }
        if any {
            self.emit(ChangeKind::Messages, None);
        }
    }

    // ---- receiving ----

    /// Fetches, opens and acknowledges everything waiting in our mailbox.
    async fn sync(&mut self) {
        loop {
            let Ok(s) = self.s() else { return };
            let after =
                s.db.setting("last_seq")
                    .ok()
                    .flatten()
                    .and_then(|v| v.as_slice().try_into().ok().map(u64::from_be_bytes))
                    .unwrap_or(0);
            let Ok(relay) = self.relay() else { return };
            let Ok(Response::Envelopes(batch)) = relay
                .call(Request::Fetch(veil_wire::Fetch {
                    mailbox_id: s.mailbox.to_vec(),
                    after_seq: after,
                    limit: 8,
                }))
                .await
            else {
                return;
            };
            if batch.items.is_empty() {
                return;
            }
            let mut last = after;
            for item in batch.items {
                if !ENVELOPE_BUCKETS.contains(&item.envelope.len()) {
                    last = last.max(item.seq);
                    continue;
                }
                match self.process(&item.envelope).await {
                    // Storage failures are transient: stop without acking, retry next sync.
                    Err(ClientError::Storage) => return,
                    // Anything else is either done or permanently invalid: acknowledge it.
                    _ => last = last.max(item.seq),
                }
            }
            let Ok(s) = self.s() else { return };
            if s.db.set_setting("last_seq", &last.to_be_bytes()).is_err() {
                return;
            }
            if let Ok(relay) = self.relay() {
                let _ = relay
                    .call(Request::Ack(veil_wire::Ack {
                        mailbox_id: s.mailbox.to_vec(),
                        up_to_seq: last,
                    }))
                    .await;
            }
        }
    }

    async fn process(&mut self, envelope: &[u8]) -> Result<()> {
        let s = self.s()?;
        let opened = s
            .account
            .open(&mut rng(), envelope, now_secs())
            .await
            .map_err(|e| match e {
                veil_core::CoreError::Storage => ClientError::Storage,
                _ => ClientError::Protocol,
            })?;
        match opened {
            Opened::Message { from, content } => {
                let Some(Body::Text(t)) = content.body else {
                    return Ok(());
                };
                let id: Option<i64> =
                    s.db.conn()
                        .query_row(
                            "SELECT id FROM contacts WHERE address = ?1",
                            [from.as_str()],
                            |r| r.get(0),
                        )
                        .optional()?;
                let Some(id) = id else { return Ok(()) };
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, body, at_ms, status) VALUES (?1, 0, ?2, ?3, 'received')",
                    params![id, t.body, now_ms()],
                )?;
                s.db.conn()
                    .execute("UPDATE contacts SET unread = unread + 1 WHERE id = ?1", [id])?;
                self.emit(ChangeKind::Messages, Some(id));
            }
            Opened::NewContact { from, intro, .. } => {
                let invite_id = intro.invite_id.clone().unwrap_or_default();
                let my_token: Option<Vec<u8>> =
                    s.db.conn()
                        .query_row("SELECT token FROM invites WHERE id = ?1", [&invite_id], |r| {
                            r.get(0)
                        })
                        .optional()?;
                let Some(my_token) = my_token else { return Ok(()) };
                let mailbox = arr32(&intro.mailbox_id).map_err(|_| ClientError::Protocol)?;
                let token = arr32(&intro.delivery_token).map_err(|_| ClientError::Protocol)?;
                let name = intro
                    .display_name
                    .as_deref()
                    .map(clean_name)
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "New contact".into());
                let id = self.upsert_contact(from.as_str(), &name, &mailbox, &token, &arr32(&my_token)?)?;
                self.s()?
                    .db
                    .conn()
                    .execute("DELETE FROM invites WHERE id = ?1", [&invite_id])?;
                self.emit(ChangeKind::Contacts, Some(id));
            }
        }
        Ok(())
    }
}

/// Default KDF cost for this platform (PROTOCOL §12).
pub fn default_kdf() -> KdfParams {
    if cfg!(target_os = "android") {
        KdfParams::MOBILE
    } else {
        KdfParams::DESKTOP
    }
}
