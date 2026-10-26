//! The client service: a single-threaded actor that owns the account, the database and the relay
//! connection. Callers (the Tauri commands) talk to it through [`Client`], whose methods return
//! display data only.
//!
//! Lifecycle: `New` → setup → `Unlocked` ⇄ `Locked`. Locking drops the account and the open
//! database; it also happens after [`AUTO_LOCK`] without user activity. Only commands the user
//! causes count as activity; refreshes triggered by incoming events do not (review P4-2).
//!
//! The relay can delay or flood us, so every relay round trip is cancelled by a lock request or
//! by the auto-lock deadline, and each sync is bounded (review P4-1).

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::Signer as _;
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use rusqlite::{OptionalExtension as _, params};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use veil_core::account::{Account, IntroFields, Opened, random_id};
use veil_core::content::{Body, Content, MailboxUpdate, Receipt, ReceiptKind, Text, TimerUpdate, Typing};
use veil_core::invite::{Invite, InviteMode};
use veil_core::vault::{self, KdfParams, PurgeTag, Unlocked, VaultHeader};
use veil_wire::{ENVELOPE_BUCKETS, ErrorCode, Request, Response, ServerFrame};
use zeroize::Zeroizing;

use crate::db::{Db, SqlBackend};
use crate::relay::{Relay, split_host_port};
use crate::unlock::{self, SecretKind};
use crate::{ClientError, Result, keystore, now_ms, now_secs, qr, write_atomic};

/// Lock after this long without user activity.
pub const AUTO_LOCK: Duration = Duration::from_mins(5);
/// At most this many fetch batches per sync; the rest waits for the next push or tick.
const MAX_BATCHES: usize = 16;
const FETCH_LIMIT: u32 = 8;
/// Give up re-sending a message after this many failed deposits.
const MAX_ATTEMPTS: i64 = 20;
const TICK: Duration = Duration::from_secs(5);
const INVITE_TTL: Duration = Duration::from_hours(24);
const MAX_NAME: usize = 64;
/// Delivery tokens registered with the relay per batch.
const TOKEN_BATCH: usize = 8;
const SPARE_TOKENS: &str = "spare_tokens";
/// Longest disappearing-message timer (the core's limit): 4 weeks. The UI offers off,
/// 5 minutes, 1 hour, 1 day, 1 week and 4 weeks.
pub const MAX_TIMER_SECS: u32 = 2_419_200;
/// Message ids per receipt (the core's limit is 256).
const RECEIPT_IDS: usize = 64;
/// Token hashes per `UpdateTokens` request (the relay's limit).
const TOKEN_REMOVALS: usize = 64;
/// Resend "typing" at most this often while the user keeps typing.
const TYPING_RESEND: Duration = Duration::from_secs(4);
/// A typing message older than this (by its sender's clock) is stale and not shown.
const TYPING_STALE_MS: i64 = 15_000;
/// While connected, retry failed messages and updates this often (not only on reconnect).
const RETRY_EVERY: Duration = Duration::from_mins(1);
const RECEIPTS: &str = "receipts";
const TYPING: &str = "typing";
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

// Display data: each flag is a separate fact the UI shows.
#[allow(clippy::struct_excessive_bools)]
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
    pub blocked: bool,
    /// Disappearing-message timer in seconds; 0 is off.
    pub timer_secs: u32,
    /// This contact arrived with the same name as an existing one: possibly someone who
    /// reinstalled Veil, possibly an impostor. Shown until the safety number is verified or
    /// the user dismisses it (INV-ID-2).
    pub key_warning: bool,
    /// Unblocked, but the update with their new token has not reached them yet.
    pub unblock_pending: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    pub id: i64,
    pub mine: bool,
    /// `text`, or `timer` for a "disappearing messages changed" notice.
    pub kind: String,
    pub text: String,
    pub at_ms: i64,
    /// `sending`, `sent`, `failed`, `delivered`, `read` (mine) or `received`.
    pub status: String,
    /// For a `timer` notice: the new timer in seconds.
    pub timer_secs: Option<u32>,
    pub expires_at_ms: Option<i64>,
}

/// The privacy settings: both off unless the user turns them on.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyView {
    pub read_receipts: bool,
    pub typing: bool,
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

/// What the locked screen needs: which keyboard, whether to offer biometrics, any wait.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockInfo {
    pub kind: SecretKind,
    pub biometric: bool,
    pub wait_secs: u64,
}

/// The security settings, shown while unlocked.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityView {
    pub kind: SecretKind,
    pub biometric: bool,
    pub purge_set: bool,
}

/// How an unlock attempt ended. `Purged` is for the app shell only (to clear the webview's
/// storage and the platform key); the UI is told "wrong PIN or password" (ADR-0012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    /// `during_wait`: the attempt came during a retry delay, so the UI must answer "try again
    /// later" like any other attempt then (review UR3-1).
    Purged {
        during_wait: bool,
    },
}

/// What changed, for the UI to refetch. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Contacts,
    Messages,
    Connection,
    Locked,
    /// The contact started typing (only with typing indicators on).
    Typing,
    TypingStopped,
}

pub type Notify = Arc<dyn Fn(ChangeKind, Option<i64>) + Send + Sync>;

pub struct SetupInput {
    pub relay: String,
    pub pin: String,
    pub name: String,
    pub kind: SecretKind,
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
    Unlock(Zeroizing<String>, Reply<UnlockOutcome>),
    UnlockInfo(Reply<UnlockInfo>),
    Security(Reply<SecurityView>),
    ChangeSecret(Zeroizing<String>, SecretKind, Zeroizing<String>, Reply<()>),
    SetPurge(Zeroizing<String>, Zeroizing<String>, Reply<()>),
    ClearPurge(Zeroizing<String>, Reply<()>),
    BioPrepare(Zeroizing<String>, Reply<Zeroizing<[u8; 32]>>),
    BioCommit(Vec<u8>, Reply<()>),
    BioDisable(Reply<()>),
    BioSealed(Reply<Option<Vec<u8>>>),
    UnlockBio(Zeroizing<[u8; 32]>, Reply<()>),
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
    DeleteContact(i64, Reply<()>),
    SetBlocked(i64, bool, Reply<()>),
    SetTimer(i64, u32, Reply<()>),
    DismissKeyWarning(i64, Reply<()>),
    Privacy(Reply<PrivacyView>),
    SetPrivacy(PrivacyView, Reply<()>),
    Typing(i64, bool, Reply<()>),
    Touch(Reply<()>),
    Reset(Reply<()>),
}

/// Lets a lock request pre-empt relay I/O that is in progress in the actor.
#[derive(Default)]
struct Interrupt {
    pending: AtomicBool,
    notify: tokio::sync::Notify,
}

/// Handle to the client actor. Cheap to clone; `Send + Sync`.
#[derive(Clone)]
pub struct Client {
    tx: mpsc::Sender<Cmd>,
    interrupt: Arc<Interrupt>,
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
        Self::start_with_auto_lock(dir, kdf, notify, AUTO_LOCK)
    }

    /// [`Client::start`] with a different auto-lock delay (tests).
    pub fn start_with_auto_lock(
        dir: PathBuf,
        kdf: KdfParams,
        notify: Notify,
        auto_lock: Duration,
    ) -> Result<Self> {
        Self::start_with(dir, kdf, notify, auto_lock, None)
    }

    /// Starts with a platform guard for the device secret (the Android Keystore in the app).
    pub fn start_with(
        dir: PathBuf,
        kdf: KdfParams,
        notify: Notify,
        auto_lock: Duration,
        guard: keystore::Guard,
    ) -> Result<Self> {
        Self::start_inner(dir, kdf, notify, auto_lock, guard, INVITE_TTL)
    }

    /// [`Client::start`] with short-lived invites, so tests can watch them expire.
    #[doc(hidden)]
    pub fn start_with_invite_ttl(
        dir: PathBuf,
        kdf: KdfParams,
        notify: Notify,
        ttl: Duration,
    ) -> Result<Self> {
        Self::start_inner(dir, kdf, notify, AUTO_LOCK, None, ttl)
    }

    fn start_inner(
        dir: PathBuf,
        kdf: KdfParams,
        notify: Notify,
        auto_lock: Duration,
        guard: keystore::Guard,
        invite_ttl: Duration,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(32);
        let interrupt = Arc::new(Interrupt::default());
        let actor_interrupt = Arc::clone(&interrupt);
        std::thread::Builder::new()
            .name("veil-client".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                    return;
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &rt,
                    Actor::new(
                        dir,
                        kdf,
                        notify,
                        actor_interrupt,
                        auto_lock,
                        guard,
                        invite_ttl.as_secs(),
                    )
                    .run(rx),
                );
            })
            .map_err(|_| ClientError::Storage)?;
        Ok(Self { tx, interrupt })
    }

    pub async fn state(&self) -> Result<AppState> {
        ask!(self, State)
    }
    pub async fn setup(&self, input: SetupInput) -> Result<()> {
        ask!(self, Setup, input)
    }
    /// Unlocks with the PIN or password. Entering the Purge PIN wipes Veil and returns
    /// [`UnlockOutcome::Purged`].
    pub async fn unlock(&self, passphrase: Zeroizing<String>) -> Result<UnlockOutcome> {
        ask!(self, Unlock, passphrase)
    }
    pub async fn unlock_info(&self) -> Result<UnlockInfo> {
        ask!(self, UnlockInfo)
    }
    pub async fn security(&self) -> Result<SecurityView> {
        ask!(self, Security)
    }
    /// Changes the PIN or password (and possibly its kind). Clears the Purge PIN, which must be
    /// set again (ADR-0012).
    pub async fn change_secret(
        &self,
        current: Zeroizing<String>,
        kind: SecretKind,
        new: Zeroizing<String>,
    ) -> Result<()> {
        ask!(self, ChangeSecret, current, kind, new)
    }
    pub async fn set_purge(&self, current: Zeroizing<String>, purge: Zeroizing<String>) -> Result<()> {
        ask!(self, SetPurge, current, purge)
    }
    pub async fn clear_purge(&self, current: Zeroizing<String>) -> Result<()> {
        ask!(self, ClearPurge, current)
    }
    /// Step 1 of turning on biometric unlock: checks the current PIN or password and returns a
    /// fresh secret for the platform keystore to seal. **Key material:** for the app shell's
    /// native code only, never for the webview.
    pub async fn biometric_prepare(&self, current: Zeroizing<String>) -> Result<Zeroizing<[u8; 32]>> {
        ask!(self, BioPrepare, current)
    }
    /// Step 2: stores the keystore-sealed secret and turns biometric unlock on.
    pub async fn biometric_commit(&self, sealed: Vec<u8>) -> Result<()> {
        ask!(self, BioCommit, sealed)
    }
    pub async fn biometric_disable(&self) -> Result<()> {
        ask!(self, BioDisable)
    }
    /// The sealed secret, for the platform keystore to open behind a biometric prompt.
    pub async fn biometric_sealed(&self) -> Result<Option<Vec<u8>>> {
        ask!(self, BioSealed)
    }
    pub async fn unlock_biometric(&self, secret: Zeroizing<[u8; 32]>) -> Result<()> {
        ask!(self, UnlockBio, secret)
    }
    /// Locks now: relay I/O in progress is cancelled first, so the relay cannot delay this.
    pub async fn lock(&self) -> Result<()> {
        self.interrupt.pending.store(true, Ordering::SeqCst);
        self.interrupt.notify.notify_waiters();
        ask!(self, Lock)
    }
    /// The user did something (typed, tapped): postpones auto-lock.
    pub async fn touch(&self) -> Result<()> {
        ask!(self, Touch)
    }
    /// Deletes this device's identity, contacts and messages, and the device secret. Used to
    /// start over after a forgotten passphrase. Cannot be undone.
    pub async fn reset(&self) -> Result<()> {
        self.interrupt.pending.store(true, Ordering::SeqCst);
        self.interrupt.notify.notify_waiters();
        ask!(self, Reset)
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
    /// Deletes the contact, the conversation and the session; their delivery token is
    /// withdrawn from the relay. They can only come back through a new invite.
    pub async fn delete_contact(&self, contact: i64) -> Result<()> {
        ask!(self, DeleteContact, contact)
    }
    /// Blocking withdraws their delivery token, so the relay refuses anything they send.
    /// Unblocking gives them a new token in an encrypted mailbox update (needs the relay).
    pub async fn set_blocked(&self, contact: i64, blocked: bool) -> Result<()> {
        ask!(self, SetBlocked, contact, blocked)
    }
    /// Sets the disappearing-message timer for both sides, in seconds (0 is off, at most
    /// [`MAX_TIMER_SECS`]).
    pub async fn set_timer(&self, contact: i64, secs: u32) -> Result<()> {
        ask!(self, SetTimer, contact, secs)
    }
    pub async fn dismiss_key_warning(&self, contact: i64) -> Result<()> {
        ask!(self, DismissKeyWarning, contact)
    }
    pub async fn privacy(&self) -> Result<PrivacyView> {
        ask!(self, Privacy)
    }
    pub async fn set_privacy(&self, p: PrivacyView) -> Result<()> {
        ask!(self, SetPrivacy, p)
    }
    /// The user is typing (`true`) or stopped. Sent only with typing indicators on, and
    /// throttled.
    pub async fn typing(&self, contact: i64, started: bool) -> Result<()> {
        ask!(self, Typing, contact, started)
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
    /// The last sync stopped early; continue on the next tick.
    more: bool,
    /// When we last told each contact "typing" (in memory only).
    typing_sent: HashMap<i64, Instant>,
    last_retry: Instant,
}

struct Actor {
    dir: PathBuf,
    kdf: KdfParams,
    notify: Notify,
    session: Option<Box<Session>>,
    last_activity: Instant,
    interrupt: Arc<Interrupt>,
    auto_lock: Duration,
    guard: keystore::Guard,
    /// Set after a Purge PIN: until Veil restarts, the lock screen keeps behaving like the
    /// vault that is gone (review U-4).
    decoy: Option<Decoy>,
    invite_ttl_secs: u64,
}

struct Decoy {
    kind: SecretKind,
    biometric: bool,
    failures: u32,
    last: u64,
}

/// Every file Veil keeps in its data directory. Nothing else there is touched (review U-1).
pub const DATA_FILES: &[&str] = &[
    HEADER_FILE,
    DB_FILE,
    "veil.db-journal",
    "veil.db-wal",
    "veil.db-shm",
    keystore::FILE,
    unlock::CONFIG_FILE,
    unlock::ATTEMPTS_FILE,
    unlock::PURGE_FILE,
    unlock::BIO_WRAP_FILE,
    unlock::BIO_SEALED_FILE,
];

/// Characters that are invisible or reorder text, so a name could imitate another (P4-11).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF0}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Normalises a display name from the network or the user: trimmed, no control, invisible or
/// bidi-override characters, at most [`MAX_NAME`] characters.
fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
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

/// mailbox, token, envelope, contact id, introduction pending.
type DeliveryRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, bool);

/// A name compared for the key-change warning: case and spacing do not make it different.
fn name_key(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Columns: `id, mine, body, at_ms, status, kind, expires_at_ms`.
fn message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageView> {
    let kind: String = r.get(5)?;
    let body: String = r.get(2)?;
    let timer_secs = (kind == "timer").then(|| body.parse().unwrap_or(0));
    Ok(MessageView {
        id: r.get(0)?,
        mine: r.get(1)?,
        text: if kind == "text" { body } else { String::new() },
        kind,
        at_ms: r.get(3)?,
        status: r.get(4)?,
        timer_secs,
        expires_at_ms: r.get(6)?,
    })
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
    fn new(
        dir: PathBuf,
        kdf: KdfParams,
        notify: Notify,
        interrupt: Arc<Interrupt>,
        auto_lock: Duration,
        guard: keystore::Guard,
        invite_ttl_secs: u64,
    ) -> Self {
        Self {
            dir,
            kdf,
            notify,
            session: None,
            last_activity: Instant::now(),
            interrupt,
            auto_lock,
            guard,
            decoy: None,
            invite_ttl_secs,
        }
    }

    fn lock_now(&mut self) {
        let was_open = self.session.take().is_some();
        self.interrupt.pending.store(false, Ordering::SeqCst);
        if was_open {
            self.emit(ChangeKind::Locked, None);
        }
    }

    fn idle_expired(&self) -> bool {
        self.last_activity.elapsed() >= self.auto_lock
    }

    /// Runs relay I/O so that a lock request or the auto-lock deadline cancels it (P4-1).
    async fn interruptible<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        let notified = self.interrupt.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.interrupt.pending.load(Ordering::SeqCst) {
            return Err(ClientError::Locked);
        }
        let left = self.auto_lock.saturating_sub(self.last_activity.elapsed());
        tokio::select! {
            r = fut => r,
            () = &mut notified => Err(ClientError::Locked),
            () = tokio::time::sleep(left) => Err(ClientError::Locked),
        }
    }

    /// One relay round trip on the live connection; see [`Self::interruptible`].
    async fn call(&self, req: Request) -> Result<Response> {
        let relay = self.relay()?;
        self.interruptible(relay.call(req)).await
    }

    fn emit(&self, kind: ChangeKind, contact: Option<i64>) {
        (self.notify)(kind, contact);
    }

    fn state(&self) -> AppState {
        if self.session.is_some() {
            AppState::Unlocked
        } else if self.decoy.is_some() || self.dir.join(HEADER_FILE).exists() {
            AppState::Locked
        } else {
            AppState::New
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>) {
        let mut tick = tokio::time::interval(
            TICK.min(self.auto_lock.checked_div(4).unwrap_or(TICK))
                .max(Duration::from_millis(50)),
        );
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
        if self.session.is_some() && self.idle_expired() {
            self.lock_now();
            return;
        }
        if self.session.is_none() {
            return;
        }
        self.expire_messages();
        let _ = self.cleanup_invites().await;
        let Some(s) = self.session.as_ref() else { return };
        if s.relay.is_none() && Instant::now() >= s.next_attempt {
            self.connect().await;
        } else if s.relay.as_ref().is_some_and(Relay::is_open) {
            let retry = s.last_retry.elapsed() >= RETRY_EVERY;
            if s.more {
                self.sync().await;
            }
            self.flush_token_removals().await;
            // A failed message or mailbox update is not left until the next reconnect
            // (review M1R2-4).
            if retry {
                self.retry_failed().await;
            }
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
        let Some(s) = self.session.as_ref() else { return };
        let (addr, pin, mailbox, key) = (s.relay_addr.clone(), s.pin, s.mailbox, s.mbox_key.clone());
        let attempt = self
            .interruptible(Box::pin(async {
                let (relay, pushes) = Relay::connect(&addr, pin).await?;
                authenticate(&relay, &pin, &mailbox, &key).await?;
                Ok::<_, ClientError>((relay, pushes))
            }))
            .await;
        let Some(s) = self.session.as_mut() else { return };
        if let Ok((relay, pushes)) = attempt {
            s.relay = Some(relay);
            s.pushes = Some(pushes);
            s.backoff = Duration::from_secs(2);
            self.emit(ChangeKind::Connection, None);
            self.sync().await;
            self.retry_failed().await;
            self.flush_token_removals().await;
        } else {
            s.backoff = s.backoff.saturating_mul(2).min(Duration::from_mins(1));
            s.next_attempt = Instant::now().checked_add(s.backoff).unwrap_or_else(Instant::now);
        }
    }

    // One arm per command; splitting the dispatch would only hide it.
    #[allow(clippy::too_many_lines)]
    async fn handle(&mut self, cmd: Cmd) {
        // Only what the user does keeps Veil unlocked; UI refreshes caused by incoming
        // messages or connection changes must not (P4-2).
        if matches!(
            cmd,
            Cmd::Setup(..)
                | Cmd::Unlock(..)
                | Cmd::UnlockBio(..)
                | Cmd::ChangeSecret(..)
                | Cmd::SetPurge(..)
                | Cmd::ClearPurge(..)
                | Cmd::BioPrepare(..)
                | Cmd::BioCommit(..)
                | Cmd::Touch(_)
                | Cmd::Send(..)
                | Cmd::CreateInvite(_)
                | Cmd::AcceptInvite(..)
                | Cmd::SetVerified(..)
                | Cmd::Rename(..)
                | Cmd::DeleteContact(..)
                | Cmd::SetBlocked(..)
                | Cmd::SetTimer(..)
                | Cmd::DismissKeyWarning(..)
                | Cmd::SetPrivacy(..)
                | Cmd::Typing(..)
        ) {
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
                self.lock_now();
                let _ = r.send(Ok(()));
            }
            Cmd::Touch(r) => {
                let _ = r.send(self.s().map(|_| ()));
            }
            Cmd::Reset(r) => {
                self.lock_now();
                self.decoy = None;
                let _ = r.send(self.wipe());
            }
            Cmd::UnlockInfo(r) => {
                let _ = r.send(Ok(self.unlock_info()));
            }
            Cmd::Security(r) => {
                let _ = r.send(self.security());
            }
            Cmd::ChangeSecret(cur, kind, new, r) => {
                let _ = r.send(self.change_secret(&cur, kind, &new));
            }
            Cmd::SetPurge(cur, purge, r) => {
                let _ = r.send(self.set_purge(&cur, &purge));
            }
            Cmd::ClearPurge(cur, r) => {
                let _ = r.send(self.clear_purge(&cur));
            }
            Cmd::BioPrepare(cur, r) => {
                let _ = r.send(self.bio_prepare(&cur));
            }
            Cmd::BioCommit(sealed, r) => {
                let _ = r.send(self.bio_commit(&sealed));
            }
            Cmd::BioDisable(r) => {
                let _ = r.send(self.bio_disable());
            }
            Cmd::BioSealed(r) => {
                let _ = r.send(Ok(self.bio_sealed()));
            }
            Cmd::UnlockBio(secret, r) => {
                let res = self.unlock_bio(&secret).await;
                let _ = r.send(res);
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
                let res = self.mark_read(c).await;
                let _ = r.send(res);
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
            Cmd::DeleteContact(c, r) => {
                let res = self.delete_contact(c).await;
                let _ = r.send(res);
            }
            Cmd::SetBlocked(c, b, r) => {
                let res = self.set_blocked(c, b).await;
                let _ = r.send(res);
            }
            Cmd::SetTimer(c, t, r) => {
                let res = self.set_timer(c, t).await;
                let _ = r.send(res);
            }
            Cmd::DismissKeyWarning(c, r) => {
                let _ = r.send(self.dismiss_key_warning(c));
            }
            Cmd::Privacy(r) => {
                let _ = r.send(self.privacy());
            }
            Cmd::SetPrivacy(p, r) => {
                let _ = r.send(self.set_privacy(p));
            }
            Cmd::Typing(c, started, r) => {
                let res = self.typing(c, started).await;
                let _ = r.send(res);
            }
        }
    }

    /// Deletes everything Veil keeps on this device: the files in [`DATA_FILES`] (and their
    /// `.tmp` siblings), the device secret and its platform key. The header and the device
    /// secret go first, and are retried, because without them nothing else can be decrypted.
    /// Used by "Start over", by setup for debris, and by the Purge PIN.
    fn wipe(&self) -> Result<()> {
        let gone = |f: &str| !self.dir.join(f).exists();
        let mut keys_gone = false;
        let started = Instant::now();
        for attempt in 0..3 {
            // A hanging platform keystore must not stretch a purge visibly (review UR3-2).
            if attempt > 0 && started.elapsed() > Duration::from_secs(2) {
                break;
            }
            if attempt > 0 {
                // A virus scanner or backup tool may hold the file for a moment.
                std::thread::sleep(Duration::from_millis(200));
            }
            keys_gone = keystore::remove(&self.dir, &self.guard).is_ok();
            let _ = std::fs::remove_file(self.dir.join(HEADER_FILE));
            if keys_gone && gone(HEADER_FILE) && gone(keystore::FILE) {
                break;
            }
        }
        let mut failed = !(keys_gone && gone(HEADER_FILE) && gone(keystore::FILE));
        for f in DATA_FILES {
            for name in [(*f).to_owned(), format!("{f}.tmp")] {
                if let Err(e) = std::fs::remove_file(self.dir.join(&name)) {
                    failed |= e.kind() != std::io::ErrorKind::NotFound;
                }
            }
        }
        if failed { Err(ClientError::Storage) } else { Ok(()) }
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
        unlock::validate(input.kind, &input.passphrase)?;
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

        // 2. The vault: device secret + passphrase wrap the database key. Without a header no
        //    setup ever completed, so anything else here is debris from an interrupted setup or
        //    an earlier install, and is replaced (P4-3).
        std::fs::create_dir_all(&self.dir).map_err(|_| ClientError::Storage)?;
        self.wipe()?;
        let mut device = Zeroizing::new([0u8; 32]);
        rand::Rng::fill(&mut rng(), &mut device[..]);
        keystore::store(&self.dir, &device, &self.guard)?;
        let (header, key) = vault::create(&mut rng(), input.passphrase.as_bytes(), &device, self.kdf)?;
        let db = Db::open(&self.dir.join(DB_FILE), key.expose())?;
        let account = Account::create(SqlBackend(db.clone()), &mut rng())?;
        db.set_setting("relay", relay_addr.as_bytes())?;
        db.set_setting("pin", &pin)?;
        db.set_setting("name", name.as_bytes())?;
        db.set_setting("mailbox", &mailbox)?;
        db.set_setting("mailbox_key", mbox_key.as_bytes())?;
        unlock::store_config(
            &self.dir,
            unlock::Config {
                kind: input.kind,
                biometric: false,
            },
        )?;
        unlock::store_purge(&self.dir, &PurgeTag::random(&mut rng()))?;
        // The header is written last: its presence is what marks setup as complete.
        write_atomic(&self.dir, HEADER_FILE, &header.encode())?;

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
            more: true,
            typing_sent: HashMap::new(),
            last_retry: Instant::now(),
        }));
        self.emit(ChangeKind::Connection, None);
        Ok(())
    }

    fn header(&self) -> Result<VaultHeader> {
        let raw = std::fs::read(self.dir.join(HEADER_FILE)).map_err(|_| ClientError::Storage)?;
        VaultHeader::decode(&raw).map_err(|_| ClientError::Storage)
    }

    async fn unlock(&mut self, passphrase: &str) -> Result<UnlockOutcome> {
        if self.session.is_some() {
            return Ok(UnlockOutcome::Unlocked);
        }
        let now = now_secs();
        if let Some(d) = self.decoy.as_mut() {
            // The vault is gone: spend the time a real attempt takes and answer like one.
            let _ = vault::create(&mut rng(), passphrase.as_bytes(), &[0u8; 32], self.kdf);
            if unlock::remaining(d.failures, d.last, now) > 0 {
                return Err(ClientError::RetryLater);
            }
            d.failures = d.failures.saturating_add(1);
            d.last = now;
            return Err(ClientError::WrongPassphrase);
        }
        let Ok(header) = self.header() else {
            let _ = vault::create(&mut rng(), passphrase.as_bytes(), &[0u8; 32], self.kdf);
            return Err(ClientError::WrongPassphrase);
        };
        let device = keystore::load(&self.dir, &self.guard)?;
        let purge = unlock::load_purge(&self.dir);
        let waiting = unlock::wait_secs(&self.dir, now) > 0;
        match vault::unlock_checking(&header, passphrase.as_bytes(), &device, purge.as_ref()) {
            // The Purge PIN works even during a retry delay (review U-3); nothing else does.
            Ok(Unlocked::Purge) => {
                let c = unlock::load_config(&self.dir);
                let (failures, last) = unlock::load_attempts(&self.dir);
                self.lock_now();
                let _ = self.wipe();
                // Answer like the attempt it replaces: during a delay a real attempt leaves
                // the countdown alone; otherwise it counts as one more failure (UR2-3).
                self.decoy = Some(if waiting {
                    Decoy {
                        kind: c.kind,
                        biometric: c.biometric,
                        failures,
                        last,
                    }
                } else {
                    Decoy {
                        kind: c.kind,
                        biometric: c.biometric,
                        failures: failures.saturating_add(1),
                        last: now,
                    }
                });
                Ok(UnlockOutcome::Purged { during_wait: waiting })
            }
            _ if waiting => Err(ClientError::RetryLater),
            Ok(Unlocked::Key(key)) => {
                unlock::reset_attempts(&self.dir);
                self.open_session(&key).await?;
                Ok(UnlockOutcome::Unlocked)
            }
            Err(_) => {
                unlock::record_failure(&self.dir, now)?;
                Err(ClientError::WrongPassphrase)
            }
        }
    }

    async fn unlock_bio(&mut self, secret: &[u8; 32]) -> Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        let header = self.header()?;
        let device = keystore::load(&self.dir, &self.guard)?;
        let blob = std::fs::read(self.dir.join(unlock::BIO_WRAP_FILE))
            .map_err(|_| ClientError::BiometricUnavailable)?;
        let key = vault::unwrap_with_secret(&header, &blob, secret, &device)
            .map_err(|_| ClientError::BiometricUnavailable)?;
        unlock::reset_attempts(&self.dir);
        self.open_session(&key).await
    }

    async fn open_session(&mut self, key: &vault::DbKey) -> Result<()> {
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
            more: true,
            typing_sent: HashMap::new(),
            last_retry: Instant::now(),
        }));
        self.expire_messages();
        let _ = self.cleanup_invites().await;
        self.connect().await;
        Ok(())
    }

    // ---- security settings ----

    fn unlock_info(&self) -> UnlockInfo {
        if let Some(d) = &self.decoy {
            return UnlockInfo {
                kind: d.kind,
                biometric: d.biometric,
                wait_secs: unlock::remaining(d.failures, d.last, now_secs()),
            };
        }
        let c = unlock::load_config(&self.dir);
        UnlockInfo {
            kind: c.kind,
            biometric: c.biometric && self.dir.join(unlock::BIO_SEALED_FILE).exists(),
            wait_secs: unlock::wait_secs(&self.dir, now_secs()),
        }
    }

    fn security(&self) -> Result<SecurityView> {
        let s = self.s()?;
        let c = unlock::load_config(&self.dir);
        Ok(SecurityView {
            kind: c.kind,
            biometric: c.biometric,
            purge_set: s.db.setting("purge_set")?.is_some_and(|v| v.as_slice() == [1]),
        })
    }

    /// Checks the current PIN or password while unlocked. Wrong answers count as failed
    /// attempts, so settings cannot be used to guess faster than the unlock screen.
    fn verify_current(&self, current: &str) -> Result<(VaultHeader, Zeroizing<[u8; 32]>, vault::DbKey)> {
        self.s()?;
        let now = now_secs();
        if unlock::wait_secs(&self.dir, now) > 0 {
            return Err(ClientError::RetryLater);
        }
        let header = self.header()?;
        let device = keystore::load(&self.dir, &self.guard)?;
        if let Ok(key) = vault::unlock(&header, current.as_bytes(), &device) {
            unlock::reset_attempts(&self.dir);
            Ok((header, device, key))
        } else {
            unlock::record_failure(&self.dir, now)?;
            Err(ClientError::WrongPassphrase)
        }
    }

    fn change_secret(&self, current: &str, kind: SecretKind, new: &str) -> Result<()> {
        unlock::validate(kind, new)?;
        let (header, device, _) = self.verify_current(current)?;
        let next = vault::rewrap(
            &mut rng(),
            &header,
            current.as_bytes(),
            new.as_bytes(),
            &device,
            header.params,
        )?;
        // The new header re-salts the KDF, so the old Purge PIN tag can never match again;
        // replace it first so a crash cannot leave a live tag for the new salt's vault.
        // Flag first, then the tag: a crash in between shows "not set" (true) rather than
        // "set" with no live tag (review U-6).
        self.s()?.db.set_setting("purge_set", &[0])?;
        unlock::store_purge(&self.dir, &PurgeTag::random(&mut rng()))?;
        // A text keyboard can type both PINs and passwords, so the lock screen is usable at
        // either crash point if the kind says "password" while the header changes (UR2-5).
        let mut c = unlock::load_config(&self.dir);
        let old = c.kind;
        if c.kind != kind {
            c.kind = SecretKind::Password;
            unlock::store_config(&self.dir, c)?;
        }
        if let Err(e) = write_atomic(&self.dir, HEADER_FILE, &next.encode()) {
            // The old secret still opens the vault: show its kind again (review UR3-3).
            c.kind = old;
            let _ = unlock::store_config(&self.dir, c);
            return Err(e);
        }
        c.kind = kind;
        unlock::store_config(&self.dir, c)
    }

    fn set_purge(&self, current: &str, purge: &str) -> Result<()> {
        let kind = unlock::load_config(&self.dir).kind;
        unlock::validate(kind, purge)?;
        let (header, device, _) = self.verify_current(current)?;
        let tag = vault::purge_tag(&header, purge.as_bytes(), &device)
            .map_err(|_| ClientError::PurgeSameAsUnlock)?;
        unlock::store_purge(&self.dir, &tag)?;
        self.s()?.db.set_setting("purge_set", &[1])
    }

    fn clear_purge(&self, current: &str) -> Result<()> {
        self.verify_current(current)?;
        self.s()?.db.set_setting("purge_set", &[0])?;
        unlock::store_purge(&self.dir, &PurgeTag::random(&mut rng()))
    }

    fn bio_prepare(&self, current: &str) -> Result<Zeroizing<[u8; 32]>> {
        let (header, device, key) = self.verify_current(current)?;
        // Biometrics stay off until the new secret is sealed and committed (review U-9).
        self.bio_files_off()?;
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::Rng::fill(&mut rng(), &mut secret[..]);
        let blob = vault::wrap_with_secret(&mut rng(), &header, &key, &secret, &device)?;
        write_atomic(&self.dir, unlock::BIO_WRAP_FILE, &blob)?;
        Ok(secret)
    }

    fn bio_commit(&self, sealed: &[u8]) -> Result<()> {
        self.s()?;
        if sealed.is_empty()
            || sealed.len() > unlock::MAX_SEALED
            || !self.dir.join(unlock::BIO_WRAP_FILE).exists()
        {
            return Err(ClientError::BadInput);
        }
        write_atomic(&self.dir, unlock::BIO_SEALED_FILE, sealed)?;
        let mut c = unlock::load_config(&self.dir);
        c.biometric = true;
        unlock::store_config(&self.dir, c)
    }

    fn bio_files_off(&self) -> Result<()> {
        for f in [unlock::BIO_SEALED_FILE, unlock::BIO_WRAP_FILE] {
            match std::fs::remove_file(self.dir.join(f)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(ClientError::Storage),
                _ => {}
            }
        }
        if !self.dir.join(HEADER_FILE).exists() {
            return Ok(());
        }
        let mut c = unlock::load_config(&self.dir);
        c.biometric = false;
        unlock::store_config(&self.dir, c)
    }

    /// Turns biometric unlock off and deletes its files. Allowed while locked too: the app
    /// calls it when the platform reports the biometric key gone (e.g. new fingerprint added).
    fn bio_disable(&mut self) -> Result<()> {
        if let Some(d) = self.decoy.as_mut() {
            d.biometric = false;
            return Ok(());
        }
        self.bio_files_off()
    }

    fn bio_sealed(&self) -> Option<Vec<u8>> {
        if let Some(d) = &self.decoy {
            // The app then shows the normal prompt, and the missing key ends it the way a
            // changed fingerprint set does (review U-4).
            return d.biometric.then(|| vec![0u8; 60]);
        }
        if !unlock::load_config(&self.dir).biometric {
            return None;
        }
        std::fs::read(self.dir.join(unlock::BIO_SEALED_FILE))
            .ok()
            .filter(|b| !b.is_empty() && b.len() <= unlock::MAX_SEALED)
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
        let (name, verified, unread, blocked, timer_secs, key_warning): (String, bool, i64, bool, u32, bool) =
            conn.query_row(
                "SELECT name, verified, unread, blocked, timer_secs, key_warning FROM contacts WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?
            .ok_or(ClientError::UnknownContact)?;
        let last: Option<(String, bool, i64)> = conn
            .query_row(
                "SELECT body, mine, at_ms FROM messages WHERE contact = ?1 AND kind = 'text'
                 AND (expires_at_ms IS NULL OR expires_at_ms > ?2) ORDER BY id DESC LIMIT 1",
                params![id, now_ms()],
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
            blocked,
            timer_secs,
            key_warning,
            unblock_pending: conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE contact = ?1 AND mine = 1 AND kind = 'mailbox'
                 AND envelope IS NOT NULL)",
                [id],
                |r| r.get(0),
            )?,
        })
    }

    fn contacts(&self) -> Result<Vec<ContactView>> {
        let s = self.s()?;
        let mut stmt = s.db.conn().prepare(
            "SELECT c.id FROM contacts c LEFT JOIN messages m ON m.contact = c.id AND m.kind IN ('text', 'timer')
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
            "SELECT id, mine, body, at_ms, status, kind, expires_at_ms FROM messages WHERE contact = ?1
             AND kind IN ('text', 'timer') ORDER BY id DESC LIMIT 500",
        )?;
        // Expired rows are deleted by the tick (at most 5 s late); the UI hides them on time.
        let mut out = stmt
            .query_map([contact], message_row)?
            .collect::<core::result::Result<Vec<_>, _>>()?;
        out.reverse();
        Ok(out)
    }

    async fn mark_read(&self, contact: i64) -> Result<()> {
        self.s()?
            .db
            .conn()
            .execute("UPDATE contacts SET unread = 0 WHERE id = ?1", [contact])?;
        if self.privacy()?.read_receipts {
            self.send_receipts(contact, ReceiptKind::Read).await;
        }
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
            "UPDATE contacts SET verified = ?2, key_warning = CASE WHEN ?2 THEN 0 ELSE key_warning END
             WHERE id = ?1",
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
            self.call(Request::UpdateTokens(veil_wire::UpdateTokens {
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
        let token = self.take_token().await?;
        let r = self.publish_invite(token).await;
        if r.is_err()
            && let Ok(s) = self.s()
        {
            // The relay already accepts this token; no invite carries it (review M1-12).
            let _ = Self::queue_token_removal(&s.db, &token);
        }
        r
    }

    async fn publish_invite(&self, token: [u8; 32]) -> Result<InviteView> {
        let s = self.s()?;
        let ttl = self.invite_ttl_secs;
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
                ttl,
            )
            .await?;
        let expires = now.saturating_add(ttl);
        self.call(Request::PutInvite(veil_wire::PutInvite {
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
        // The pin, not the address, identifies the relay: one relay can be reached at several
        // addresses (a tailnet IP for some contacts, a public name for others), and the pin
        // proves it is the same server holding the same key.
        if invite.relay_spki_sha256 != s.pin {
            return Err(ClientError::OtherRelay);
        }
        let now = now_secs();
        if invite.is_expired(now) {
            return Err(ClientError::InviteInvalid);
        }
        // The token first: once the relay hands out the invite it is gone (P4-10).
        let my_token = self.take_token().await?;
        let Response::Invite(pkg) = self
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
        let s = self.s()?;
        let fields = IntroFields {
            mailbox_id: s.mailbox,
            delivery_token: my_token,
            display_name: (!s.name.is_empty()).then(|| s.name.clone()),
            rekey: None,
        };
        // The core's session state and our contact row are committed together (P4-6). The
        // introduction is stored with the contact and delivered (and retried) from there.
        let id = self
            .atomically(async {
                let red = s
                    .account
                    .redeem_invite(&mut rng(), &invite, &pkg.sealed, fields, now)
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
                s.db.conn().execute(
                    "UPDATE contacts SET intro = ?2 WHERE id = ?1",
                    params![id, red.envelope],
                )?;
                Ok(id)
            })
            .await?;
        self.deliver_intro(id).await;
        self.emit(ChangeKind::Contacts, Some(id));
        Self::contact_view(&self.s()?.db, id)
    }

    /// Runs `fut` inside one `SQLite` savepoint: everything it writes, including the core's
    /// store, is committed together or not at all.
    async fn atomically<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        let db = self.s()?.db.clone();
        let conn = db.conn();
        conn.execute_batch("SAVEPOINT veil_op")?;
        let r = fut.await;
        let end = if r.is_ok() {
            "RELEASE veil_op"
        } else {
            "ROLLBACK TO veil_op; RELEASE veil_op"
        };
        if conn.execute_batch(end).is_err() || !conn.is_autocommit() {
            // This is always the outermost savepoint: if it could not be closed, roll the whole
            // transaction back, or every later write would sit in a transaction that never
            // commits while its messages are acked (review P4R2-2).
            if !conn.is_autocommit() {
                let _ = conn.execute_batch("ROLLBACK");
            }
            return Err(ClientError::Storage);
        }
        r
    }

    /// Deposits a contact's pending introduction, if any.
    async fn deliver_intro(&self, contact: i64) -> bool {
        let Ok(s) = self.s() else { return false };
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> =
            s.db.conn()
                .query_row(
                    "SELECT mailbox, token, intro FROM contacts WHERE id = ?1 AND intro IS NOT NULL",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .ok()
                .flatten();
        let Some((mailbox, token, envelope)) = row else {
            return false;
        };
        let ok = self
            .call(Request::Deposit(veil_wire::Deposit {
                mailbox_id: mailbox,
                token,
                envelope,
            }))
            .await
            .is_ok();
        if ok {
            let _ =
                s.db.conn()
                    .execute("UPDATE contacts SET intro = NULL WHERE id = ?1", [contact]);
        }
        ok
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
        let (id, blocked): (i64, bool) = db.conn().query_row(
            "SELECT id, blocked FROM contacts WHERE address = ?1",
            [address],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if blocked {
            // Re-paired while blocked: they stay blocked, so the new token goes too (M1-9).
            Self::queue_token_removal(db, my_token)?;
        }
        Ok(id)
    }

    async fn send(&mut self, contact: i64, text: &str) -> Result<MessageView> {
        let body = text.trim();
        if body.is_empty() {
            return Err(ClientError::BadInput);
        }
        if let Some(s) = self.session.as_mut() {
            // The message itself ends "typing" on the other side.
            s.typing_sent.remove(&contact);
        }
        let s = self.s()?;
        let (address, blocked, timer): (String, bool, u32) =
            s.db.conn()
                .query_row(
                    "SELECT address, blocked, timer_secs FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        if blocked {
            return Err(ClientError::Blocked);
        }
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let content = Content {
            id: random_id(&mut rng()),
            sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            body: Some(Body::Text(Text {
                body: body.to_owned(),
                expire_timer_secs: (timer > 0).then_some(timer),
                ..Default::default()
            })),
        };
        let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
        let at = now_ms();
        let expires = (timer > 0).then(|| at.saturating_add(i64::from(timer).saturating_mul(1000)));
        s.db.conn().execute(
            "INSERT INTO messages (contact, mine, body, at_ms, status, envelope, msg_id, expires_at_ms)
             VALUES (?1, 1, ?2, ?3, 'sending', ?4, ?5, ?6)",
            params![contact, body, at, envelope, content.id, expires],
        )?;
        let id = s.db.conn().last_insert_rowid();
        let status = if self.deliver(id).await { "sent" } else { "failed" };
        Ok(MessageView {
            id,
            mine: true,
            kind: "text".into(),
            text: body.to_owned(),
            at_ms: at,
            status: status.to_owned(),
            timer_secs: None,
            expires_at_ms: expires,
        })
    }

    /// Deposits a stored outgoing envelope. On success the envelope is erased.
    async fn deliver(&self, message: i64) -> bool {
        let Ok(s) = self.s() else { return false };
        let row: Option<DeliveryRow> =
            s.db.conn()
                .query_row(
                    "SELECT c.mailbox, c.token, m.envelope, c.id, c.intro IS NOT NULL
                 FROM messages m JOIN contacts c ON c.id = m.contact
                 WHERE m.id = ?1 AND m.envelope IS NOT NULL AND c.blocked = 0",
                    [message],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()
                .ok()
                .flatten();
        let Some((mailbox, token, envelope, contact, intro_pending)) = row else {
            return false;
        };
        // The contact can only place our messages after our introduction: never send ahead
        // of it, or the message would be dropped on arrival (review P4R2-1).
        if intro_pending && !self.deliver_intro(contact).await {
            let _ = s.db.conn().execute(
                "UPDATE messages SET status = 'failed', attempts = attempts + 1 WHERE id = ?1",
                [message],
            );
            return false;
        }
        let ok = self
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
            "UPDATE messages SET status = 'failed', attempts = attempts + 1 WHERE id = ?1"
        };
        let _ = s.db.conn().execute(sql, [message]);
        ok
    }

    async fn retry_failed(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.last_retry = Instant::now();
        }
        let Ok(s) = self.s() else { return };
        let ids: Vec<i64> =
            s.db.conn()
                .prepare(
                    "SELECT m.id FROM messages m JOIN contacts c ON c.id = m.contact
                     WHERE m.status IN ('failed', 'sending') AND m.envelope IS NOT NULL
                     AND m.attempts < ?1 AND c.blocked = 0 ORDER BY m.id",
                )
                .and_then(|mut st| st.query_map([MAX_ATTEMPTS], |r| r.get(0))?.collect())
                .unwrap_or_default();
        let intros: Vec<i64> =
            s.db.conn()
                .prepare("SELECT id FROM contacts WHERE intro IS NOT NULL AND blocked = 0 ORDER BY id")
                .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
                .unwrap_or_default();
        for id in intros {
            if self.interrupt.pending.load(Ordering::SeqCst) || self.idle_expired() {
                return;
            }
            self.deliver_intro(id).await;
        }
        let mut any = false;
        for id in ids {
            if self.interrupt.pending.load(Ordering::SeqCst) || self.idle_expired() {
                break;
            }
            any |= self.deliver(id).await;
        }
        if any {
            self.emit(ChangeKind::Messages, None);
        }
    }

    // ---- receiving ----

    /// Fetches, opens and acknowledges what is waiting in our mailbox, at most
    /// [`MAX_BATCHES`] batches at a time. A relay that replays old sequence numbers or never
    /// runs dry cannot keep the actor busy (P4-1).
    async fn sync(&mut self) {
        self.sync_batches().await;
        self.send_delivery_receipts().await;
    }

    async fn sync_batches(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.more = false;
        }
        for _ in 0..MAX_BATCHES {
            if self.idle_expired() {
                return;
            }
            let Ok(s) = self.s() else { return };
            let after =
                s.db.setting("last_seq")
                    .ok()
                    .flatten()
                    .and_then(|v| v.as_slice().try_into().ok().map(u64::from_be_bytes))
                    .unwrap_or(0);
            let mailbox = s.mailbox.to_vec();
            let Ok(Response::Envelopes(batch)) = self
                .call(Request::Fetch(veil_wire::Fetch {
                    mailbox_id: mailbox.clone(),
                    after_seq: after,
                    limit: FETCH_LIMIT,
                }))
                .await
            else {
                return;
            };
            let full = batch.items.len() >= usize::try_from(FETCH_LIMIT).unwrap_or(usize::MAX);
            let mut last = after;
            let mut stalled = false;
            for item in batch.items {
                // Only strictly newer items count; replays and reordering are skipped.
                if item.seq <= last {
                    continue;
                }
                if !ENVELOPE_BUCKETS.contains(&item.envelope.len()) {
                    last = item.seq;
                    continue;
                }
                match self.process(&item.envelope).await {
                    // Storage failures are transient and were rolled back: stop without
                    // acking, retry on the next sync.
                    Err(ClientError::Storage) => {
                        stalled = true;
                        break;
                    }
                    // Anything else is either done or permanently invalid: acknowledge it.
                    _ => last = item.seq,
                }
            }
            if last == after {
                return;
            }
            let Ok(s) = self.s() else { return };
            if s.db.set_setting("last_seq", &last.to_be_bytes()).is_err() {
                return;
            }
            let _ = self
                .call(Request::Ack(veil_wire::Ack {
                    mailbox_id: mailbox,
                    up_to_seq: last,
                }))
                .await;
            if stalled || !full {
                return;
            }
        }
        if let Some(s) = self.session.as_mut() {
            s.more = true;
        }
    }

    /// Opens one envelope and stores the result. The core's ratchet update and our rows are
    /// committed together, so a crash or a storage error cannot lose the message (P4-6).
    async fn process(&mut self, envelope: &[u8]) -> Result<()> {
        self.atomically(self.process_inner(envelope)).await
    }

    async fn process_inner(&self, envelope: &[u8]) -> Result<()> {
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
                let row: Option<(i64, bool)> =
                    s.db.conn()
                        .query_row(
                            "SELECT id, blocked FROM contacts WHERE address = ?1",
                            [from.as_str()],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                let Some((id, blocked)) = row else { return Ok(()) };
                let (msg_id, sent_at_ms) = (content.id.clone(), content.sent_at_ms);
                let Some(body) = content.body else { return Ok(()) };
                // Whatever a blocked contact had queued before the block is dropped; only a
                // mailbox update is kept, so unblocking later can still reach them.
                if blocked && !matches!(body, Body::MailboxUpdate(_)) {
                    return Ok(());
                }
                self.receive(id, &msg_id, sent_at_ms, body)?;
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
                // Addresses are key hashes, so a changed key arrives as a new contact. One that
                // takes the name of an existing contact gets a warning, never their history
                // (INV-ID-2).
                let key = name_key(&name);
                let clash = intro.display_name.is_some() && {
                    let mut stmt =
                        s.db.conn()
                            .prepare("SELECT name FROM contacts WHERE address != ?1")?;
                    let names = stmt
                        .query_map([from.as_str()], |r| r.get::<_, String>(0))?
                        .collect::<core::result::Result<Vec<_>, _>>()?;
                    names.iter().any(|n| name_key(n) == key)
                };
                let id = self.upsert_contact(from.as_str(), &name, &mailbox, &token, &arr32(&my_token)?)?;
                if clash {
                    s.db.conn()
                        .execute("UPDATE contacts SET key_warning = 1 WHERE id = ?1", [id])?;
                }
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

impl Actor {
    /// Stores one message from a known contact. Runs inside [`Self::process`]'s transaction.
    fn receive(&self, contact: i64, msg_id: &[u8], sent_at_ms: u64, body: Body) -> Result<()> {
        let s = self.s()?;
        let conn = s.db.conn();
        let now = now_ms();
        match body {
            Body::Text(t) => {
                // Their timer, or ours if they sent none (an older version that ignores timers).
                let local: u32 =
                    conn.query_row("SELECT timer_secs FROM contacts WHERE id = ?1", [contact], |r| {
                        r.get(0)
                    })?;
                let expires = t
                    .expire_timer_secs
                    .filter(|t| *t > 0)
                    .or((local > 0).then_some(local))
                    .map(|t| now.saturating_add(i64::from(t).saturating_mul(1000)));
                conn.execute(
                    "INSERT INTO messages (contact, mine, body, at_ms, status, msg_id, expires_at_ms)
                     VALUES (?1, 0, ?2, ?3, 'received', ?4, ?5)",
                    params![contact, t.body, now, msg_id, expires],
                )?;
                conn.execute("UPDATE contacts SET unread = unread + 1 WHERE id = ?1", [contact])?;
                self.emit(ChangeKind::Messages, Some(contact));
            }
            Body::TimerUpdate(t) => {
                // Only a newer change of theirs counts, so a retried older one cannot undo it
                // (review M1-7). Their clock orders their own changes.
                let sent = i64::try_from(sent_at_ms).unwrap_or(i64::MAX);
                let n = conn.execute(
                    "UPDATE contacts SET timer_secs = ?2, timer_peer_ms = ?3 WHERE id = ?1 AND timer_peer_ms < ?3",
                    params![contact, t.seconds, sent],
                )?;
                if n == 0 {
                    return Ok(());
                }
                conn.execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 0, 'timer', ?2, ?3, 'received')",
                    params![contact, t.seconds.to_string(), now],
                )?;
                self.emit(ChangeKind::Messages, Some(contact));
                self.emit(ChangeKind::Contacts, Some(contact));
            }
            // Receipts only count while we send them too.
            Body::Receipt(r) if self.privacy()?.read_receipts => {
                let sql = if r.kind == i32::from(ReceiptKind::Read) {
                    "UPDATE messages SET status = 'read', envelope = NULL
                     WHERE contact = ?1 AND mine = 1 AND msg_id = ?2 AND status != 'read'"
                } else {
                    "UPDATE messages SET status = 'delivered', envelope = NULL
                     WHERE contact = ?1 AND mine = 1 AND msg_id = ?2 AND status IN ('sending', 'failed', 'sent')"
                };
                let mut changed = 0usize;
                for id in &r.ids {
                    changed = changed.saturating_add(conn.execute(sql, params![contact, id])?);
                }
                if changed > 0 {
                    self.emit(ChangeKind::Messages, Some(contact));
                }
            }
            Body::Typing(t) if self.privacy()?.typing => {
                let age = now.saturating_sub(i64::try_from(sent_at_ms).unwrap_or(0));
                if age.abs() <= TYPING_STALE_MS {
                    let kind = if t.started {
                        ChangeKind::Typing
                    } else {
                        ChangeKind::TypingStopped
                    };
                    self.emit(kind, Some(contact));
                }
            }
            // A new delivery token for this contact (they unblocked us). Moving to another
            // relay is not supported, so such an update is ignored.
            // Only a newer one (by their clock) counts, as for timers (review M1R2-1).
            Body::MailboxUpdate(m) if m.relay_url.is_none() => {
                conn.execute(
                    "UPDATE contacts SET mailbox = ?2, token = ?3, mailbox_peer_ms = ?4
                     WHERE id = ?1 AND mailbox_peer_ms < ?4",
                    params![
                        contact,
                        m.new_mailbox_id,
                        m.new_delivery_token,
                        i64::try_from(sent_at_ms).unwrap_or(i64::MAX)
                    ],
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    // ---- privacy settings ----

    fn privacy(&self) -> Result<PrivacyView> {
        let db = &self.s()?.db;
        let on = |k: &str| -> Result<bool> { Ok(db.setting(k)?.is_some_and(|v| v.as_slice() == [1])) };
        Ok(PrivacyView {
            read_receipts: on(RECEIPTS)?,
            typing: on(TYPING)?,
        })
    }

    fn set_privacy(&self, p: PrivacyView) -> Result<()> {
        let db = &self.s()?.db;
        if p.read_receipts && !self.privacy()?.read_receipts {
            // No receipts at all for what arrived or was read while receipts were off (M1-4).
            db.conn().execute(
                "UPDATE messages SET receipt = 2 WHERE mine = 0 AND receipt < 2",
                [],
            )?;
        }
        db.set_setting(RECEIPTS, &[u8::from(p.read_receipts)])?;
        db.set_setting(TYPING, &[u8::from(p.typing)])?;
        Ok(())
    }

    /// Seals and deposits a message that is not stored (receipt, typing, mailbox update):
    /// best effort, nothing is retried. Never to a blocked contact or ahead of our
    /// introduction.
    async fn send_ephemeral(&self, contact: i64, body: Body) -> Result<()> {
        // Offline: do not advance the session for a message that cannot go out.
        self.relay()?;
        let s = self.s()?;
        let (address, mailbox, token): (String, Vec<u8>, Vec<u8>) = s
            .db
            .conn()
            .query_row(
                "SELECT address, mailbox, token FROM contacts WHERE id = ?1 AND blocked = 0 AND intro IS NULL",
                [contact],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(ClientError::UnknownContact)?;
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let content = Content {
            id: random_id(&mut rng()),
            sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            body: Some(body),
        };
        let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
        self.call(Request::Deposit(veil_wire::Deposit {
            mailbox_id: mailbox,
            token,
            envelope,
        }))
        .await?;
        Ok(())
    }

    /// Sends `kind` receipts for a contact's messages that have not had one yet.
    async fn send_receipts(&self, contact: i64, kind: ReceiptKind) {
        let level: i64 = if kind == ReceiptKind::Read { 2 } else { 1 };
        let Ok(s) = self.s() else { return };
        let rows: Vec<(i64, Vec<u8>)> =
            s.db.conn()
                .prepare(
                    "SELECT id, msg_id FROM messages WHERE contact = ?1 AND mine = 0 AND kind = 'text'
                 AND msg_id IS NOT NULL AND receipt < ?2 ORDER BY id LIMIT 256",
                )
                .and_then(|mut st| {
                    st.query_map(params![contact, level], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect()
                })
                .unwrap_or_default();
        for chunk in rows.chunks(RECEIPT_IDS) {
            let receipt = Receipt {
                kind: i32::from(kind),
                ids: chunk.iter().map(|(_, m)| m.clone()).collect(),
            };
            match self.send_ephemeral(contact, Body::Receipt(receipt)).await {
                Ok(()) => {}
                // Refused for good (they blocked or deleted us): counted as sent, or every sync
                // would seal and try again (review M1-6).
                Err(ClientError::Rejected(code)) if code != ErrorCode::RateLimited => {}
                Err(_) => return,
            }
            for (id, _) in chunk {
                let _ = s.db.conn().execute(
                    "UPDATE messages SET receipt = ?2 WHERE id = ?1 AND receipt < ?2",
                    params![id, level],
                );
            }
        }
    }

    async fn send_delivery_receipts(&self) {
        if !self.privacy().is_ok_and(|p| p.read_receipts) {
            return;
        }
        let Ok(s) = self.s() else { return };
        let contacts: Vec<i64> =
            s.db.conn()
                .prepare(
                    "SELECT DISTINCT m.contact FROM messages m JOIN contacts c ON c.id = m.contact
                 WHERE m.mine = 0 AND m.kind = 'text' AND m.msg_id IS NOT NULL AND m.receipt = 0
                 AND c.blocked = 0 AND c.intro IS NULL",
                )
                .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
                .unwrap_or_default();
        for c in contacts {
            self.send_receipts(c, ReceiptKind::Delivered).await;
        }
    }

    async fn typing(&mut self, contact: i64, started: bool) -> Result<()> {
        if !self.privacy()?.typing {
            return Ok(());
        }
        let now = Instant::now();
        let s = self.session.as_mut().ok_or(ClientError::Locked)?;
        let last = s.typing_sent.get(&contact).copied();
        if started {
            if last.is_some_and(|t| now.duration_since(t) < TYPING_RESEND) {
                return Ok(());
            }
            s.typing_sent.insert(contact, now);
        } else if s.typing_sent.remove(&contact).is_none() {
            return Ok(());
        }
        // Best effort: a lost typing message only means no indicator.
        let _ = self
            .send_ephemeral(contact, Body::Typing(Typing { started }))
            .await;
        Ok(())
    }

    // ---- disappearing messages ----

    async fn set_timer(&mut self, contact: i64, secs: u32) -> Result<()> {
        if secs > MAX_TIMER_SECS {
            return Err(ClientError::BadInput);
        }
        let s = self.s()?;
        let (address, blocked): (String, bool) =
            s.db.conn()
                .query_row(
                    "SELECT address, blocked FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        if blocked {
            return Err(ClientError::Blocked);
        }
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let content = Content {
            id: random_id(&mut rng()),
            sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            body: Some(Body::TimerUpdate(TimerUpdate { seconds: secs })),
        };
        let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
        // The notice is stored like a message, so it is retried until it gets through.
        let id = self
            .atomically(async {
                // Our change counts in the ordering too, so the later of two simultaneous
                // changes (by wall clock) wins on both sides (review M1R2-2).
                s.db.conn().execute(
                    "UPDATE contacts SET timer_secs = ?2, timer_peer_ms = max(timer_peer_ms, ?3) WHERE id = ?1",
                    params![contact, secs, now_ms()],
                )?;
                // An older change still waiting to go out must not arrive after this one.
                s.db.conn().execute(
                    "UPDATE messages SET envelope = NULL WHERE contact = ?1 AND mine = 1 AND kind = 'timer'
                     AND envelope IS NOT NULL",
                    [contact],
                )?;
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status, envelope)
                     VALUES (?1, 1, 'timer', ?2, ?3, 'sending', ?4)",
                    params![contact, secs.to_string(), now_ms(), envelope],
                )?;
                Ok(s.db.conn().last_insert_rowid())
            })
            .await?;
        self.deliver(id).await;
        self.emit(ChangeKind::Messages, Some(contact));
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    /// Deletes messages whose timer ran out. `secure_delete` overwrites their content in the
    /// database file (INV-REST-9).
    fn expire_messages(&self) {
        let Ok(s) = self.s() else { return };
        let now = now_ms();
        let contacts: Vec<i64> =
            s.db.conn()
                .prepare("SELECT DISTINCT contact FROM messages WHERE expires_at_ms <= ?1")
                .and_then(|mut st| st.query_map([now], |r| r.get(0))?.collect())
                .unwrap_or_default();
        if contacts.is_empty() {
            return;
        }
        // Unread rows are the newest incoming ones: take the expired ones among them off the
        // count before they go (review M1-11, M1R2-3).
        for c in &contacts {
            let _ = s.db.conn().execute(
                "UPDATE contacts SET unread = max(0, unread - (SELECT count(*) FROM (
                   SELECT expires_at_ms FROM messages WHERE contact = ?1 AND mine = 0 AND kind = 'text'
                   ORDER BY id DESC LIMIT (SELECT unread FROM contacts WHERE id = ?1))
                 WHERE expires_at_ms <= ?2)) WHERE id = ?1",
                params![c, now],
            );
        }
        if s.db
            .conn()
            .execute("DELETE FROM messages WHERE expires_at_ms <= ?1", [now])
            .is_err()
        {
            return;
        }

        for c in contacts {
            self.emit(ChangeKind::Messages, Some(c));
        }
        self.emit(ChangeKind::Contacts, None);
    }

    // ---- contacts: delete, block ----

    fn drop_pending_mailbox_updates(db: &Db, contact: i64) -> Result<()> {
        db.conn().execute(
            "UPDATE messages SET envelope = NULL WHERE contact = ?1 AND mine = 1 AND kind = 'mailbox'
             AND envelope IS NOT NULL",
            [contact],
        )?;
        Ok(())
    }

    fn queue_token_removal(db: &Db, token: &[u8]) -> Result<()> {
        db.conn().execute(
            "INSERT OR IGNORE INTO token_removals (hash) VALUES (?1)",
            [token_hash(&arr32(token)?)],
        )?;
        Ok(())
    }

    /// Withdraws queued delivery tokens from the relay. Kept in the database until the relay
    /// confirms, so going offline only delays it.
    async fn flush_token_removals(&self) {
        let Ok(s) = self.s() else { return };
        if self.relay().is_err() {
            return;
        }
        for _ in 0..4 {
            let hashes: Vec<Vec<u8>> =
                s.db.conn()
                    .prepare("SELECT hash FROM token_removals LIMIT ?1")
                    .and_then(|mut st| {
                        st.query_map([i64::try_from(TOKEN_REMOVALS).unwrap_or(64)], |r| r.get(0))?
                            .collect()
                    })
                    .unwrap_or_default();
            if hashes.is_empty() {
                return;
            }
            let req = Request::UpdateTokens(veil_wire::UpdateTokens {
                mailbox_id: s.mailbox.to_vec(),
                add: vec![],
                remove: hashes.clone(),
            });
            if self.call(req).await.is_err() {
                return;
            }
            for h in &hashes {
                let _ =
                    s.db.conn()
                        .execute("DELETE FROM token_removals WHERE hash = ?1", [h]);
            }
        }
    }

    /// Expired invites: their prekeys are deleted and their tokens withdrawn from the relay.
    async fn cleanup_invites(&self) -> Result<()> {
        let s = self.s()?;
        let now = now_secs();
        let now_i = i64::try_from(now).unwrap_or(i64::MAX);
        let tokens: Vec<Vec<u8>> =
            s.db.conn()
                .prepare("SELECT token FROM invites WHERE expires <= ?1")?
                .query_map([now_i], |r| r.get(0))?
                .collect::<core::result::Result<_, _>>()?;
        if tokens.is_empty() {
            return Ok(());
        }
        self.atomically(async {
            for t in &tokens {
                Self::queue_token_removal(&s.db, t)?;
            }
            s.db.conn()
                .execute("DELETE FROM invites WHERE expires <= ?1", [now_i])?;
            s.account.sweep_expired_invites(now).await?;
            Ok(())
        })
        .await
    }

    async fn delete_contact(&mut self, contact: i64) -> Result<()> {
        let s = self.s()?;
        let (address, my_token): (String, Vec<u8>) =
            s.db.conn()
                .query_row(
                    "SELECT address, my_token FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        self.atomically(async {
            s.account.forget_contact(&addr).await?;
            Self::queue_token_removal(&s.db, &my_token)?;
            // Messages go with the contact (ON DELETE CASCADE), overwritten by secure_delete.
            s.db.conn()
                .execute("DELETE FROM contacts WHERE id = ?1", [contact])?;
            Ok(())
        })
        .await?;
        if let Some(s) = self.session.as_mut() {
            s.typing_sent.remove(&contact);
        }
        self.flush_token_removals().await;
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    async fn set_blocked(&mut self, contact: i64, blocked: bool) -> Result<()> {
        let s = self.s()?;
        let (address, was, my_token): (String, bool, Vec<u8>) =
            s.db.conn()
                .query_row(
                    "SELECT address, blocked, my_token FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        if was == blocked {
            return Ok(());
        }
        if blocked {
            // Their token is withdrawn: the relay refuses whatever they send from now on.
            self.atomically(async {
                s.db.conn()
                    .execute("UPDATE contacts SET blocked = 1 WHERE id = ?1", [contact])?;
                Self::queue_token_removal(&s.db, &my_token)?;
                // An unblock update still waiting to go out names the token withdrawn here.
                Self::drop_pending_mailbox_updates(&s.db, contact)?;
                Ok(())
            })
            .await?;
            self.flush_token_removals().await;
        } else {
            self.unblock(contact, &address).await?;
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    /// Gives an unblocked contact a fresh delivery token in an encrypted mailbox update. The
    /// update is stored and retried like a message until it gets through (review M1-3).
    async fn unblock(&mut self, contact: i64, address: &str) -> Result<()> {
        let token = self.take_token().await?;
        let s = self.s()?;
        let r = async {
            let addr = veil_core::identity::Address::parse(address).map_err(|_| ClientError::Storage)?;
            let content = Content {
                id: random_id(&mut rng()),
                sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
                body: Some(Body::MailboxUpdate(MailboxUpdate {
                    new_mailbox_id: s.mailbox.to_vec(),
                    new_delivery_token: token.to_vec(),
                    relay_url: None,
                })),
            };
            let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
            self.atomically(async {
                let old: Vec<u8> =
                    s.db.conn()
                        .query_row("SELECT my_token FROM contacts WHERE id = ?1", [contact], |r| {
                            r.get(0)
                        })?;
                // Withdrawn at block time already; queued again in case a re-pair added one.
                Self::queue_token_removal(&s.db, &old)?;
                s.db.conn().execute(
                    "UPDATE contacts SET blocked = 0, my_token = ?2 WHERE id = ?1",
                    params![contact, token.to_vec()],
                )?;
                // Only the newest update may reach them (review M1R2-1).
                Self::drop_pending_mailbox_updates(&s.db, contact)?;
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status, envelope)
                     VALUES (?1, 1, 'mailbox', '', ?2, 'sending', ?3)",
                    params![contact, now_ms(), envelope],
                )?;
                Ok(s.db.conn().last_insert_rowid())
            })
            .await
        }
        .await;
        match r {
            Ok(id) => {
                // Delivered now if possible; otherwise retried with the other pending messages.
                self.deliver(id).await;
                Ok(())
            }
            Err(e) => {
                let _ = Self::queue_token_removal(&s.db, &token);
                Err(e)
            }
        }
    }

    fn dismiss_key_warning(&self, contact: i64) -> Result<()> {
        let n = self
            .s()?
            .db
            .conn()
            .execute("UPDATE contacts SET key_warning = 0 WHERE id = ?1", [contact])?;
        if n == 0 {
            return Err(ClientError::UnknownContact);
        }
        self.emit(ChangeKind::Contacts, Some(contact));
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
