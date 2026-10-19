//! Relay storage (redb, pure Rust).
//!
//! What is stored is exactly what PROTOCOL §2, §4.2, §6.3 and §9 allow, and nothing else:
//! * mailboxes: random id → Ed25519 auth key, sequence counter, quotas, last-auth minute;
//! * delivery-token *hashes* per mailbox;
//! * envelopes: `(mailbox, seq)` → expiry, receipt minute, sealed bytes;
//! * invites: id → expiry, sealed package;
//! * blobs: id → chunks, plus hashed one-time upload tokens;
//! * an expiry index over all of the above, so expiry never scans live data.
//!
//! No IP address, no connection data, no sender, no User-Agent (INV-META-2). Every write is a
//! single redb transaction, so a failed operation changes nothing.
//!
//! **Memory.** redb's page cache is bounded explicitly ([`Store::open`]); the expiry sweep
//! reads only index keys that are due and works in short batches, each its own transaction.

use std::path::Path;

use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition, WriteTransaction};

type Bytes = &'static [u8];

const MAILBOXES: TableDefinition<Bytes, Bytes> = TableDefinition::new("mailboxes");
const TOKENS: TableDefinition<Bytes, Bytes> = TableDefinition::new("tokens");
const ENVELOPES: TableDefinition<Bytes, Bytes> = TableDefinition::new("envelopes");
const INVITES: TableDefinition<Bytes, Bytes> = TableDefinition::new("invites");
const UPLOAD_TOKENS: TableDefinition<Bytes, Bytes> = TableDefinition::new("upload_tokens");
const BLOBS: TableDefinition<Bytes, Bytes> = TableDefinition::new("blobs");
const BLOB_CHUNKS: TableDefinition<Bytes, Bytes> = TableDefinition::new("blob_chunks");
const STATS: TableDefinition<Bytes, u64> = TableDefinition::new("stats");
/// `kind (1) || due (u64 BE) || record id` → empty. Sorted by kind, then due time.
const EXPIRY: TableDefinition<Bytes, Bytes> = TableDefinition::new("expiry");

const STAT_MAILBOXES: &[u8] = b"mailboxes";
const STAT_INVITES: &[u8] = b"invites";
const STAT_BLOB_BYTES: &[u8] = b"blob_bytes";
const STAT_ENVELOPE_BYTES: &[u8] = b"envelope_bytes";

const X_ENVELOPE: u8 = b'e';
const X_INVITE: u8 = b'i';
const X_UPLOAD: u8 = b'u';
const X_BLOB: u8 = b'b';
const X_MAILBOX: u8 = b'm';

/// Expired records handled per sweep transaction, so the writer is never held for long.
const SWEEP_BATCH: usize = 256;

/// Default redb page cache: small enough for a Raspberry Pi container (`mem_limit: 512m`).
pub const DEFAULT_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Storage errors. Messages never include stored or request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Conflict,
    #[error("quota exceeded")]
    Quota,
    #[error("not authorized")]
    Unauthorized,
    #[error("corrupt record")]
    Corrupt,
    #[error("storage failure")]
    Io,
}

pub type Result<T> = core::result::Result<T, StoreError>;

fn io<E>(_: E) -> StoreError {
    StoreError::Io
}

/// Storage limits (from the relay config).
#[derive(Debug, Clone, Copy)]
pub struct Quotas {
    pub max_mailboxes: u64,
    pub max_envelopes_per_mailbox: u64,
    /// Bound on all queued envelopes together, so open mailbox creation cannot fill the disk.
    pub max_envelope_bytes_total: u64,
    pub max_tokens_per_mailbox: u32,
    pub max_invites: u64,
    pub max_blob_bytes_total: u64,
    pub envelope_ttl_secs: u64,
    pub invite_max_ttl_secs: u64,
    pub blob_ttl_secs: u64,
    pub upload_token_ttl_secs: u64,
    pub mailbox_idle_secs: u64,
}

// --- fixed-layout records -------------------------------------------------------------

fn take<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N]> {
    b.get(at..at.checked_add(N).ok_or(StoreError::Corrupt)?)
        .and_then(|s| s.try_into().ok())
        .ok_or(StoreError::Corrupt)
}

fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    take::<8>(b, at).map(u64::from_be_bytes)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    take::<4>(b, at).map(u32::from_be_bytes)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|p| p.len()).fold(0usize, usize::saturating_add);
    let mut v = Vec::with_capacity(len);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[derive(Debug, Clone, Copy)]
struct Mailbox {
    auth_pub: [u8; 32],
    last_seq: u64,
    count: u64,
    tokens: u32,
    last_auth_minute: u64,
}

impl Mailbox {
    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 32 + 8 + 8 + 4 + 8 {
            return Err(StoreError::Corrupt);
        }
        Ok(Self {
            auth_pub: take::<32>(b, 0)?,
            last_seq: u64_at(b, 32)?,
            count: u64_at(b, 40)?,
            tokens: u32_at(b, 48)?,
            last_auth_minute: u64_at(b, 52)?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        cat(&[
            &self.auth_pub,
            &self.last_seq.to_be_bytes(),
            &self.count.to_be_bytes(),
            &self.tokens.to_be_bytes(),
            &self.last_auth_minute.to_be_bytes(),
        ])
    }
}

/// An envelope as returned to the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub seq: u64,
    pub received_minute: u64,
    pub envelope: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct BlobMeta {
    expires: u64,
    total: u32,
    received: u32,
    complete: bool,
    bytes: u64,
}

impl BlobMeta {
    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 8 + 4 + 4 + 1 + 8 {
            return Err(StoreError::Corrupt);
        }
        Ok(Self {
            expires: u64_at(b, 0)?,
            total: u32_at(b, 8)?,
            received: u32_at(b, 12)?,
            complete: take::<1>(b, 16)? == [1],
            bytes: u64_at(b, 17)?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        cat(&[
            &self.expires.to_be_bytes(),
            &self.total.to_be_bytes(),
            &self.received.to_be_bytes(),
            &[u8::from(self.complete)],
            &self.bytes.to_be_bytes(),
        ])
    }
}

fn len_u64(b: &[u8]) -> u64 {
    u64::try_from(b.len()).unwrap_or(u64::MAX)
}

fn minute(now: u64) -> u64 {
    now.saturating_sub(now % 60)
}

fn env_key(mailbox: &[u8; 32], seq: u64) -> Vec<u8> {
    cat(&[mailbox, &seq.to_be_bytes()])
}

fn chunk_key(blob: &[u8; 32], idx: u32) -> Vec<u8> {
    cat(&[blob, &idx.to_be_bytes()])
}

/// Exclusive upper bound for "every key that starts with this 32-byte prefix". Keys in our
/// tables are `prefix || suffix` with suffixes of at most 32 bytes (token hashes; client
/// chosen), and `prefix || FF×33` sorts above all of them, whatever the suffix bytes are
/// (review P3-2: an `FF×16` bound let `FF…`-prefixed token hashes escape deletion).
fn prefix_end(prefix: &[u8; 32]) -> Vec<u8> {
    cat(&[prefix, &[0xFF; 33]])
}

fn idle_due(rec: &Mailbox, q: &Quotas) -> u64 {
    rec.last_auth_minute.saturating_add(q.mailbox_idle_secs)
}

fn xkey(kind: u8, due: u64, id: &[u8]) -> Vec<u8> {
    cat(&[&[kind], &due.to_be_bytes(), id])
}

type Table<'t> = redb::Table<'t, Bytes, Bytes>;

fn index_put(x: &mut Table<'_>, kind: u8, due: u64, id: &[u8]) -> Result<()> {
    x.insert(&xkey(kind, due, id)[..], &[][..]).map_err(io)?;
    Ok(())
}

fn index_del(x: &mut Table<'_>, kind: u8, due: u64, id: &[u8]) -> Result<()> {
    x.remove(&xkey(kind, due, id)[..]).map_err(io)?;
    Ok(())
}

fn sub_stat(stats: &mut redb::Table<'_, Bytes, u64>, key: &[u8], by: u64) -> Result<()> {
    let v = stats.get(key).map_err(io)?.map_or(0, |g| g.value());
    stats.insert(key, v.saturating_sub(by)).map_err(io)?;
    Ok(())
}

/// Deletes every envelope of `mailbox` in `range` (seq bounds) and their index entries.
/// Returns (records, stored bytes) removed.
fn remove_envelopes(txn: &WriteTransaction, range: core::ops::Range<&[u8]>) -> Result<(u64, u64)> {
    let mut env = txn.open_table(ENVELOPES).map_err(io)?;
    let mut gone: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut bytes = 0u64;
    let mut bad = false;
    env.retain_in(range, |k, v| {
        bytes = bytes.saturating_add(len_u64(v));
        match u64_at(v, 0) {
            Ok(due) => gone.push((k.to_vec(), due)),
            Err(_) => bad = true,
        }
        false
    })
    .map_err(io)?;
    if bad {
        return Err(StoreError::Corrupt);
    }
    let mut x = txn.open_table(EXPIRY).map_err(io)?;
    for (k, due) in &gone {
        index_del(&mut x, X_ENVELOPE, *due, k)?;
    }
    Ok((u64::try_from(gone.len()).unwrap_or(u64::MAX), bytes))
}

/// Removes a mailbox with its tokens, envelopes and index entries. False if absent.
fn remove_mailbox(txn: &WriteTransaction, id: &[u8; 32], q: &Quotas) -> Result<bool> {
    let rec = {
        let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
        let Some(g) = mb.remove(&id[..]).map_err(io)? else {
            return Ok(false);
        };
        Mailbox::decode(g.value())?
    };
    let end = prefix_end(id);
    {
        let mut tokens = txn.open_table(TOKENS).map_err(io)?;
        tokens.retain_in(&id[..]..&end[..], |_, _| false).map_err(io)?;
    }
    let (_, freed) = remove_envelopes(txn, &id[..]..&end[..])?;
    let mut x = txn.open_table(EXPIRY).map_err(io)?;
    index_del(&mut x, X_MAILBOX, idle_due(&rec, q), id)?;
    let mut stats = txn.open_table(STATS).map_err(io)?;
    sub_stat(&mut stats, STAT_MAILBOXES, 1)?;
    sub_stat(&mut stats, STAT_ENVELOPE_BYTES, freed)?;
    Ok(true)
}

// --- the store ------------------------------------------------------------------------

pub struct Store {
    db: Database,
    q: Quotas,
    /// Records the sweep looked at (test-only: proves it never scans live data).
    #[cfg(test)]
    examined: core::sync::atomic::AtomicU64,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store")
    }
}

macro_rules! stat {
    ($stats:expr, $key:expr) => {
        $stats.get($key).map_err(io)?.map_or(0, |g| g.value())
    };
}

impl Store {
    /// Opens (or creates) the database with the default page cache ([`DEFAULT_CACHE_BYTES`]).
    pub fn open(path: &Path, q: Quotas) -> Result<Self> {
        Self::open_with_cache(path, q, DEFAULT_CACHE_BYTES)
    }

    /// Opens with an explicit page-cache bound. redb's own default (1 GiB) would let the
    /// relay's memory grow with its data until a container memory limit kills it (P3-1).
    pub fn open_with_cache(path: &Path, q: Quotas, cache_bytes: usize) -> Result<Self> {
        let db = redb::Builder::new()
            .set_cache_size(cache_bytes)
            .create(path)
            .map_err(io)?;
        let s = Self {
            db,
            q,
            #[cfg(test)]
            examined: core::sync::atomic::AtomicU64::new(0),
        };
        // Create all tables up front so readers never see a missing table.
        let txn = s.db.begin_write().map_err(io)?;
        for t in [
            MAILBOXES,
            TOKENS,
            ENVELOPES,
            INVITES,
            UPLOAD_TOKENS,
            BLOBS,
            BLOB_CHUNKS,
            EXPIRY,
        ] {
            txn.open_table(t).map_err(io)?;
        }
        txn.open_table(STATS).map_err(io)?;
        txn.commit().map_err(io)?;
        Ok(s)
    }

    pub fn quotas(&self) -> &Quotas {
        &self.q
    }

    // ---- mailboxes ----

    pub fn mailbox_exists(&self, id: &[u8; 32]) -> Result<bool> {
        let txn = self.db.begin_read().map_err(io)?;
        let mb = txn.open_table(MAILBOXES).map_err(io)?;
        Ok(mb.get(&id[..]).map_err(io)?.is_some())
    }

    pub fn create_mailbox(&self, id: &[u8; 32], auth_pub: &[u8; 32], now: u64) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut stats = txn.open_table(STATS).map_err(io)?;
            let n = stat!(stats, STAT_MAILBOXES);
            if n >= self.q.max_mailboxes {
                return Err(StoreError::Quota);
            }
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            if mb.get(&id[..]).map_err(io)?.is_some() {
                return Err(StoreError::Conflict);
            }
            let rec = Mailbox {
                auth_pub: *auth_pub,
                last_seq: 0,
                count: 0,
                tokens: 0,
                last_auth_minute: minute(now),
            };
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_put(&mut x, X_MAILBOX, idle_due(&rec, &self.q), id)?;
            stats.insert(STAT_MAILBOXES, n.saturating_add(1)).map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    /// The mailbox's auth key, if the mailbox exists.
    pub fn mailbox_auth_key(&self, id: &[u8; 32]) -> Result<[u8; 32]> {
        let txn = self.db.begin_read().map_err(io)?;
        let mb = txn.open_table(MAILBOXES).map_err(io)?;
        let rec = mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?;
        Ok(Mailbox::decode(rec.value())?.auth_pub)
    }

    /// Records a successful authentication (keeps an active mailbox from idle expiry).
    pub fn touch_mailbox(&self, id: &[u8; 32], now: u64) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            let mut rec = {
                let g = mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?;
                Mailbox::decode(g.value())?
            };
            if rec.last_auth_minute == minute(now) {
                return Ok(()); // nothing changes; the write transaction is dropped
            }
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_del(&mut x, X_MAILBOX, idle_due(&rec, &self.q), id)?;
            rec.last_auth_minute = minute(now);
            index_put(&mut x, X_MAILBOX, idle_due(&rec, &self.q), id)?;
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    pub fn delete_mailbox(&self, id: &[u8; 32]) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        if !remove_mailbox(&txn, id, &self.q)? {
            return Err(StoreError::NotFound);
        }
        txn.commit().map_err(io)
    }

    /// Adds and removes delivery-token hashes for a mailbox.
    pub fn update_tokens(&self, id: &[u8; 32], add: &[[u8; 32]], remove: &[[u8; 32]]) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            let mut rec = {
                let g = mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?;
                Mailbox::decode(g.value())?
            };
            let mut tokens = txn.open_table(TOKENS).map_err(io)?;
            for h in remove {
                if tokens.remove(&cat(&[id, h])[..]).map_err(io)?.is_some() {
                    rec.tokens = rec.tokens.saturating_sub(1);
                }
            }
            for h in add {
                if tokens.insert(&cat(&[id, h])[..], &[][..]).map_err(io)?.is_none() {
                    rec.tokens = rec.tokens.saturating_add(1);
                }
            }
            if rec.tokens > self.q.max_tokens_per_mailbox {
                return Err(StoreError::Quota);
            }
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    /// Stores an envelope if `token_hash` is registered for the mailbox. Returns the new
    /// sequence number. Unknown mailbox and unknown token give the *same* error, so a
    /// depositor cannot probe which mailboxes exist.
    pub fn deposit(&self, id: &[u8; 32], token_hash: &[u8; 32], envelope: &[u8], now: u64) -> Result<u64> {
        let txn = self.db.begin_write().map_err(io)?;
        let seq;
        {
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            let Some(g) = mb.get(&id[..]).map_err(io)? else {
                return Err(StoreError::Unauthorized);
            };
            let mut rec = Mailbox::decode(g.value())?;
            drop(g);
            let tokens = txn.open_table(TOKENS).map_err(io)?;
            if tokens.get(&cat(&[id, token_hash])[..]).map_err(io)?.is_none() {
                return Err(StoreError::Unauthorized);
            }
            if rec.count >= self.q.max_envelopes_per_mailbox {
                return Err(StoreError::Quota);
            }
            let expires = now.saturating_add(self.q.envelope_ttl_secs);
            let value = cat(&[&expires.to_be_bytes(), &minute(now).to_be_bytes(), envelope]);
            let mut stats = txn.open_table(STATS).map_err(io)?;
            let used = stat!(stats, STAT_ENVELOPE_BYTES)
                .checked_add(len_u64(&value))
                .ok_or(StoreError::Quota)?;
            if used > self.q.max_envelope_bytes_total {
                return Err(StoreError::Quota);
            }
            seq = rec.last_seq.checked_add(1).ok_or(StoreError::Quota)?;
            rec.last_seq = seq;
            rec.count = rec.count.saturating_add(1);
            let key = env_key(id, seq);
            let mut env = txn.open_table(ENVELOPES).map_err(io)?;
            env.insert(&key[..], &value[..]).map_err(io)?;
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_put(&mut x, X_ENVELOPE, expires, &key)?;
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
            stats.insert(STAT_ENVELOPE_BYTES, used).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        Ok(seq)
    }

    /// Envelopes with `seq > after`, oldest first, at most `limit`; plus the mailbox's last seq.
    pub fn fetch(&self, id: &[u8; 32], after: u64, limit: usize, now: u64) -> Result<(Vec<Stored>, u64)> {
        let txn = self.db.begin_read().map_err(io)?;
        let mb = txn.open_table(MAILBOXES).map_err(io)?;
        let rec = Mailbox::decode(mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?.value())?;
        let env = txn.open_table(ENVELOPES).map_err(io)?;
        let start = env_key(id, after.saturating_add(1));
        let end = prefix_end(id);
        let mut out = Vec::new();
        for item in env.range(&start[..]..&end[..]).map_err(io)? {
            if out.len() >= limit {
                break;
            }
            let (k, v) = item.map_err(io)?;
            let (k, v) = (k.value(), v.value());
            if u64_at(v, 0)? <= now {
                continue; // expired; the sweeper deletes it
            }
            out.push(Stored {
                seq: u64_at(k, 32)?,
                received_minute: u64_at(v, 8)?,
                envelope: v.get(16..).ok_or(StoreError::Corrupt)?.to_vec(),
            });
        }
        Ok((out, rec.last_seq))
    }

    /// Deletes envelopes with `seq <= up_to`. Returns how many were removed.
    pub fn ack(&self, id: &[u8; 32], up_to: u64) -> Result<u64> {
        let txn = self.db.begin_write().map_err(io)?;
        let removed;
        {
            let mut rec = {
                let mb = txn.open_table(MAILBOXES).map_err(io)?;
                let g = mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?;
                Mailbox::decode(g.value())?
            };
            let start = env_key(id, 0);
            let end = env_key(id, up_to.saturating_add(1).max(1));
            let (n, freed) = if up_to == u64::MAX {
                remove_envelopes(&txn, &start[..]..&prefix_end(id)[..])?
            } else {
                remove_envelopes(&txn, &start[..]..&end[..])?
            };
            removed = n;
            rec.count = rec.count.saturating_sub(n);
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
            let mut stats = txn.open_table(STATS).map_err(io)?;
            sub_stat(&mut stats, STAT_ENVELOPE_BYTES, freed)?;
        }
        txn.commit().map_err(io)?;
        Ok(removed)
    }

    // ---- invites ----

    pub fn put_invite(&self, id: &[u8; 16], sealed: &[u8], expires_at: u64, now: u64) -> Result<()> {
        let expires = expires_at.min(now.saturating_add(self.q.invite_max_ttl_secs));
        if expires <= now {
            return Err(StoreError::NotFound);
        }
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut stats = txn.open_table(STATS).map_err(io)?;
            let n = stat!(stats, STAT_INVITES);
            if n >= self.q.max_invites {
                return Err(StoreError::Quota);
            }
            let mut inv = txn.open_table(INVITES).map_err(io)?;
            if inv.get(&id[..]).map_err(io)?.is_some() {
                return Err(StoreError::Conflict);
            }
            inv.insert(&id[..], &cat(&[&expires.to_be_bytes(), sealed])[..])
                .map_err(io)?;
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_put(&mut x, X_INVITE, expires, id)?;
            stats.insert(STAT_INVITES, n.saturating_add(1)).map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    /// Returns the sealed package and deletes it, atomically: an invite is served once
    /// (INV-PAIR-2). Expired invites are deleted and reported as not found.
    pub fn take_invite(&self, id: &[u8; 16], now: u64) -> Result<Vec<u8>> {
        let txn = self.db.begin_write().map_err(io)?;
        let sealed;
        {
            let mut inv = txn.open_table(INVITES).map_err(io)?;
            let value = inv
                .remove(&id[..])
                .map_err(io)?
                .ok_or(StoreError::NotFound)?
                .value()
                .to_vec();
            let mut stats = txn.open_table(STATS).map_err(io)?;
            sub_stat(&mut stats, STAT_INVITES, 1)?;
            let expires = u64_at(&value, 0)?;
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_del(&mut x, X_INVITE, expires, id)?;
            if expires <= now {
                sealed = None;
            } else {
                sealed = Some(value.get(8..).ok_or(StoreError::Corrupt)?.to_vec());
            }
        }
        txn.commit().map_err(io)?;
        sealed.ok_or(StoreError::NotFound)
    }

    // ---- blobs ----

    /// Stores the hash of a new one-time upload token.
    pub fn add_upload_token(&self, token_hash: &[u8; 32], now: u64) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut t = txn.open_table(UPLOAD_TOKENS).map_err(io)?;
            let expires = now.saturating_add(self.q.upload_token_ttl_secs);
            if let Some(old) = t
                .insert(
                    &token_hash[..],
                    &cat(&[&expires.to_be_bytes(), &[0u8], &[0u8; 32]])[..],
                )
                .map_err(io)?
            {
                // A 256-bit random collision; keep the index consistent anyway.
                let old_due = u64_at(old.value(), 0)?;
                drop(old);
                let mut x = txn.open_table(EXPIRY).map_err(io)?;
                index_del(&mut x, X_UPLOAD, old_due, token_hash)?;
            }
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            index_put(&mut x, X_UPLOAD, expires, token_hash)?;
        }
        txn.commit().map_err(io)
    }

    /// Stores one chunk. The token binds to the first blob it uploads; the blob becomes
    /// downloadable when every chunk is present, and the token is then consumed. Re-sending
    /// a chunk (resume) is allowed until completion. An incomplete blob expires with its
    /// upload token; a complete one lives for `blob_ttl_secs` from completion (P3-10).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn put_chunk(
        &self,
        token_hash: &[u8; 32],
        blob: &[u8; 32],
        idx: u32,
        total: u32,
        data: &[u8],
        full_chunk: usize,
        now: u64,
    ) -> Result<bool> {
        // Every chunk but the last is exactly full-size, so sizes cannot drift on resume.
        let last = idx.checked_add(1) == Some(total);
        if !last && data.len() != full_chunk {
            return Err(StoreError::Unauthorized);
        }
        let len = u64::try_from(data.len()).map_err(|_| StoreError::Quota)?;
        let txn = self.db.begin_write().map_err(io)?;
        let complete;
        {
            let mut toks = txn.open_table(UPLOAD_TOKENS).map_err(io)?;
            let tok = toks
                .get(&token_hash[..])
                .map_err(io)?
                .ok_or(StoreError::Unauthorized)?
                .value()
                .to_vec();
            let tok_expires = u64_at(&tok, 0)?;
            if tok_expires <= now {
                return Err(StoreError::Unauthorized);
            }
            let bound = take::<1>(&tok, 8)? == [1];
            let bound_blob = take::<32>(&tok, 9)?;
            if bound && bound_blob != *blob {
                return Err(StoreError::Unauthorized);
            }
            let mut blobs = txn.open_table(BLOBS).map_err(io)?;
            let existing = blobs
                .get(&blob[..])
                .map_err(io)?
                .map(|g| BlobMeta::decode(g.value()))
                .transpose()?;
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            let mut meta = match existing {
                Some(_) if !bound => return Err(StoreError::Conflict), // someone else's blob id
                Some(m) => m,
                None if bound => return Err(StoreError::Corrupt),
                None => {
                    let m = BlobMeta {
                        expires: tok_expires,
                        total,
                        received: 0,
                        complete: false,
                        bytes: 0,
                    };
                    index_put(&mut x, X_BLOB, m.expires, blob)?;
                    m
                }
            };
            if meta.complete || meta.total != total {
                return Err(StoreError::Conflict);
            }
            let mut stats = txn.open_table(STATS).map_err(io)?;
            let used = stat!(stats, STAT_BLOB_BYTES);
            let mut chunks = txn.open_table(BLOB_CHUNKS).map_err(io)?;
            let ck = chunk_key(blob, idx);
            let previous = chunks.get(&ck[..]).map_err(io)?.map(|g| g.value().len());
            let prev_len = previous
                .map_or(Ok(0), u64::try_from)
                .map_err(|_| StoreError::Corrupt)?;
            let new_used = used.saturating_sub(prev_len).saturating_add(len);
            if new_used > self.q.max_blob_bytes_total {
                return Err(StoreError::Quota);
            }
            chunks.insert(&ck[..], data).map_err(io)?;
            if previous.is_none() {
                meta.received = meta.received.saturating_add(1);
            }
            meta.bytes = meta.bytes.saturating_sub(prev_len).saturating_add(len);
            meta.complete = meta.received == meta.total;
            complete = meta.complete;
            if complete {
                index_del(&mut x, X_BLOB, meta.expires, blob)?;
                meta.expires = now.saturating_add(self.q.blob_ttl_secs);
                index_put(&mut x, X_BLOB, meta.expires, blob)?;
            }
            blobs.insert(&blob[..], &meta.encode()[..]).map_err(io)?;
            stats.insert(STAT_BLOB_BYTES, new_used).map_err(io)?;
            if complete {
                toks.remove(&token_hash[..]).map_err(io)?;
                index_del(&mut x, X_UPLOAD, tok_expires, token_hash)?;
            } else if !bound {
                let rebound = cat(&[&tok_expires.to_be_bytes(), &[1u8], blob]);
                toks.insert(&token_hash[..], &rebound[..]).map_err(io)?;
            }
        }
        txn.commit().map_err(io)?;
        Ok(complete)
    }

    /// One chunk of a complete, unexpired blob, with the total chunk count.
    pub fn get_chunk(&self, blob: &[u8; 32], idx: u32, now: u64) -> Result<(u32, Vec<u8>)> {
        let txn = self.db.begin_read().map_err(io)?;
        let blobs = txn.open_table(BLOBS).map_err(io)?;
        let meta = BlobMeta::decode(
            blobs
                .get(&blob[..])
                .map_err(io)?
                .ok_or(StoreError::NotFound)?
                .value(),
        )?;
        if !meta.complete || meta.expires <= now || idx >= meta.total {
            return Err(StoreError::NotFound);
        }
        let chunks = txn.open_table(BLOB_CHUNKS).map_err(io)?;
        let data = chunks
            .get(&chunk_key(blob, idx)[..])
            .map_err(io)?
            .ok_or(StoreError::Corrupt)?
            .value()
            .to_vec();
        Ok((meta.total, data))
    }

    // ---- expiry ----

    /// Deletes expired envelopes, invites, upload tokens and blobs, and idle mailboxes.
    /// Returns the number of envelopes, invites, blobs and mailboxes removed.
    ///
    /// Only index entries that are due are read, in batches of [`SWEEP_BATCH`], each in its
    /// own short write transaction: the cost depends on what expires, not on what is stored
    /// (P3-1).
    pub fn sweep(&self, now: u64) -> Result<u64> {
        let mut removed = 0u64;
        for kind in [X_ENVELOPE, X_INVITE, X_UPLOAD, X_BLOB, X_MAILBOX] {
            loop {
                let (n, more) = self.sweep_batch(kind, now)?;
                removed = removed.saturating_add(n);
                if !more {
                    break;
                }
            }
        }
        Ok(removed)
    }

    /// Index keys of `kind` due at or before `now`, at most `max` of them.
    fn due_keys(txn: &WriteTransaction, kind: u8, now: u64, max: usize) -> Result<Vec<Vec<u8>>> {
        let x = txn.open_table(EXPIRY).map_err(io)?;
        let start = [kind];
        let end = xkey(kind, now.saturating_add(1), &[]);
        let mut keys = Vec::new();
        if now == u64::MAX {
            for item in x.range(&start[..]..).map_err(io)? {
                let (k, _) = item.map_err(io)?;
                if keys.len() >= max || k.value().first() != Some(&kind) {
                    break;
                }
                keys.push(k.value().to_vec());
            }
        } else {
            for item in x.range(&start[..]..&end[..]).map_err(io)? {
                if keys.len() >= max {
                    break;
                }
                keys.push(item.map_err(io)?.0.value().to_vec());
            }
        }
        Ok(keys)
    }

    fn sweep_batch(&self, kind: u8, now: u64) -> Result<(u64, bool)> {
        let txn = self.db.begin_write().map_err(io)?;
        let keys = Self::due_keys(&txn, kind, now, SWEEP_BATCH)?;
        let more = keys.len() >= SWEEP_BATCH;
        let mut removed = 0u64;
        for k in &keys {
            let due = u64_at(k, 1)?;
            let id = k.get(9..).ok_or(StoreError::Corrupt)?;
            if self.expire_one(&txn, kind, due, id)? {
                removed = removed.saturating_add(1);
            }
            // Stale entries (record already gone or re-dated) are dropped too.
            let mut x = txn.open_table(EXPIRY).map_err(io)?;
            x.remove(&k[..]).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        Ok((removed, more))
    }

    /// Removes the record an index entry points to, if it still carries that due time.
    /// Returns true when a counted record was removed.
    fn expire_one(&self, txn: &WriteTransaction, kind: u8, due: u64, id: &[u8]) -> Result<bool> {
        #[cfg(test)]
        self.examined.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match kind {
            X_ENVELOPE => {
                let mailbox = take::<32>(id, 0)?;
                let freed = {
                    let mut env = txn.open_table(ENVELOPES).map_err(io)?;
                    let live = env
                        .get(id)
                        .map_err(io)?
                        .map(|g| (u64_at(g.value(), 0), len_u64(g.value())));
                    match live {
                        Some((Ok(d), len)) if d == due => {
                            env.remove(id).map_err(io)?;
                            len
                        }
                        Some((Err(e), _)) => return Err(e),
                        _ => return Ok(false),
                    }
                };
                let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
                let rec = mb
                    .get(&mailbox[..])
                    .map_err(io)?
                    .map(|g| Mailbox::decode(g.value()))
                    .transpose()?;
                if let Some(mut rec) = rec {
                    rec.count = rec.count.saturating_sub(1);
                    mb.insert(&mailbox[..], &rec.encode()[..]).map_err(io)?;
                }
                let mut stats = txn.open_table(STATS).map_err(io)?;
                sub_stat(&mut stats, STAT_ENVELOPE_BYTES, freed)?;
                Ok(true)
            }
            X_INVITE => {
                let mut inv = txn.open_table(INVITES).map_err(io)?;
                let live = inv.get(id).map_err(io)?.map(|g| u64_at(g.value(), 0));
                match live {
                    Some(Ok(d)) if d == due => {
                        inv.remove(id).map_err(io)?;
                        let mut stats = txn.open_table(STATS).map_err(io)?;
                        sub_stat(&mut stats, STAT_INVITES, 1)?;
                        Ok(true)
                    }
                    Some(Err(e)) => Err(e),
                    _ => Ok(false),
                }
            }
            X_UPLOAD => {
                let mut toks = txn.open_table(UPLOAD_TOKENS).map_err(io)?;
                let live = toks.get(id).map_err(io)?.map(|g| u64_at(g.value(), 0));
                if let Some(Ok(d)) = live
                    && d == due
                {
                    toks.remove(id).map_err(io)?;
                }
                Ok(false)
            }
            X_BLOB => {
                let blob = take::<32>(id, 0)?;
                let meta = {
                    let mut blobs = txn.open_table(BLOBS).map_err(io)?;
                    let meta = blobs
                        .get(&blob[..])
                        .map_err(io)?
                        .map(|g| BlobMeta::decode(g.value()))
                        .transpose()?;
                    match meta {
                        Some(m) if m.expires == due => {
                            blobs.remove(&blob[..]).map_err(io)?;
                            m
                        }
                        _ => return Ok(false),
                    }
                };
                let end = prefix_end(&blob);
                let mut chunks = txn.open_table(BLOB_CHUNKS).map_err(io)?;
                chunks.retain_in(&blob[..]..&end[..], |_, _| false).map_err(io)?;
                let mut stats = txn.open_table(STATS).map_err(io)?;
                sub_stat(&mut stats, STAT_BLOB_BYTES, meta.bytes)?;
                Ok(true)
            }
            X_MAILBOX => {
                let m = take::<32>(id, 0)?;
                let live = {
                    let mb = txn.open_table(MAILBOXES).map_err(io)?;
                    mb.get(&m[..])
                        .map_err(io)?
                        .map(|g| Mailbox::decode(g.value()))
                        .transpose()?
                };
                match live {
                    Some(rec) if idle_due(&rec, &self.q) == due => remove_mailbox(txn, &m, &self.q),
                    _ => Ok(false),
                }
            }
            _ => Err(StoreError::Corrupt),
        }
    }

    /// Rows in each table, for tests that check nothing is left behind.
    #[cfg(test)]
    fn row_counts(&self) -> Vec<(&'static str, u64)> {
        let txn = self.db.begin_read().unwrap();
        let mut out = Vec::new();
        for (name, t) in [
            ("mailboxes", MAILBOXES),
            ("tokens", TOKENS),
            ("envelopes", ENVELOPES),
            ("invites", INVITES),
            ("upload_tokens", UPLOAD_TOKENS),
            ("blobs", BLOBS),
            ("blob_chunks", BLOB_CHUNKS),
            ("expiry", EXPIRY),
        ] {
            let table = txn.open_table(t).unwrap();
            out.push((name, u64::try_from(table.iter().unwrap().count()).unwrap()));
        }
        out
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    pub(crate) fn quotas() -> Quotas {
        Quotas {
            max_mailboxes: 3,
            max_envelopes_per_mailbox: 3,
            max_envelope_bytes_total: 10_000,
            max_tokens_per_mailbox: 4,
            max_invites: 2,
            max_blob_bytes_total: 300,
            envelope_ttl_secs: 100,
            invite_max_ttl_secs: 50,
            blob_ttl_secs: 100,
            upload_token_ttl_secs: 10,
            mailbox_idle_secs: 1000,
        }
    }

    fn store() -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("veil-store-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        (Store::open(&dir.join("db"), quotas()).unwrap(), dir)
    }

    #[test]
    fn mailbox_tokens_deposit_fetch_ack() {
        let (s, dir) = store();
        let (m, t) = ([1u8; 32], [2u8; 32]);
        s.create_mailbox(&m, &[9; 32], 1000).unwrap();
        assert_eq!(s.create_mailbox(&m, &[9; 32], 1000), Err(StoreError::Conflict));
        assert_eq!(s.mailbox_auth_key(&m).unwrap(), [9; 32]);
        // Unknown token and unknown mailbox are indistinguishable.
        assert_eq!(s.deposit(&m, &t, &[0; 1024], 1000), Err(StoreError::Unauthorized));
        assert_eq!(
            s.deposit(&[7; 32], &t, &[0; 1024], 1000),
            Err(StoreError::Unauthorized)
        );
        s.update_tokens(&m, &[t], &[]).unwrap();
        for i in 1..=3u8 {
            assert_eq!(s.deposit(&m, &t, &[i; 1024], 1000).unwrap(), u64::from(i));
        }
        assert_eq!(s.deposit(&m, &t, &[4; 1024], 1000), Err(StoreError::Quota));
        let (items, last) = s.fetch(&m, 1, 10, 1000).unwrap();
        assert_eq!(last, 3);
        assert_eq!(items.iter().map(|i| i.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(items[0].received_minute, 960);
        assert_eq!(s.ack(&m, 2).unwrap(), 2);
        assert_eq!(s.fetch(&m, 0, 10, 1000).unwrap().0.len(), 1);
        assert_eq!(
            s.deposit(&m, &t, &[5; 1024], 1000).unwrap(),
            4,
            "seq keeps increasing"
        );
        // Removing the token blocks the depositor.
        s.update_tokens(&m, &[], &[t]).unwrap();
        assert_eq!(s.deposit(&m, &t, &[0; 1024], 1000), Err(StoreError::Unauthorized));
        assert_eq!(
            s.update_tokens(&m, &[[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]], &[]),
            Err(StoreError::Quota)
        );
        s.delete_mailbox(&m).unwrap();
        assert_eq!(s.fetch(&m, 0, 10, 1000), Err(StoreError::NotFound));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The global envelope byte quota holds, and every removal path (ack, delete, expiry,
    /// idle-mailbox expiry) gives the bytes back.
    #[test]
    fn envelope_bytes_are_capped_and_released() {
        let (s, dir) = store();
        let (a, b, t) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        for m in [&a, &b] {
            s.create_mailbox(m, &[9; 32], 1000).unwrap();
            s.update_tokens(m, &[t], &[]).unwrap();
        }
        // Each stored record is 16 + 4096 bytes: two fit under 10 000, a third does not.
        let env = [0u8; 4096];
        s.deposit(&a, &t, &env, 1000).unwrap();
        s.deposit(&b, &t, &env, 1000).unwrap();
        assert_eq!(s.deposit(&a, &t, &env, 1000), Err(StoreError::Quota));
        // ack frees.
        s.ack(&a, 1).unwrap();
        s.deposit(&a, &t, &env, 1000).unwrap();
        assert_eq!(s.deposit(&a, &t, &env, 1000), Err(StoreError::Quota));
        // delete frees.
        s.delete_mailbox(&b).unwrap();
        s.deposit(&a, &t, &env, 1000).unwrap();
        assert_eq!(s.deposit(&a, &t, &env, 1000), Err(StoreError::Quota));
        // expiry frees (ttl 100).
        s.sweep(1100).unwrap();
        s.deposit(&a, &t, &env, 1100).unwrap();
        s.deposit(&a, &t, &env, 1100).unwrap();
        assert_eq!(s.deposit(&a, &t, &env, 1100), Err(StoreError::Quota));
        s.sweep(1200).unwrap();
        // Idle-mailbox expiry frees unexpired envelopes too: at 2050 the 1990 deposits are still
        // live (ttl 100) but the mailbox has been idle for over 1000 s since its auth at 1000.
        s.deposit(&a, &t, &env, 1990).unwrap();
        s.deposit(&a, &t, &env, 1990).unwrap();
        assert_eq!(s.deposit(&a, &t, &env, 1990), Err(StoreError::Quota));
        s.sweep(2050).unwrap();
        assert_eq!(s.mailbox_auth_key(&a), Err(StoreError::NotFound));
        s.create_mailbox(&b, &[9; 32], 2050).unwrap();
        s.update_tokens(&b, &[t], &[]).unwrap();
        s.deposit(&b, &t, &env, 2050).unwrap();
        s.deposit(&b, &t, &env, 2050).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn rows(s: &Store) -> Vec<(&'static str, u64)> {
        s.row_counts().into_iter().filter(|(_, n)| *n > 0).collect()
    }

    /// P3-2: token hashes are client-chosen, so ones starting with `FF…` must not escape the
    /// prefix range on delete or on idle expiry.
    #[test]
    fn ff_prefixed_tokens_are_deleted_with_their_mailbox() {
        let (s, dir) = store();
        let m = [0x42u8; 32];
        let mut half = [0u8; 32];
        half[..16].copy_from_slice(&[0xFF; 16]);
        let hostile = [[0xFF; 32], half];
        for path in ["delete", "idle"] {
            s.create_mailbox(&m, &[9; 32], 1000).unwrap();
            s.update_tokens(&m, &hostile, &[]).unwrap();
            if path == "delete" {
                s.delete_mailbox(&m).unwrap();
            } else {
                s.sweep(1000 + 2000).unwrap();
            }
            assert_eq!(rows(&s), vec![("expiry", 0); 0], "{path}: rows left behind");
            s.create_mailbox(&m, &[9; 32], 1000).unwrap();
            for h in &hostile {
                assert_eq!(
                    s.deposit(&m, h, &[0; 1024], 1000),
                    Err(StoreError::Unauthorized),
                    "{path}: old token still valid"
                );
            }
            s.delete_mailbox(&m).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// P3-1: the sweep reads only what is due, in batches, never the live data.
    #[test]
    fn sweep_touches_only_due_records() {
        let (s, dir) = store();
        let q = Quotas {
            max_envelopes_per_mailbox: 1000,
            max_envelope_bytes_total: u64::MAX,
            ..quotas()
        };
        let path = dir.join("big");
        let s2 = Store::open(&path, q).unwrap();
        drop(s);
        let (m, t) = ([1u8; 32], [2u8; 32]);
        s2.create_mailbox(&m, &[9; 32], 1000).unwrap();
        s2.update_tokens(&m, &[t], &[]).unwrap();
        for _ in 0..300 {
            s2.deposit(&m, &t, &[0; 1024], 1000).unwrap(); // due at 1100
        }
        let examined = || s2.examined.load(core::sync::atomic::Ordering::Relaxed);
        assert_eq!(s2.sweep(1099).unwrap(), 0);
        assert_eq!(examined(), 0, "nothing due, nothing read");
        // 300 due: more than one batch (256), all removed.
        assert_eq!(s2.sweep(1100).unwrap(), 300);
        assert_eq!(examined(), 300);
        assert!(s2.fetch(&m, 0, 32, 1100).unwrap().0.is_empty());
        // The count and byte totals followed: the mailbox accepts a full load again.
        for _ in 0..1000 {
            s2.deposit(&m, &t, &[0; 1024], 1100).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Every record type, after expiry and deletion, leaves no row behind, index included.
    #[test]
    fn nothing_is_left_behind() {
        let (s, dir) = store();
        let (m, t) = ([1u8; 32], [2u8; 32]);
        s.create_mailbox(&m, &[9; 32], 1000).unwrap();
        s.update_tokens(&m, &[t], &[]).unwrap();
        s.deposit(&m, &t, &[0; 1024], 1000).unwrap();
        s.deposit(&m, &t, &[0; 1024], 1000).unwrap();
        s.ack(&m, 1).unwrap();
        s.touch_mailbox(&m, 1500).unwrap();
        s.put_invite(&[1; 16], &[7; 64], 1040, 1000).unwrap();
        s.put_invite(&[2; 16], &[7; 64], 1040, 1000).unwrap();
        s.take_invite(&[2; 16], 1000).unwrap();
        s.add_upload_token(&[5; 32], 1000).unwrap();
        s.put_chunk(&[5; 32], &[6; 32], 0, 1, &[1; 10], 100, 1000)
            .unwrap();
        s.add_upload_token(&[7; 32], 1000).unwrap(); // never used
        s.sweep(10_000).unwrap();
        assert_eq!(rows(&s), vec![], "everything expired, including the mailbox");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// P3-10: an abandoned upload frees its quota when its token expires, not after the
    /// blob TTL; a completed blob lives for the blob TTL from completion.
    #[test]
    fn abandoned_uploads_expire_with_their_token() {
        let (s, dir) = store();
        s.add_upload_token(&[1; 32], 1000).unwrap(); // token ttl 10
        s.put_chunk(&[1; 32], &[2; 32], 0, 2, &[0; 200], 200, 1000)
            .unwrap();
        s.add_upload_token(&[3; 32], 1000).unwrap();
        assert_eq!(
            s.put_chunk(&[3; 32], &[4; 32], 0, 1, &[0; 200], 200, 1000),
            Err(StoreError::Quota),
            "quota 300, 200 held"
        );
        assert_eq!(s.sweep(1010).unwrap(), 1, "the abandoned blob");
        s.add_upload_token(&[3; 32], 1010).unwrap();
        assert!(
            s.put_chunk(&[3; 32], &[4; 32], 0, 1, &[0; 200], 200, 1015)
                .unwrap()
        );
        assert_eq!(s.sweep(1100).unwrap(), 0, "complete: lives 100 s from completion");
        assert_eq!(s.get_chunk(&[4; 32], 0, 1100).unwrap().0, 1);
        assert_eq!(s.sweep(1115).unwrap(), 1);
        assert_eq!(rows(&s), vec![]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invites_are_single_use_and_capped() {
        let (s, dir) = store();
        s.put_invite(&[1; 16], &[7; 4136], 2000, 1000).unwrap();
        assert_eq!(
            s.put_invite(&[1; 16], &[7; 4136], 2000, 1000),
            Err(StoreError::Conflict)
        );
        assert_eq!(s.take_invite(&[1; 16], 1000).unwrap(), vec![7; 4136]);
        assert_eq!(
            s.take_invite(&[1; 16], 1000),
            Err(StoreError::NotFound),
            "INV-PAIR-2"
        );
        // TTL is capped at invite_max_ttl_secs (50 s), whatever the client asks for.
        s.put_invite(&[2; 16], &[7; 4136], u64::MAX, 1000).unwrap();
        assert_eq!(s.take_invite(&[2; 16], 1051), Err(StoreError::NotFound));
        s.put_invite(&[3; 16], &[7; 4136], 2000, 1000).unwrap();
        s.put_invite(&[4; 16], &[7; 4136], 2000, 1000).unwrap();
        assert_eq!(
            s.put_invite(&[5; 16], &[7; 4136], 2000, 1000),
            Err(StoreError::Quota)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn blobs_bind_tokens_and_complete() {
        let (s, dir) = store();
        let (tok, blob) = ([1u8; 32], [2u8; 32]);
        s.add_upload_token(&tok, 1000).unwrap();
        // Non-last chunks must be full-size (here: 100).
        assert_eq!(
            s.put_chunk(&tok, &blob, 0, 2, &[1; 50], 100, 1000),
            Err(StoreError::Unauthorized)
        );
        assert!(!s.put_chunk(&tok, &blob, 0, 2, &[1; 100], 100, 1000).unwrap());
        assert_eq!(
            s.get_chunk(&blob, 0, 1000),
            Err(StoreError::NotFound),
            "incomplete"
        );
        // The token is bound to this blob now.
        assert_eq!(
            s.put_chunk(&tok, &[3; 32], 0, 1, &[1; 10], 100, 1000),
            Err(StoreError::Unauthorized)
        );
        // Resume: re-send chunk 0, then the last chunk.
        assert!(!s.put_chunk(&tok, &blob, 0, 2, &[1; 100], 100, 1000).unwrap());
        assert!(s.put_chunk(&tok, &blob, 1, 2, &[2; 30], 100, 1000).unwrap());
        assert_eq!(s.get_chunk(&blob, 1, 1000).unwrap(), (2, vec![2; 30]));
        // The token is consumed on completion.
        assert_eq!(
            s.put_chunk(&tok, &blob, 1, 2, &[2; 30], 100, 1000),
            Err(StoreError::Unauthorized)
        );
        // Another token cannot write into an existing blob id.
        s.add_upload_token(&[9; 32], 1000).unwrap();
        assert_eq!(
            s.put_chunk(&[9; 32], &blob, 0, 2, &[1; 100], 100, 1000),
            Err(StoreError::Conflict)
        );
        // Global byte quota (300; 130 used).
        s.add_upload_token(&[8; 32], 1000).unwrap();
        assert_eq!(
            s.put_chunk(&[8; 32], &[4; 32], 0, 3, &[0; 200], 200, 1000),
            Err(StoreError::Quota)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sweep_expires_everything_on_time() {
        let (s, dir) = store();
        let (m, t) = ([1u8; 32], [2u8; 32]);
        s.create_mailbox(&m, &[9; 32], 1000).unwrap();
        s.update_tokens(&m, &[t], &[]).unwrap();
        s.deposit(&m, &t, &[0; 1024], 1000).unwrap();
        s.put_invite(&[1; 16], &[7; 4136], 1040, 1000).unwrap();
        s.add_upload_token(&[5; 32], 1000).unwrap();
        s.put_chunk(&[5; 32], &[6; 32], 0, 1, &[1; 10], 100, 1000)
            .unwrap();
        assert_eq!(s.sweep(1050).unwrap(), 1, "only the invite has expired");
        assert_eq!(s.sweep(1101).unwrap(), 2, "envelope and blob");
        assert_eq!(s.fetch(&m, 0, 10, 1101).unwrap().0.len(), 0);
        // After the idle period without auth the mailbox goes too.
        assert_eq!(s.sweep(1000 + 2000).unwrap(), 1);
        assert_eq!(s.mailbox_auth_key(&m), Err(StoreError::NotFound));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
