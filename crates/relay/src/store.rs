//! Relay storage (redb, pure Rust).
//!
//! What is stored is exactly what PROTOCOL §2, §4.2, §6.3 and §9 allow, and nothing else:
//! * mailboxes: random id → Ed25519 auth key, sequence counter, quotas, last-auth minute;
//! * delivery-token *hashes* per mailbox;
//! * envelopes: `(mailbox, seq)` → expiry, receipt minute, sealed bytes;
//! * invites: id → expiry, sealed package;
//! * blobs: id → chunks, plus hashed one-time upload tokens.
//!
//! No IP address, no connection data, no sender, no User-Agent (INV-META-2). Every write is a
//! single redb transaction, so a failed operation changes nothing.

use std::collections::BTreeMap;
use std::path::Path;

use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};

type Bytes = &'static [u8];

const MAILBOXES: TableDefinition<Bytes, Bytes> = TableDefinition::new("mailboxes");
const TOKENS: TableDefinition<Bytes, Bytes> = TableDefinition::new("tokens");
const ENVELOPES: TableDefinition<Bytes, Bytes> = TableDefinition::new("envelopes");
const INVITES: TableDefinition<Bytes, Bytes> = TableDefinition::new("invites");
const UPLOAD_TOKENS: TableDefinition<Bytes, Bytes> = TableDefinition::new("upload_tokens");
const BLOBS: TableDefinition<Bytes, Bytes> = TableDefinition::new("blobs");
const BLOB_CHUNKS: TableDefinition<Bytes, Bytes> = TableDefinition::new("blob_chunks");
const STATS: TableDefinition<Bytes, u64> = TableDefinition::new("stats");

const STAT_MAILBOXES: &[u8] = b"mailboxes";
const STAT_INVITES: &[u8] = b"invites";
const STAT_BLOB_BYTES: &[u8] = b"blob_bytes";
const STAT_ENVELOPE_BYTES: &[u8] = b"envelope_bytes";

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

/// Deletes every envelope in `range`; returns (records, stored bytes) removed.
fn remove_counted(
    env: &mut redb::Table<'_, Bytes, Bytes>,
    range: core::ops::Range<&[u8]>,
) -> Result<(u64, u64)> {
    let (mut n, mut bytes) = (0u64, 0u64);
    env.retain_in(range, |_, v| {
        n = n.saturating_add(1);
        bytes = bytes.saturating_add(len_u64(v));
        false
    })
    .map_err(io)?;
    Ok((n, bytes))
}

fn sub_stat(stats: &mut redb::Table<'_, Bytes, u64>, key: &[u8], by: u64) -> Result<()> {
    let v = stats.get(key).map_err(io)?.map_or(0, |g| g.value());
    stats.insert(key, v.saturating_sub(by)).map_err(io)?;
    Ok(())
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

/// `[prefix, prefix + 1)` as a key range (all keys starting with a 32-byte prefix).
fn prefix_end(prefix: &[u8; 32]) -> Vec<u8> {
    cat(&[prefix, &[0xFF; 16]])
}

// --- the store ------------------------------------------------------------------------

pub struct Store {
    db: Database,
    q: Quotas,
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
    pub fn open(path: &Path, q: Quotas) -> Result<Self> {
        let db = Database::create(path).map_err(io)?;
        let s = Self { db, q };
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
            rec.last_auth_minute = minute(now);
            mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    pub fn delete_mailbox(&self, id: &[u8; 32]) -> Result<()> {
        let txn = self.db.begin_write().map_err(io)?;
        {
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            if mb.remove(&id[..]).map_err(io)?.is_none() {
                return Err(StoreError::NotFound);
            }
            let end = prefix_end(id);
            let mut tokens = txn.open_table(TOKENS).map_err(io)?;
            tokens.retain_in(&id[..]..&end[..], |_, _| false).map_err(io)?;
            let mut env = txn.open_table(ENVELOPES).map_err(io)?;
            let freed = remove_counted(&mut env, &id[..]..&end[..])?.1;
            let mut stats = txn.open_table(STATS).map_err(io)?;
            let n = stat!(stats, STAT_MAILBOXES);
            stats.insert(STAT_MAILBOXES, n.saturating_sub(1)).map_err(io)?;
            sub_stat(&mut stats, STAT_ENVELOPE_BYTES, freed)?;
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
            let mut env = txn.open_table(ENVELOPES).map_err(io)?;
            env.insert(&env_key(id, seq)[..], &value[..]).map_err(io)?;
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
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            let mut rec = {
                let g = mb.get(&id[..]).map_err(io)?.ok_or(StoreError::NotFound)?;
                Mailbox::decode(g.value())?
            };
            let mut env = txn.open_table(ENVELOPES).map_err(io)?;
            let start = env_key(id, 0);
            let end = env_key(id, up_to.saturating_add(1).max(1));
            let (n, freed) = remove_counted(&mut env, &start[..]..&end[..])?;
            removed = n;
            rec.count = rec.count.saturating_sub(n);
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
            let n = stat!(stats, STAT_INVITES);
            stats.insert(STAT_INVITES, n.saturating_sub(1)).map_err(io)?;
            if u64_at(&value, 0)? <= now {
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
            t.insert(
                &token_hash[..],
                &cat(&[&expires.to_be_bytes(), &[0u8], &[0u8; 32]])[..],
            )
            .map_err(io)?;
        }
        txn.commit().map_err(io)
    }

    /// Stores one chunk. The token binds to the first blob it uploads; the blob becomes
    /// downloadable when every chunk is present, and the token is then consumed. Re-sending
    /// a chunk (resume) is allowed until completion.
    #[allow(clippy::too_many_arguments)]
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
            if u64_at(&tok, 0)? <= now {
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
            let mut meta = match existing {
                Some(_) if !bound => return Err(StoreError::Conflict), // someone else's blob id
                Some(m) => m,
                None if bound => return Err(StoreError::Corrupt),
                None => BlobMeta {
                    expires: now.saturating_add(self.q.blob_ttl_secs),
                    total,
                    received: 0,
                    complete: false,
                    bytes: 0,
                },
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
            blobs.insert(&blob[..], &meta.encode()[..]).map_err(io)?;
            stats.insert(STAT_BLOB_BYTES, new_used).map_err(io)?;
            if complete {
                toks.remove(&token_hash[..]).map_err(io)?;
            } else if !bound {
                let rebound = cat(&[&u64_at(&tok, 0)?.to_be_bytes(), &[1u8], blob]);
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
    /// Returns the number of records removed.
    pub fn sweep(&self, now: u64) -> Result<u64> {
        let txn = self.db.begin_write().map_err(io)?;
        let mut removed = 0u64;
        {
            // Envelopes: per-mailbox counts must follow.
            let mut env = txn.open_table(ENVELOPES).map_err(io)?;
            let mut per_mailbox: BTreeMap<[u8; 32], u64> = BTreeMap::new();
            let mut env_freed = 0u64;
            env.retain(|k, v| {
                let expired = u64_at(v, 0).is_ok_and(|e| e <= now);
                if expired {
                    env_freed = env_freed.saturating_add(len_u64(v));
                    if let Ok(m) = take::<32>(k, 0) {
                        let n = per_mailbox.entry(m).or_insert(0);
                        *n = n.saturating_add(1);
                    }
                }
                !expired
            })
            .map_err(io)?;
            let mut mb = txn.open_table(MAILBOXES).map_err(io)?;
            for (id, n) in &per_mailbox {
                removed = removed.saturating_add(*n);
                let rec = mb
                    .get(&id[..])
                    .map_err(io)?
                    .map(|g| Mailbox::decode(g.value()))
                    .transpose()?;
                if let Some(mut rec) = rec {
                    rec.count = rec.count.saturating_sub(*n);
                    mb.insert(&id[..], &rec.encode()[..]).map_err(io)?;
                }
            }
            // Idle mailboxes (no successful auth for `mailbox_idle_secs`).
            let cutoff = now.saturating_sub(self.q.mailbox_idle_secs);
            let mut idle: Vec<[u8; 32]> = Vec::new();
            for item in mb.iter().map_err(io)? {
                let (k, v) = item.map_err(io)?;
                if Mailbox::decode(v.value())?.last_auth_minute < cutoff {
                    idle.push(take::<32>(k.value(), 0)?);
                }
            }
            let mut tokens = txn.open_table(TOKENS).map_err(io)?;
            let mut stats = txn.open_table(STATS).map_err(io)?;
            for id in &idle {
                mb.remove(&id[..]).map_err(io)?;
                let end = prefix_end(id);
                tokens.retain_in(&id[..]..&end[..], |_, _| false).map_err(io)?;
                env_freed = env_freed.saturating_add(remove_counted(&mut env, &id[..]..&end[..])?.1);
                let n = stat!(stats, STAT_MAILBOXES);
                stats.insert(STAT_MAILBOXES, n.saturating_sub(1)).map_err(io)?;
                removed = removed.saturating_add(1);
            }
            sub_stat(&mut stats, STAT_ENVELOPE_BYTES, env_freed)?;
            // Invites.
            let mut inv = txn.open_table(INVITES).map_err(io)?;
            let mut n_inv = 0u64;
            inv.retain(|_, v| {
                let keep = u64_at(v, 0).is_ok_and(|e| e > now);
                if !keep {
                    n_inv = n_inv.saturating_add(1);
                }
                keep
            })
            .map_err(io)?;
            let n = stat!(stats, STAT_INVITES);
            stats.insert(STAT_INVITES, n.saturating_sub(n_inv)).map_err(io)?;
            removed = removed.saturating_add(n_inv);
            // Upload tokens.
            let mut toks = txn.open_table(UPLOAD_TOKENS).map_err(io)?;
            toks.retain(|_, v| u64_at(v, 0).is_ok_and(|e| e > now))
                .map_err(io)?;
            // Blobs, and incomplete blobs whose token is gone.
            let mut blobs = txn.open_table(BLOBS).map_err(io)?;
            let mut dead: Vec<([u8; 32], u64)> = Vec::new();
            for item in blobs.iter().map_err(io)? {
                let (k, v) = item.map_err(io)?;
                let meta = BlobMeta::decode(v.value())?;
                if meta.expires <= now {
                    dead.push((take::<32>(k.value(), 0)?, meta.bytes));
                }
            }
            let mut chunks = txn.open_table(BLOB_CHUNKS).map_err(io)?;
            let mut freed = 0u64;
            for (id, bytes) in &dead {
                blobs.remove(&id[..]).map_err(io)?;
                let end = prefix_end(id);
                chunks.retain_in(&id[..]..&end[..], |_, _| false).map_err(io)?;
                freed = freed.saturating_add(*bytes);
                removed = removed.saturating_add(1);
            }
            let used = stat!(stats, STAT_BLOB_BYTES);
            stats
                .insert(STAT_BLOB_BYTES, used.saturating_sub(freed))
                .map_err(io)?;
        }
        txn.commit().map_err(io)?;
        Ok(removed)
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
