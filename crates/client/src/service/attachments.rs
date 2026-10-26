//! Photos, files and voice notes (milestone 3, ADR-0015).
//!
//! A file is encrypted with the core's chunked XChaCha20-Poly1305 STREAM (PROTOCOL §9), the
//! ciphertext is uploaded to the relay's blob store in 64 KiB chunks under a random id, and
//! only then is the `Attachment` message (id, key, hash, sizes) sealed and sent. The receiver
//! downloads the chunks, checks the hash before decrypting, and keeps the file in the
//! encrypted database. Nothing is written outside `SQLCipher`.
//!
//! Transfers run inside the actor, one chunk per step between commands, on the one relay
//! connection, so there is one database writer and a lock pre-empts them like any relay I/O.

use rusqlite::{OptionalExtension as _, params};
use serde::Serialize;
use veil_core::account::random_id;
use veil_core::attachment::{self, AttachmentKey};
use veil_core::content::{Attachment, Body, Content};
use veil_wire::{ErrorCode, Request, Response};
use zeroize::Zeroizing;

use super::{Actor, ChangeKind, MessageView, rng};
use crate::{ClientError, Result, now_ms, now_secs};

/// Largest file Veil sends or downloads (the core allows 100 MiB).
pub const MAX_FILE: usize = 25 * 1024 * 1024;
/// Longest voice note.
pub const MAX_VOICE_MS: u32 = 5 * 60 * 1000;
/// Largest voice note: 5 minutes of Opus at 32 kbit/s is about 1.2 MB. A larger "voice
/// note" from a contact is a file, so the app never plays a large blob in the webview
/// (review M3R2-2, INV-ATT-5).
pub const MAX_VOICE_BYTES: usize = 4 * 1024 * 1024;
/// Ciphertext per chunk: 64 KiB of plaintext plus the 16-byte tag.
const CT_CHUNK: usize = attachment::CHUNK + 16;
/// Give up a transfer after this many failed chunk requests in a row.
const MAX_TRANSFER_ATTEMPTS: i64 = 30;
/// Longest wait between attempts of a failing transfer.
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;
/// Fresh re-uploads (new key, blob id and token) after the relay refused an upload token,
/// before the upload is shown as not sent.
const MAX_RESTARTS: i64 = 2;
/// Files a contact's messages may download by themselves per day; past it, the user taps to
/// download, so a contact cannot fill the phone (review M3-12).
pub const AUTO_DOWNLOAD_PER_DAY: i64 = 100 * 1024 * 1024;
/// Received files downloaded by themselves and never opened, all contacts together; past
/// it, new files wait for a tap, so the total stays bounded too (review M3R2-5).
pub const AUTO_DOWNLOAD_UNOPENED: i64 = 500 * 1024 * 1024;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Report progress to the UI every this many chunks.
const PROGRESS_EVERY: i64 = 16;
/// Image types the UI shows inline (SVG never: it is a document, not an image).
const INLINE_IMAGES: &[&str] = &["image/jpeg", "image/png", "image/webp", "image/gif"];

/// What the UI hands over to send. The bytes are wiped when this is dropped.
pub struct AttachmentInput {
    /// `image`, `file` or `voice`.
    pub kind: String,
    pub mime: String,
    pub name: Option<String>,
    pub data: Zeroizing<Vec<u8>>,
    pub thumbnail: Option<Vec<u8>>,
    pub duration_ms: Option<u32>,
    pub waveform: Option<Vec<u8>>,
}

impl core::fmt::Debug for AttachmentInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AttachmentInput { .. }")
    }
}

/// An attachment as the UI shows it. The file itself is fetched separately.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub kind: String,
    pub mime: String,
    pub name: Option<String>,
    pub size: i64,
    /// `uploading`, `sent`, `downloading`, `ready`, `failed` or `too_large`.
    pub state: String,
    /// 0 to 1 while uploading or downloading.
    pub progress: f32,
    pub duration_ms: Option<u32>,
    pub waveform: Vec<u8>,
    /// Small inline preview (JPEG), sent inside the message.
    pub thumbnail: Option<Vec<u8>>,
}

/// What `finish_upload` reads: recipient, message and attachment fields.
type UploadRow = (
    String,
    i64,
    Vec<u8>,
    String,
    Option<String>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<u32>,
    Option<Vec<u8>>,
    Option<u32>,
);

/// One pending transfer, as stored.
struct Transfer {
    message: i64,
    upload: bool,
    blob_id: Vec<u8>,
    next: i64,
    total: i64,
    token: Option<Vec<u8>>,
}

fn clean_mime(m: &str) -> Option<String> {
    let m = m.trim().to_ascii_lowercase();
    let ok = !m.is_empty()
        && m.len() <= 127
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/+-.".contains(&b))
        && m.contains('/');
    ok.then_some(m)
}

/// A file name for display and saving: no path, no control or invisible characters.
fn clean_file_name(n: &str) -> Option<String> {
    let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
    let out: String = super::clean_name_long(base, 255);
    (!out.is_empty() && out != "." && out != "..").then_some(out)
}

fn kind_for(mime: &str, voice: bool) -> &'static str {
    if voice {
        "voice"
    } else if INLINE_IMAGES.contains(&mime) {
        "image"
    } else {
        "file"
    }
}

impl Actor {
    /// Encrypts a file and queues it for upload. The message is sent once the upload is done.
    pub(super) async fn send_attachment(
        &mut self,
        contact: i64,
        input: AttachmentInput,
    ) -> Result<MessageView> {
        let size = input.data.len();
        if size == 0 || size > MAX_FILE {
            return Err(ClientError::BadInput);
        }
        let mime = clean_mime(&input.mime).ok_or(ClientError::BadInput)?;
        let voice = input.kind == "voice";
        if voice
            && (input.duration_ms.is_none_or(|d| d == 0 || d > MAX_VOICE_MS)
                || !mime.starts_with("audio/")
                || size > MAX_VOICE_BYTES)
        {
            return Err(ClientError::BadInput);
        }
        let kind = kind_for(&mime, voice);
        let name = match input.name.as_deref() {
            Some(n) => Some(clean_file_name(n).ok_or(ClientError::BadInput)?),
            None => None,
        };
        let thumbnail = input.thumbnail.filter(|t| !t.is_empty());
        if thumbnail.as_ref().is_some_and(|t| t.len() > 8 * 1024)
            || input.waveform.as_ref().is_some_and(|w| w.len() > 256)
        {
            return Err(ClientError::BadInput);
        }
        let s = self.s()?;
        let (blocked, timer): (bool, u32) =
            s.db.conn()
                .query_row(
                    "SELECT blocked, timer_secs FROM contacts WHERE id = ?1",
                    [contact],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(ClientError::UnknownContact)?;
        if blocked {
            return Err(ClientError::Blocked);
        }
        let (key, enc) = attachment::encrypt(&mut rng(), &input.data).map_err(|_| ClientError::BadInput)?;
        let mut blob_id = vec![0u8; 32];
        rand::Rng::fill(&mut rng(), &mut blob_id[..]);
        let total = i64::from(attachment::chunk_count(enc.padded_size)?);
        let at = now_ms();
        let expires = (timer > 0).then(|| at.saturating_add(i64::from(timer).saturating_mul(1000)));
        let msg_id = random_id(&mut rng());
        let db = s.db.clone();
        let id = self
            .atomically(async {
                let conn = db.conn();
                conn.execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status, msg_id, expires_at_ms)
                     VALUES (?1, 1, 'attachment', '', ?2, 'sending', ?3, ?4)",
                    params![contact, at, msg_id, expires],
                )?;
                let id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO attachments (message, kind, mime, name, size, duration_ms, waveform, thumbnail,
                       blob_id, att_key, nonce_prefix, sha256, padded_size, total_chunks, state, data, timer_secs)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'upload', ?15, ?16)",
                    params![
                        id,
                        kind,
                        mime,
                        name,
                        i64::try_from(size).unwrap_or(i64::MAX),
                        input.duration_ms,
                        input.waveform,
                        thumbnail,
                        blob_id,
                        key.key_bytes().to_vec(),
                        key.nonce_prefix().to_vec(),
                        enc.ciphertext_sha256.to_vec(),
                        i64::try_from(enc.padded_size).unwrap_or(i64::MAX),
                        total,
                        &input.data[..],
                        (timer > 0).then_some(timer),
                    ],
                )?;
                let mut put = conn.prepare(
                    "INSERT INTO attachment_chunks (message, idx, data) VALUES (?1, ?2, ?3)",
                )?;
                for (i, c) in enc.ciphertext.chunks(CT_CHUNK).enumerate() {
                    put.execute(params![id, i64::try_from(i).unwrap_or(i64::MAX), c])?;
                }
                Ok(id)
            })
            .await?;
        self.wake_transfers();
        self.emit(ChangeKind::Messages, Some(contact));
        self.message(id)
    }

    /// Marks that there may be transfer work.
    pub(super) fn wake_transfers(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.transfers = true;
        }
    }

    /// Whether the run loop should spend a step on a transfer now.
    pub(super) fn wants_transfer(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.transfers && s.relay.as_ref().is_some_and(crate::relay::Relay::is_open))
            && !self.idle_expired()
    }

    /// Moves one transfer forward by one chunk.
    pub(super) async fn transfer_step(&mut self) {
        let Ok(s) = self.s() else { return };
        let next: Option<Transfer> =
            s.db.conn()
                .query_row(
                    // Uploads first (the user is waiting on them), then the transfer that has
                    // failed least; one that keeps failing waits its turn (review M3-4).
                    "SELECT message, state = 'upload', blob_id, next_chunk, total_chunks, upload_token
                 FROM attachments WHERE state IN ('upload', 'download') AND next_attempt_ms <= ?1
                 ORDER BY state = 'download', attempts, message LIMIT 1",
                    [now_ms()],
                    |r| {
                        Ok(Transfer {
                            message: r.get(0)?,
                            upload: r.get(1)?,
                            blob_id: r.get(2)?,
                            next: r.get(3)?,
                            total: r.get(4)?,
                            token: r.get(5)?,
                        })
                    },
                )
                .optional()
                .ok()
                .flatten();
        let Some(t) = next else {
            if let Some(s) = self.session.as_mut() {
                s.transfers = false;
            }
            return;
        };
        let result = if t.upload {
            self.upload_step(&t).await
        } else {
            self.download_step(&t).await
        };
        match result {
            Ok(()) => {}
            // Offline, locked or throttled: try again later.
            Err(
                ClientError::Unreachable
                | ClientError::Locked
                | ClientError::Rejected(ErrorCode::RateLimited),
            ) => {
                if let Some(s) = self.session.as_mut() {
                    s.transfers = false;
                }
            }
            // Chunks that do not match what the sender authenticated, or a blob the relay
            // does not have (never uploaded, or expired): asking again will not help.
            Err(ClientError::Protocol) => self.give_up(t.message),
            Err(ClientError::Rejected(ErrorCode::NotFound)) if !t.upload => self.give_up(t.message),
            // The relay refused the upload token (expired while offline or locked, or out of
            // re-sends): start again under a fresh key, blob id and token (review M3-7).
            Err(ClientError::Rejected(
                ErrorCode::Unauthorized | ErrorCode::QuotaExceeded | ErrorCode::Conflict,
            )) if t.upload => {
                if self.restart_upload(t.message, true).await.is_err() {
                    self.give_up(t.message);
                }
            }
            Err(_) => self.transfer_failed(t.message),
        }
    }

    /// Counts a failed attempt and waits before the next; past the limit, gives up.
    fn transfer_failed(&mut self, message: i64) {
        let Ok(s) = self.s() else { return };
        let attempts: i64 =
            s.db.conn()
                .query_row(
                    "UPDATE attachments SET attempts = attempts + 1 WHERE message = ?1 RETURNING attempts",
                    [message],
                    |r| r.get(0),
                )
                .unwrap_or(MAX_TRANSFER_ATTEMPTS);
        if attempts >= MAX_TRANSFER_ATTEMPTS {
            self.give_up(message);
            return;
        }
        let _ = s.db.conn().execute(
            "UPDATE attachments SET next_attempt_ms = ?2 WHERE message = ?1",
            params![message, now_ms().saturating_add(backoff_ms(attempts))],
        );
    }

    /// The transfer failed for good: the UI offers to try again.
    fn give_up(&mut self, message: i64) {
        let Ok(s) = self.s() else { return };
        let conn = s.db.conn();
        // Chunks are dropped either way; a retried upload is encrypted afresh.
        let _ = conn.execute(
            "UPDATE attachments SET state = 'failed', next_chunk = 0, upload_token = NULL
             WHERE message = ?1 AND state IN ('upload', 'download')",
            [message],
        );
        let _ = conn.execute("DELETE FROM attachment_chunks WHERE message = ?1", [message]);
        let _ = conn.execute(
            "UPDATE messages SET status = 'failed' WHERE id = ?1 AND mine = 1",
            [message],
        );
        let contact = self.contact_of(message);
        self.emit(ChangeKind::Messages, contact);
    }

    fn contact_of(&self, message: i64) -> Option<i64> {
        self.s()
            .ok()?
            .db
            .conn()
            .query_row("SELECT contact FROM messages WHERE id = ?1", [message], |r| {
                r.get(0)
            })
            .ok()
    }

    fn progress(&self, message: i64, next: i64) {
        if next % PROGRESS_EVERY == 0 {
            let c = self.contact_of(message);
            self.emit(ChangeKind::Messages, c);
        }
    }

    async fn upload_step(&mut self, t: &Transfer) -> Result<()> {
        let s = self.s()?;
        let mailbox = s.mailbox;
        let db = s.db.clone();
        let token = if let Some(tok) = &t.token {
            tok.clone()
        } else {
            {
                let Response::UploadToken(u) = self
                    .call(Request::BlobUploadToken(veil_wire::MailboxRef {
                        mailbox_id: mailbox.to_vec(),
                    }))
                    .await?
                else {
                    return Err(ClientError::Relay);
                };
                db.conn().execute(
                    "UPDATE attachments SET upload_token = ?2 WHERE message = ?1",
                    params![t.message, u.upload_token],
                )?;
                u.upload_token
            }
        };
        if t.next >= t.total {
            return self.finish_upload(t.message).await;
        }
        let data: Vec<u8> = db.conn().query_row(
            "SELECT data FROM attachment_chunks WHERE message = ?1 AND idx = ?2",
            params![t.message, t.next],
            |r| r.get(0),
        )?;
        let put = self
            .call(Request::BlobPut(veil_wire::BlobPut {
                upload_token: token,
                blob_id: t.blob_id.clone(),
                chunk_index: u32::try_from(t.next).map_err(|_| ClientError::Storage)?,
                total_chunks: u32::try_from(t.total).map_err(|_| ClientError::Storage)?,
                data,
            }))
            .await;
        match put {
            Ok(_) => {}
            // The token is spent once the blob is complete: a lost reply to the last chunk
            // looks like this. The blob is there if it can be read.
            Err(ClientError::Rejected(ErrorCode::Unauthorized))
                if t.next.saturating_add(1) == t.total && self.blob_complete(&t.blob_id).await => {}
            Err(e) => return Err(e),
        }
        let next = t.next.saturating_add(1);
        // Both or neither, so `next_chunk` never points at a chunk already dropped (M3-6).
        self.atomically(async {
            db.conn().execute(
                "UPDATE attachments SET next_chunk = ?2, attempts = 0 WHERE message = ?1",
                params![t.message, next],
            )?;
            db.conn().execute(
                "DELETE FROM attachment_chunks WHERE message = ?1 AND idx = ?2",
                params![t.message, t.next],
            )?;
            Ok(())
        })
        .await?;
        self.progress(t.message, next);
        if next >= t.total {
            self.finish_upload(t.message).await?;
        }
        Ok(())
    }

    async fn blob_complete(&self, blob_id: &[u8]) -> bool {
        matches!(
            self.call(Request::BlobGet(veil_wire::BlobGet {
                blob_id: blob_id.to_vec(),
                chunk_index: 0,
            }))
            .await,
            Ok(Response::BlobChunk(_))
        )
    }

    /// The file is at the relay: seal the `Attachment` message and send it like a text.
    async fn finish_upload(&mut self, message: i64) -> Result<()> {
        let s = self.s()?;
        let row: UploadRow = s.db.conn().query_row(
            "SELECT c.address, m.contact, m.msg_id, a.mime, a.name, a.size, a.padded_size, a.blob_id,
                    a.att_key, a.nonce_prefix, a.sha256, a.thumbnail, a.duration_ms, a.waveform, a.timer_secs
             FROM attachments a JOIN messages m ON m.id = a.message JOIN contacts c ON c.id = m.contact
             WHERE a.message = ?1",
            [message],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                ))
            },
        )?;
        let (
            address,
            contact,
            msg_id,
            mime,
            name,
            size,
            padded,
            blob_id,
            key,
            nonce,
            sha,
            thumb,
            dur,
            wave,
            timer,
        ) = row;
        let addr = veil_core::identity::Address::parse(&address).map_err(|_| ClientError::Storage)?;
        let content = Content {
            id: msg_id,
            sent_at_ms: u64::try_from(now_ms()).unwrap_or(0),
            body: Some(Body::Attachment(Attachment {
                blob_id,
                key,
                nonce_prefix: nonce,
                ciphertext_sha256: sha,
                size: u64::try_from(size).map_err(|_| ClientError::Storage)?,
                padded_size: u64::try_from(padded).map_err(|_| ClientError::Storage)?,
                mime,
                file_name: name,
                thumbnail: thumb,
                voice_duration_ms: dur,
                waveform: wave,
                expire_timer_secs: timer,
            })),
        };
        let db = s.db.clone();
        self.atomically(async {
            let envelope = s.account.seal(&mut rng(), &addr, &content, now_secs()).await?;
            db.conn().execute(
                "UPDATE messages SET envelope = ?2 WHERE id = ?1",
                params![message, envelope],
            )?;
            db.conn().execute(
                "UPDATE attachments SET state = 'sent', upload_token = NULL WHERE message = ?1",
                [message],
            )?;
            Ok(())
        })
        .await?;
        self.deliver(message).await;
        self.emit(ChangeKind::Messages, Some(contact));
        Ok(())
    }

    async fn download_step(&mut self, t: &Transfer) -> Result<()> {
        if t.next >= t.total {
            // Every chunk is here; finishing failed last time (M3-6).
            return self.finish_download(t.message).await;
        }
        let Response::BlobChunk(chunk) = self
            .call(Request::BlobGet(veil_wire::BlobGet {
                blob_id: t.blob_id.clone(),
                chunk_index: u32::try_from(t.next).map_err(|_| ClientError::Storage)?,
            }))
            .await?
        else {
            return Err(ClientError::Relay);
        };
        // The relay is not trusted: the chunk count and sizes must match what the sender
        // authenticated; the hash and the AEAD check the rest.
        if !chunk_fits(t.total, t.next, chunk.total_chunks, chunk.data.len()) {
            return Err(ClientError::Protocol);
        }
        let db = self.s()?.db.clone();
        let next = t.next.saturating_add(1);
        self.atomically(async {
            db.conn().execute(
                "INSERT OR REPLACE INTO attachment_chunks (message, idx, data) VALUES (?1, ?2, ?3)",
                params![t.message, t.next, chunk.data],
            )?;
            db.conn().execute(
                "UPDATE attachments SET next_chunk = ?2, attempts = 0 WHERE message = ?1",
                params![t.message, next],
            )?;
            Ok(())
        })
        .await?;
        self.progress(t.message, next);
        if next >= t.total {
            self.finish_download(t.message).await?;
        }
        Ok(())
    }

    /// All chunks are here: check the hash, decrypt, keep the file, drop the ciphertext.
    async fn finish_download(&mut self, message: i64) -> Result<()> {
        let db = self.s()?.db.clone();
        let conn = db.conn();
        let (key, nonce, sha, size, padded): (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = conn.query_row(
            "SELECT att_key, nonce_prefix, sha256, size, padded_size FROM attachments WHERE message = ?1",
            [message],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let key = Zeroizing::new(key);
        let mut ct = Vec::new();
        {
            let mut st =
                conn.prepare("SELECT data FROM attachment_chunks WHERE message = ?1 ORDER BY idx")?;
            let mut rows = st.query([message])?;
            while let Some(r) = rows.next()? {
                let part: Vec<u8> = r.get(0)?;
                if ct.len().saturating_add(part.len()) > MAX_FILE.saturating_add(MAX_FILE / 4) {
                    return Err(ClientError::Relay);
                }
                ct.extend_from_slice(&part);
            }
        }
        let plain = AttachmentKey::from_parts(&key, &nonce).and_then(|k| {
            attachment::decrypt(
                &k,
                &ct,
                &sha,
                u64::try_from(size).unwrap_or(u64::MAX),
                u64::try_from(padded).unwrap_or(u64::MAX),
            )
        });
        drop(ct);
        self.atomically(async {
            conn.execute("DELETE FROM attachment_chunks WHERE message = ?1", [message])?;
            match &plain {
                Ok(plain) => {
                    conn.execute(
                        "UPDATE attachments SET state = 'ready', data = ?2 WHERE message = ?1",
                        params![message, &plain[..]],
                    )?;
                }
                // Wrong hash or a failed AEAD tag: damaged or forged. Never shown.
                Err(_) => {
                    conn.execute(
                        "UPDATE attachments SET state = 'failed', next_chunk = 0 WHERE message = ?1",
                        [message],
                    )?;
                }
            }
            Ok(())
        })
        .await?;
        let c = self.contact_of(message);
        self.emit(ChangeKind::Messages, c);
        Ok(())
    }

    /// Stores an incoming `Attachment` (inside `process`'s transaction). The download starts
    /// on the next step.
    pub(super) fn receive_attachment(
        &self,
        contact: i64,
        msg_id: &[u8],
        a: &Attachment,
        expires: Option<i64>,
    ) -> Result<()> {
        let s = self.s()?;
        let conn = s.db.conn();
        let mime = clean_mime(&a.mime).unwrap_or_else(|| "application/octet-stream".into());
        let voice = a.voice_duration_ms.is_some()
            && mime.starts_with("audio/")
            && usize::try_from(a.size).is_ok_and(|n| n <= MAX_VOICE_BYTES);
        let kind = kind_for(&mime, voice);
        let name = a.file_name.as_deref().and_then(clean_file_name);
        let too_large = usize::try_from(a.size).map_or(true, |n| n > MAX_FILE);
        let size = i64::try_from(a.size).unwrap_or(i64::MAX);
        let today: i64 = conn.query_row(
            "SELECT COALESCE(SUM(a.size), 0) FROM attachments a JOIN messages m ON m.id = a.message
             WHERE m.contact = ?1 AND m.mine = 0 AND m.at_ms > ?2 AND a.state != 'available'",
            params![contact, now_ms().saturating_sub(DAY_MS)],
            |r| r.get(0),
        )?;
        let unopened: i64 = conn.query_row(
            "SELECT COALESCE(SUM(a.size), 0) FROM attachments a JOIN messages m ON m.id = a.message
             WHERE m.mine = 0 AND a.opened = 0 AND a.state IN ('download', 'ready')",
            [],
            |r| r.get(0),
        )?;
        let state = if too_large {
            "too_large"
        } else if today.saturating_add(size) > AUTO_DOWNLOAD_PER_DAY
            || unopened.saturating_add(size) > AUTO_DOWNLOAD_UNOPENED
        {
            "available"
        } else {
            "download"
        };
        let total = i64::from(attachment::chunk_count(a.padded_size).map_err(|_| ClientError::Protocol)?);
        // The same plausibility checks the sender's core made: sizes that fit each other.
        if attachment::padded_size(a.size).ok() != Some(a.padded_size) {
            return Err(ClientError::Protocol);
        }
        conn.execute(
            "INSERT INTO messages (contact, mine, kind, body, at_ms, status, msg_id, expires_at_ms)
             VALUES (?1, 0, 'attachment', '', ?2, 'received', ?3, ?4)",
            params![contact, now_ms(), msg_id, expires],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO attachments (message, kind, mime, name, size, duration_ms, waveform, thumbnail,
               blob_id, att_key, nonce_prefix, sha256, padded_size, total_chunks, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                id,
                kind,
                mime,
                name,
                size,
                a.voice_duration_ms.map(|d| d.min(MAX_VOICE_MS)),
                a.waveform,
                a.thumbnail,
                a.blob_id,
                a.key,
                a.nonce_prefix,
                a.ciphertext_sha256,
                i64::try_from(a.padded_size).unwrap_or(i64::MAX),
                total,
                state,
            ],
        )?;
        conn.execute("UPDATE contacts SET unread = unread + 1 WHERE id = ?1", [contact])?;
        self.emit(ChangeKind::Messages, Some(contact));
        self.emit(ChangeKind::Contacts, Some(contact));
        self.emit(ChangeKind::Incoming, Some(contact));
        Ok(())
    }

    /// The attachment part of a message, if it has one.
    pub(super) fn attachment_view(&self, message: i64) -> Result<Option<AttachmentView>> {
        Ok(self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT kind, mime, name, size, state, next_chunk, total_chunks, duration_ms, waveform, thumbnail
                 FROM attachments WHERE message = ?1",
                [message],
                |r| {
                    let state: String = r.get(4)?;
                    let next: i64 = r.get(5)?;
                    let total: i64 = r.get(6)?;
                    #[allow(clippy::cast_precision_loss, clippy::as_conversions)]
                    let progress = if total > 0 {
                        (next.min(total) as f32) / (total as f32)
                    } else {
                        0.0
                    };
                    Ok(AttachmentView {
                        kind: r.get(0)?,
                        mime: r.get(1)?,
                        name: r.get(2)?,
                        size: r.get(3)?,
                        state: match state.as_str() {
                            "upload" => "uploading".into(),
                            "download" => "downloading".into(),
                            _ => state,
                        },
                        progress,
                        duration_ms: r.get(7)?,
                        waveform: r.get::<_, Option<Vec<u8>>>(8)?.unwrap_or_default(),
                        thumbnail: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// The file, for the UI to show or save. Display data: it is what the user received.
    pub(super) fn attachment_data(
        &self,
        message: i64,
    ) -> Result<(String, Option<String>, Zeroizing<Vec<u8>>)> {
        let (mime, name, data): (String, Option<String>, Option<Vec<u8>>) = self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT a.mime, a.name, a.data FROM attachments a JOIN messages m ON m.id = a.message
                 WHERE a.message = ?1 AND m.deleted = 0",
                [message],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(ClientError::BadInput)?;
        let data = Zeroizing::new(data.ok_or(ClientError::NotReady)?);
        // Shown, played or saved: it no longer counts against the automatic downloads.
        self.s()?
            .db
            .conn()
            .execute("UPDATE attachments SET opened = 1 WHERE message = ?1", [message])?;
        Ok((mime, name, data))
    }

    /// Starts a failed transfer again, or a download the user tapped (`available`). A failed
    /// upload is encrypted again under a fresh key and a new blob id (never re-encrypting
    /// under the old key, PROTOCOL §9).
    pub(super) async fn retry_attachment(&mut self, message: i64) -> Result<()> {
        let mine: bool = self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT m.mine FROM attachments a JOIN messages m ON m.id = a.message
                 WHERE a.message = ?1 AND m.deleted = 0
                   AND (a.state = 'failed' OR (a.state = 'available' AND m.mine = 0))",
                [message],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(ClientError::BadInput)?;
        if mine {
            self.restart_upload(message, false).await?;
        } else {
            self.s()?.db.conn().execute(
                "UPDATE attachments SET state = 'download', attempts = 0, next_attempt_ms = 0, next_chunk = 0
                 WHERE message = ?1",
                [message],
            )?;
            self.wake_transfers();
            let c = self.contact_of(message);
            self.emit(ChangeKind::Messages, c);
        }
        Ok(())
    }

    /// Encrypts one of our files again under a fresh key, nonce prefix and blob id and queues
    /// the upload. `automatic`: after the relay refused the token, at most `MAX_RESTARTS`
    /// times; the user's own retry starts the count again.
    pub(super) async fn restart_upload(&mut self, message: i64, automatic: bool) -> Result<()> {
        let s = self.s()?;
        let (data, restarts): (Option<Vec<u8>>, i64) =
            s.db.conn()
                .query_row(
                    "SELECT a.data, a.restarts FROM attachments a JOIN messages m ON m.id = a.message
                     WHERE a.message = ?1 AND m.mine = 1 AND m.deleted = 0",
                    [message],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(ClientError::BadInput)?;
        if automatic && restarts >= MAX_RESTARTS {
            return Err(ClientError::Relay);
        }
        let restarts = if automatic { restarts.saturating_add(1) } else { 0 };
        let db = s.db.clone();
        let data = Zeroizing::new(data.ok_or(ClientError::Storage)?);
        let (key, enc) = attachment::encrypt(&mut rng(), &data).map_err(|_| ClientError::Storage)?;
        let mut blob_id = vec![0u8; 32];
        rand::Rng::fill(&mut rng(), &mut blob_id[..]);
        let total = i64::from(attachment::chunk_count(enc.padded_size)?);
        self.atomically(async {
            let conn = db.conn();
            conn.execute("DELETE FROM attachment_chunks WHERE message = ?1", [message])?;
            conn.execute(
                "UPDATE attachments SET state = 'upload', attempts = 0, next_attempt_ms = 0, next_chunk = 0,
                   upload_token = NULL, restarts = ?8, blob_id = ?2, att_key = ?3, nonce_prefix = ?4,
                   sha256 = ?5, padded_size = ?6, total_chunks = ?7
                 WHERE message = ?1",
                params![
                    message,
                    blob_id,
                    key.key_bytes().to_vec(),
                    key.nonce_prefix().to_vec(),
                    enc.ciphertext_sha256.to_vec(),
                    i64::try_from(enc.padded_size).unwrap_or(i64::MAX),
                    total,
                    restarts
                ],
            )?;
            conn.execute("UPDATE messages SET status = 'sending' WHERE id = ?1", [message])?;
            let mut put =
                conn.prepare("INSERT INTO attachment_chunks (message, idx, data) VALUES (?1, ?2, ?3)")?;
            for (i, c) in enc.ciphertext.chunks(CT_CHUNK).enumerate() {
                put.execute(params![message, i64::try_from(i).unwrap_or(i64::MAX), c])?;
            }
            Ok(())
        })
        .await?;
        self.wake_transfers();
        let c = self.contact_of(message);
        self.emit(ChangeKind::Messages, c);
        Ok(())
    }
}

#[cfg(feature = "test-hooks")]
impl Actor {
    pub(super) fn attachment_blob(&self, message: i64) -> Result<Vec<u8>> {
        Ok(self.s()?.db.conn().query_row(
            "SELECT blob_id FROM attachments WHERE message = ?1",
            [message],
            |r| r.get(0),
        )?)
    }

    pub(super) async fn raw_upload(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mailbox = self.s()?.mailbox;
        let Response::UploadToken(u) = self
            .call(Request::BlobUploadToken(veil_wire::MailboxRef {
                mailbox_id: mailbox.to_vec(),
            }))
            .await?
        else {
            return Err(ClientError::Relay);
        };
        let mut blob_id = vec![0u8; 32];
        rand::Rng::fill(&mut rng(), &mut blob_id[..]);
        let chunks: Vec<&[u8]> = ciphertext.chunks(CT_CHUNK).collect();
        let total = u32::try_from(chunks.len()).map_err(|_| ClientError::BadInput)?;
        for (i, c) in chunks.into_iter().enumerate() {
            self.call(Request::BlobPut(veil_wire::BlobPut {
                upload_token: u.upload_token.clone(),
                blob_id: blob_id.clone(),
                chunk_index: u32::try_from(i).map_err(|_| ClientError::BadInput)?,
                total_chunks: total,
                data: c.to_vec(),
            }))
            .await?;
        }
        Ok(blob_id)
    }
}

/// Wait before the next attempt of a transfer that failed `attempts` times: 2 s doubling,
/// at most `MAX_BACKOFF_MS`.
fn backoff_ms(attempts: i64) -> i64 {
    let shift = u32::try_from(attempts.clamp(0, 20)).unwrap_or(20);
    2000_i64.saturating_mul(1_i64 << shift).min(MAX_BACKOFF_MS)
}

/// Whether a chunk from the relay has the shape the sender authenticated: the same chunk
/// count, full-size chunks except the last, and no chunk larger than a full one. The relay is
/// not trusted; the hash and the AEAD check the bytes.
fn chunk_fits(total: i64, index: i64, claimed_total: u32, len: usize) -> bool {
    let last = index.saturating_add(1) == total;
    i64::from(claimed_total) == total && len <= CT_CHUNK && (last || len == CT_CHUNK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_types_are_cleaned() {
        assert_eq!(clean_file_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(
            clean_file_name("C:\\Users\\x\\photo.jpg").as_deref(),
            Some("photo.jpg")
        );
        assert_eq!(clean_file_name("..").as_deref(), None);
        assert_eq!(clean_file_name("a\u{202e}gpj.exe").as_deref(), Some("agpj.exe"));
        assert_eq!(clean_mime("Image/PNG").as_deref(), Some("image/png"));
        assert_eq!(clean_mime("text/html; charset=x").as_deref(), None);
        assert_eq!(clean_mime("nope").as_deref(), None);
        assert_eq!(kind_for("image/svg+xml", false), "file");
        assert_eq!(kind_for("image/png", false), "image");
        assert_eq!(kind_for("audio/webm", true), "voice");
    }

    /// The hostile-relay shapes the honest relay never serves (review M3-5).
    #[test]
    fn chunks_must_match_what_the_sender_authenticated() {
        assert!(chunk_fits(3, 0, 3, CT_CHUNK));
        assert!(chunk_fits(3, 2, 3, 17));
        assert!(!chunk_fits(3, 0, 4, CT_CHUNK), "another chunk count");
        assert!(
            !chunk_fits(3, 1, 3, CT_CHUNK - 1),
            "a short chunk before the last"
        );
        assert!(
            !chunk_fits(3, 2, 3, CT_CHUNK + 1),
            "a chunk larger than a full one"
        );
        assert!(!chunk_fits(3, 0, 3, CT_CHUNK + 1));
    }

    #[test]
    fn failing_transfers_back_off() {
        assert_eq!(backoff_ms(0), 2000);
        assert_eq!(backoff_ms(1), 4000);
        assert_eq!(backoff_ms(29), MAX_BACKOFF_MS);
        assert_eq!(backoff_ms(-5), 2000);
    }
}
