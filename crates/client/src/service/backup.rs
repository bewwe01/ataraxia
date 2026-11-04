//! Encrypted backup and restore (milestone 7, ADR-0021), and the standing re-key invites a
//! restore needs (PROTOCOL §3).
//!
//! A backup is the encrypted database without ratchet sessions, prekeys or invites
//! (`veil_core::backup::NOT_BACKED_UP`), sealed under a generated backup code. Restoring keeps
//! the identity key and the relay mailbox, so contacts keep reaching the user; new sessions are
//! set up by redeeming the re-key invite each contact gave us, which the contact's app takes as
//! the same contact with the same safety number.

use std::io::Read as _;
use std::path::Path;

use rand::seq::SliceRandom as _;
use rusqlite::{OptionalExtension as _, params};
use veil_core::backup::{self as bak, BackupCode};
use veil_core::content::{Body, ContactIntro, RekeyInvite};
use veil_core::identity::Address;
use veil_core::invite::Invite;
use zeroize::Zeroizing;

use super::{Actor, ChangeKind, IntroFields, arr32, rng};
use crate::db::Db;
use crate::{ClientError, Result, now_ms, now_secs};

/// The backup file in the data directory, until the shell hands it to the user.
pub const BACKUP_FILE: &str = "backup.vbak";
/// The exported database while a backup is made, and the backup's database while a restore
/// reads it. Both are `SQLCipher` files under a random key held only in memory.
pub const EXPORT_FILE: &str = "backup-export.db";
pub const RESTORE_FILE: &str = "restore.db";
const CODE_KEY: &str = "backup.code";
/// Set by a restore until every contact was re-keyed or marked: the highest message row id
/// before it started (LE). Row ids only grow, so a line written by this restore is above it
/// whatever any clock says (review BK3-1).
const REKEY_DUE_KEY: &str = "restore.rekey_due";
/// Set once the user was shown the backup code after a backup that was saved (review BK-7).
const CODE_SEEN_KEY: &str = "backup.code_seen";
/// The largest backup a restore takes, and so the largest one made (review BK-8).
pub const MAX_BACKUP: u64 = 1024 * 1024 * 1024;
/// The tag on a queued re-key invite, so a newer one replaces it.
const TAG: &str = "rekey";
/// The tag on the introduction a restore sends each contact.
const RESTORE_TAG: &str = "restore";
/// A re-key invite is replaced when it has less than this left.
const RENEW_BEFORE_SECS: u64 = 30 * 24 * 3600;
/// Contacts given a new re-key invite per round (as for profiles).
const PER_ROUND: usize = 4;
/// After a re-key invite could not be made or sealed for a contact, the next try waits this
/// long (review BK-2).
const RETRY_AFTER_MS: i64 = 60 * 60 * 1000;
/// A contact re-keyed by our restore who sent nothing back for this long probably cannot read
/// the new session (their invite was stale): they are marked as needing an invite (BK-5).
pub const REKEY_ANSWER_MS: i64 = 7 * 24 * 3600 * 1000;

/// A contact as a restore re-keys it: id, address, our token for them, their re-key invite.
type RekeyRow = (i64, String, Vec<u8>, Option<String>, Option<Vec<u8>>);

/// What a restore needs. No `Debug` beyond a redacted one: everything here is secret.
pub struct RestoreInput {
    /// The backup file's bytes.
    pub backup: Zeroizing<Vec<u8>>,
    /// The backup code as the user typed it.
    pub code: Zeroizing<String>,
    pub kind: crate::unlock::SecretKind,
    /// The new PIN or password for this device.
    pub passphrase: Zeroizing<String>,
}

impl core::fmt::Debug for RestoreInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RestoreInput { .. }")
    }
}

/// A backup just written.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupView {
    /// The backup code, shown only when it was just made (the first backup); afterwards the
    /// same code opens every backup. Written down by the user, never stored outside Veil.
    pub code: Option<String>,
    pub bytes: u64,
}

/// How a restore went.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreView {
    pub contacts: u32,
    /// Contacts that gave no re-key invite (paired before backups existed, or never online
    /// since): they need a new invite.
    pub need_invite: u32,
    /// False while re-keying is still due: it finishes at the next unlock (if `unlocked` is
    /// false, Veil could not open the restored data yet) or soon after, on its own.
    pub finished: bool,
    /// Veil is unlocked after the restore (review BK3-5).
    pub unlocked: bool,
}

/// A path inside an SQL string literal.
fn sql_path(p: &Path) -> Result<String> {
    Ok(p.to_str().ok_or(ClientError::Storage)?.replace('\'', "''"))
}

/// Marks re-keying as due in a restored database (review BK2-2).
pub(super) fn mark_rekey_due(db: &Db) -> Result<()> {
    let top: i64 = db
        .conn()
        .query_row("SELECT coalesce(max(id), 0) FROM messages", [], |r| r.get(0))?;
    db.set_setting(REKEY_DUE_KEY, &top.to_le_bytes())
}

/// Removes what a backup or restore that did not finish (a crash, say) left in the data
/// directory; all of it is encrypted, but none of it is needed (review BK-16).
pub(super) fn remove_leftovers(dir: &Path) {
    remove_db(&dir.join(EXPORT_FILE));
    remove_db(&dir.join(RESTORE_FILE));
    let _ = std::fs::remove_file(dir.join(BACKUP_FILE));
    let _ = std::fs::remove_file(dir.join(format!("{BACKUP_FILE}.tmp")));
}

/// Removes a file and its `SQLite` side files, if any.
pub(super) fn remove_db(path: &Path) {
    for ext in ["", "-journal", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(ext);
        let _ = std::fs::remove_file(p);
    }
}

/// Drops from a database copy everything a backup must not carry: ratchet sessions, our
/// prekeys and invites, envelopes sealed under the old sessions, and transfers in flight.
fn strip(conn: &rusqlite::Connection, schema: &str) -> Result<()> {
    for prefix in bak::NOT_BACKED_UP {
        let len = i64::try_from(prefix.len()).map_err(|_| ClientError::Storage)?;
        conn.execute(
            &format!("DELETE FROM {schema}.kv WHERE substr(k, 1, ?2) = ?1"),
            params![prefix, len],
        )?;
    }
    conn.execute_batch(&format!(
        "DELETE FROM {schema}.invites;
         DELETE FROM {schema}.messages WHERE mine = 1 AND kind IN ('control', 'mailbox');
         UPDATE {schema}.messages SET envelope = NULL, status = 'failed' WHERE envelope IS NOT NULL;
         UPDATE {schema}.attachments SET state = 'failed', upload_token = NULL WHERE state IN ('upload', 'download');
         DELETE FROM {schema}.attachment_chunks WHERE message IN
           (SELECT message FROM {schema}.attachments WHERE state = 'failed' AND data IS NULL);
         UPDATE {schema}.contacts SET rekey_mine_until = 0, rekey_mine_id = NULL, profile_sent = NULL, intro = NULL,
           rekey_pending_ms = 0, rekey_retry_ms = 0;
         -- The Purge PIN's tag is per device and not in the backup: the restore makes a random
         -- one, so the flag must not say a Purge PIN is set (review BK-3).
         INSERT OR REPLACE INTO {schema}.settings (k, v) VALUES ('purge_set', x'00');"
    ))?;
    Ok(())
}

/// A re-key invite a contact gave us, checked: it must be theirs (their identity key) and
/// for our relay.
fn check_rekey(r: &RekeyInvite, theirs: &[u8], pin: &[u8; 32], now: u64) -> Option<Invite> {
    let inv = Invite::from_link(&r.link).ok()?;
    (*inv.identity.serialize() == *theirs && inv.relay_spki_sha256 == *pin && !inv.is_expired(now))
        .then_some(inv)
}

/// Copies the database to `path` under `key`, then strips it (see [`strip`]).
fn export_to(db: &Db, path: &Path, key: &[u8; 32]) -> Result<()> {
    let conn = db.conn();
    let attach = Zeroizing::new(format!(
        "ATTACH DATABASE '{}' AS bak KEY \"x'{}'\";",
        sql_path(path)?,
        crate::db::hex(&key[..]).as_str()
    ));
    conn.execute_batch(&attach)?;
    // Deleted rows are overwritten, not left in free pages (SQLite copies the main database's
    // setting at ATTACH; this does not rely on it), and full auto-vacuum (set while the file
    // is still empty) gives freed pages back, so none are left at all (review BK-10). Unlike
    // a VACUUM, it needs no second copy of the database in memory (BK2-6).
    let r = conn
        .execute_batch("PRAGMA bak.secure_delete = ON; PRAGMA bak.auto_vacuum = FULL;")
        .map_err(ClientError::from)
        .and_then(|()| {
            conn.query_row("SELECT sqlcipher_export('bak')", [], |_| Ok(()))
                .map_err(ClientError::from)
        })
        // The export copies tables, not the schema version, which the migrations go by.
        .and_then(|()| {
            let v: i64 = conn.query_row("PRAGMA main.user_version", [], |r| r.get(0))?;
            conn.execute_batch(&format!("PRAGMA bak.user_version = {v};"))?;
            Ok(())
        })
        .and_then(|()| strip(conn, "bak"));
    let _ = conn.execute_batch("DETACH DATABASE bak;");
    r
}

impl Actor {
    // ---- re-key invites ----

    /// Gives contacts whose re-key invite from us is missing or running out a new one. Runs
    /// on every retry tick; at most [`PER_ROUND`] contacts a round, in random order.
    pub(super) async fn sync_rekeys(&self) {
        let Ok(s) = self.s() else { return };
        let _ = self.expire_rekeys().await;
        let horizon = i64::try_from(now_secs().saturating_add(RENEW_BEFORE_SECS)).unwrap_or(i64::MAX);
        // Not to contacts we have no session with (they need an invite from us first), nor
        // again soon after a try failed: each try makes an invite with fresh prekeys (BK-2).
        let Ok(mut due) =
            s.db.conn()
                .prepare(
                    "SELECT id FROM contacts WHERE blocked = 0 AND key_warning = 0 AND intro IS NULL
                 AND needs_invite = 0 AND rekey_mine_until < ?1 AND rekey_retry_ms <= ?2",
                )
                .and_then(|mut st| {
                    st.query_map(params![horizon, now_ms()], |r| r.get::<_, i64>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
        else {
            return;
        };
        due.shuffle(&mut rng());
        due.truncate(PER_ROUND);
        for contact in due {
            if self.give_rekey(contact).await.is_err() {
                let _ = s.db.conn().execute(
                    "UPDATE contacts SET rekey_retry_ms = ?2 WHERE id = ?1",
                    params![contact, now_ms().saturating_add(RETRY_AFTER_MS)],
                );
            }
        }
    }

    /// Contacts our restore re-keyed who sent nothing back in [`REKEY_ANSWER_MS`]: their
    /// re-key invite was probably stale, so they never got the new session. They are marked
    /// as needing an invite, with a line in the chat (review BK-5).
    async fn expire_rekeys(&self) -> Result<()> {
        let s = self.s()?;
        let before = now_ms().saturating_sub(REKEY_ANSWER_MS);
        let due: Vec<i64> =
            s.db.conn()
                .prepare("SELECT id FROM contacts WHERE rekey_pending_ms > 0 AND rekey_pending_ms <= ?1")?
                .query_map([before], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
        for contact in due {
            // One transaction per contact, closed the same way as every other (BK2-4).
            self.atomically(async {
                let conn = s.db.conn();
                conn.execute(
                    "UPDATE contacts SET rekey_pending_ms = 0, needs_invite = 1 WHERE id = ?1",
                    [contact],
                )?;
                conn.execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 1, 'restored', 'no-reply', ?2, 'sent')",
                    params![contact, now_ms()],
                )?;
                Ok(())
            })
            .await?;
            self.emit(ChangeKind::Messages, Some(contact));
            self.emit(ChangeKind::Contacts, Some(contact));
        }
        Ok(())
    }

    /// A new re-key invite for one contact, queued to them; the one before is revoked.
    async fn give_rekey(&self, contact: i64) -> Result<()> {
        let s = self.s()?;
        let (address, my_token, old): (String, Vec<u8>, Option<Vec<u8>>) = s.db.conn().query_row(
            "SELECT address, my_token, rekey_mine_id FROM contacts WHERE id = ?1",
            [contact],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let addr = Address::parse(&address).map_err(|_| ClientError::Storage)?;
        // All in one savepoint: an invite that cannot be sealed to the contact is not kept
        // (review BK-2).
        let id = self
            .atomically(async {
                let created = self.new_rekey(&addr, &my_token).await?;
                if let Some(old) = old.as_deref().and_then(|o| <[u8; 16]>::try_from(o).ok()) {
                    revoke_quietly(&s.account, &old).await?;
                }
                s.db.conn().execute(
                    "DELETE FROM messages WHERE contact = ?1 AND mine = 1 AND kind = 'control' AND body = ?2",
                    params![contact, TAG],
                )?;
                let id = self
                    .queue_control_as(contact, Body::Rekey(created.0), None, TAG)
                    .await?;
                s.db.conn().execute(
                    "UPDATE contacts SET rekey_mine_until = ?2, rekey_mine_id = ?3, rekey_retry_ms = 0 WHERE id = ?1",
                    params![
                        contact,
                        i64::try_from(created.1).unwrap_or(i64::MAX),
                        created.2.to_vec()
                    ],
                )?;
                Ok(id)
            })
            .await?;
        self.deliver(id).await;
        Ok(())
    }

    /// A re-key invite for `contact`: the message body, its expiry and its id.
    async fn new_rekey(&self, contact: &Address, my_token: &[u8]) -> Result<(RekeyInvite, u64, [u8; 16])> {
        let s = self.s()?;
        let created = s
            .account
            .create_rekey_invite(
                &mut rng(),
                contact,
                &format!("wss://{}", s.relay_addr),
                s.pin,
                s.mailbox,
                arr32(my_token)?,
                now_secs(),
            )
            .await?;
        let expires = created.invite.expires_at;
        let id = created.invite.id;
        Ok((
            RekeyInvite {
                link: created.invite.to_link(),
                sealed_package: created.sealed_package.clone(),
            },
            expires,
            id,
        ))
    }

    /// A contact's re-key invite for us (inside `process`'s transaction): kept if it is theirs.
    pub(super) fn receive_rekey(&self, contact: i64, address: &Address, r: &RekeyInvite) -> Result<()> {
        let s = self.s()?;
        let Some(theirs) = s.account.contact_identity(address)? else {
            return Ok(());
        };
        if let Some(inv) = check_rekey(r, &theirs.serialize(), &s.pin, now_secs()) {
            // Only a newer invite replaces the one we hold: the relay chooses the order, and
            // an older one is already revoked (review BK-4). Never from a contact under a key
            // warning (BK-15, INV-ID-2).
            s.db.conn().execute(
                "UPDATE contacts SET rekey_link = ?2, rekey_sealed = ?3, rekey_until = ?4, needs_invite = 0
                 WHERE id = ?1 AND key_warning = 0 AND rekey_until < ?4",
                params![
                    contact,
                    r.link,
                    r.sealed_package,
                    i64::try_from(inv.expires_at).unwrap_or(i64::MAX)
                ],
            )?;
        }
        Ok(())
    }

    /// A known contact redeemed our re-key invite: they restored Veil from a backup (inside
    /// `process`'s transaction). Same identity key, so the same contact and safety number;
    /// what we queued for them under the old session can no longer be read, so it is marked
    /// failed, and they get a new re-key invite and our profile again.
    pub(super) async fn receive_restore(
        &self,
        contact: i64,
        address: &Address,
        intro: &ContactIntro,
    ) -> Result<()> {
        let s = self.s()?;
        let conn = s.db.conn();
        // They may have used an older invite of ours, or an ordinary one: the re-key invite we
        // gave them last is not kept for 400 days for nothing (review BK-11).
        let old: Option<Vec<u8>> = conn.query_row(
            "SELECT rekey_mine_id FROM contacts WHERE id = ?1",
            [contact],
            |r| r.get(0),
        )?;
        if let Some(old) = old.as_deref().and_then(|o| <[u8; 16]>::try_from(o).ok()) {
            revoke_quietly(&s.account, &old).await?;
        }
        // An ordinary invite (asked for after a restore that could not reach us): its token
        // is the one they deliver with now, so it becomes ours for them, and the invite is
        // used up, as for a new contact. A re-key invite has no row here (review BK-9).
        let invite_id = intro.invite_id.clone().unwrap_or_default();
        let token: Option<Vec<u8>> = conn
            .query_row("SELECT token FROM invites WHERE id = ?1", [&invite_id], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(token) = token {
            // The token they had before (on the lost device, and in the backup) is withdrawn
            // from the relay (review BK2-8).
            let old: Vec<u8> =
                conn.query_row("SELECT my_token FROM contacts WHERE id = ?1", [contact], |r| {
                    r.get(0)
                })?;
            if old != token {
                Self::queue_token_removal(&s.db, &old)?;
            }
            conn.execute(
                "UPDATE contacts SET my_token = ?2 WHERE id = ?1",
                params![contact, arr32(&token)?.to_vec()],
            )?;
            conn.execute("DELETE FROM invites WHERE id = ?1", [&invite_id])?;
        }
        if let (Ok(mailbox), Ok(token)) = (arr32(&intro.mailbox_id), arr32(&intro.delivery_token)) {
            conn.execute(
                "UPDATE contacts SET mailbox = ?2, token = ?3 WHERE id = ?1",
                params![contact, mailbox.to_vec(), token.to_vec()],
            )?;
        }
        conn.execute(
            "UPDATE contacts SET rekey_mine_until = 0, rekey_mine_id = NULL, profile_sent = NULL WHERE id = ?1",
            [contact],
        )?;
        conn.execute(
            "DELETE FROM messages WHERE contact = ?1 AND mine = 1 AND kind IN ('control', 'mailbox')",
            [contact],
        )?;
        conn.execute(
            "UPDATE messages SET envelope = NULL, status = 'failed' WHERE contact = ?1 AND mine = 1 AND envelope IS NOT NULL",
            [contact],
        )?;
        // Any re-key invite we hold from them died with their old device: their fresh one
        // replaces it whatever the two devices' clocks say (review BK2-9).
        conn.execute(
            "UPDATE contacts SET rekey_link = NULL, rekey_sealed = NULL, rekey_until = 0 WHERE id = ?1",
            [contact],
        )?;
        if let Some(r) = &intro.rekey {
            self.receive_rekey(contact, address, r)?;
        }
        conn.execute(
            "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 0, 'restored', '', ?2, 'received')",
            params![contact, now_ms()],
        )?;
        self.emit(ChangeKind::Messages, Some(contact));
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    // ---- backup ----

    /// Writes a backup to [`BACKUP_FILE`] in the data directory, for the shell to hand to the
    /// user. The first backup makes the backup code and returns it to be written down.
    pub(super) fn create_backup(&self) -> Result<BackupView> {
        let s = self.s()?;
        let code = if let Some(c) = s.db.setting(CODE_KEY)? {
            let c = core::str::from_utf8(&c).map_err(|_| ClientError::Storage)?;
            BackupCode::parse(c).map_err(|_| ClientError::Storage)?
        } else {
            let c = BackupCode::generate(&mut rng());
            s.db.set_setting(CODE_KEY, c.expose().as_bytes())?;
            s.db.set_setting(CODE_SEEN_KEY, &[0])?;
            c
        };
        // Shown until the UI says the user saw it with a saved backup, not just once: a
        // backup that failed or was not saved must not swallow the code (review BK-7).
        let new = s.db.setting(CODE_SEEN_KEY)?.is_none_or(|v| v.as_slice() != [1]);
        let export = self.dir.join(EXPORT_FILE);
        remove_db(&export);
        let mut key = Zeroizing::new([0u8; 32]);
        rand::Rng::fill(&mut rng(), &mut key[..]);
        let r = export_to(&s.db, &export, &key).and_then(|()| {
            let tmp = self.dir.join(format!("{BACKUP_FILE}.tmp"));
            let db_file = std::fs::File::open(&export).map_err(|_| ClientError::Storage)?;
            let out = std::fs::File::create(&tmp).map_err(|_| ClientError::Storage)?;
            let mut w = std::io::BufWriter::new(out);
            bak::seal(
                &mut rng(),
                &code,
                (&key[..]).chain(std::io::BufReader::new(db_file)),
                &mut w,
            )?;
            let out = w.into_inner().map_err(|_| ClientError::Storage)?;
            out.sync_all().map_err(|_| ClientError::Storage)?;
            let bytes = out
                .metadata()
                .map(|m| m.len())
                .map_err(|_| ClientError::Storage)?;
            drop(out);
            // One a restore would refuse is not made at all (review BK-8).
            if bytes > MAX_BACKUP {
                let _ = std::fs::remove_file(&tmp);
                return Err(ClientError::BackupTooLarge);
            }
            std::fs::rename(&tmp, self.dir.join(BACKUP_FILE)).map_err(|_| ClientError::Storage)?;
            Ok(bytes)
        });
        remove_db(&export);
        if r.is_err() {
            let _ = std::fs::remove_file(self.dir.join(format!("{BACKUP_FILE}.tmp")));
        }
        let bytes = r?;
        Ok(BackupView {
            code: new.then(|| code.display().to_string()),
            bytes,
        })
    }

    /// The user saw the backup code with a saved backup: later backups no longer show it.
    pub(super) fn backup_code_seen(&self) -> Result<()> {
        let s = self.s()?;
        if s.db.setting(CODE_KEY)?.is_some() {
            s.db.set_setting(CODE_SEEN_KEY, &[1])?;
        }
        Ok(())
    }

    /// Forgets the backup code: the next backup makes and shows a new one. Backups made
    /// before still open with the old code only (review BK-14).
    pub(super) fn new_backup_code(&self) -> Result<()> {
        let s = self.s()?;
        s.db.conn().execute(
            "DELETE FROM settings WHERE k IN (?1, ?2)",
            params![CODE_KEY, CODE_SEEN_KEY],
        )?;
        Ok(())
    }

    /// The backup code, for "Show my backup code" (after the user's PIN or password).
    pub(super) fn backup_code(&self) -> Result<Option<String>> {
        Ok(self
            .s()?
            .db
            .setting(CODE_KEY)?
            .and_then(|c| BackupCode::parse(core::str::from_utf8(&c).ok()?).ok())
            .map(|c| c.display().to_string()))
    }

    // ---- restore ----

    /// Opens a backup into [`RESTORE_FILE`] (still encrypted, under the backup's own database
    /// key) and returns that key.
    pub(super) fn unpack(&self, input: &RestoreInput) -> Result<Zeroizing<[u8; 32]>> {
        let code = BackupCode::parse(&input.code).map_err(|_| ClientError::BackupCode)?;
        let path = self.dir.join(RESTORE_FILE);
        remove_db(&path);
        let mut file =
            std::io::BufWriter::new(std::fs::File::create(&path).map_err(|_| ClientError::Storage)?);
        let mut key = Zeroizing::new([0u8; 32]);
        let mut have = 0usize;
        let r = bak::open(&code, &input.backup[..], |chunk| {
            use std::io::Write as _;
            let mut rest = chunk;
            // The first 32 bytes are the exported database's key, kept in memory only.
            if let Some(need) = 32usize.checked_sub(have).filter(|n| *n > 0) {
                let take = rest.len().min(need);
                let (k, more) = rest.split_at(take);
                let end = have.checked_add(take).ok_or(veil_core::CoreError::Storage)?;
                key.get_mut(have..end)
                    .ok_or(veil_core::CoreError::Storage)?
                    .copy_from_slice(k);
                have = end;
                rest = more;
            }
            file.write_all(rest).map_err(|_| veil_core::CoreError::Storage)
        });
        let flushed = file
            .into_inner()
            .map_err(|_| ClientError::Storage)
            .and_then(|f| f.sync_all().map_err(|_| ClientError::Storage));
        match (r, flushed) {
            (Ok(()), Ok(())) if have == 32 => Ok(key),
            // The marker did not open: the code is wrong. Anything else is damage (next arm).
            (Err(veil_core::CoreError::AuthFailed), _) => {
                remove_db(&path);
                Err(ClientError::BackupCode)
            }
            _ => {
                remove_db(&path);
                Err(ClientError::BackupInvalid)
            }
        }
    }

    /// Finishes a restore if re-keying is still due (right after it, or at the next unlock if
    /// Veil stopped part way; review BK2-2). The flag goes once every contact was handled.
    pub(super) async fn finish_restore(&self) {
        let Ok(s) = self.s() else { return };
        let Ok(Some(due)) = s.db.setting(REKEY_DUE_KEY) else {
            return;
        };
        // A malformed flag handles everyone again rather than no one.
        let since = <[u8; 8]>::try_from(due.as_slice()).map_or(-1, i64::from_le_bytes);
        if self.rekey_all(since).await.is_ok() {
            let _ =
                s.db.conn()
                    .execute("DELETE FROM settings WHERE k = ?1", [REKEY_DUE_KEY]);
        }
    }

    /// How the restore went, from the database.
    pub(super) fn restore_view(&self) -> Result<RestoreView> {
        let s = self.s()?;
        let count = |q: &str| -> Result<u32> {
            let n: i64 = s.db.conn().query_row(q, [], |r| r.get(0))?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        };
        Ok(RestoreView {
            unlocked: true,
            contacts: count("SELECT count(*) FROM contacts WHERE blocked = 0")?,
            need_invite: count("SELECT count(*) FROM contacts WHERE blocked = 0 AND needs_invite = 1")?,
            finished: s.db.setting(REKEY_DUE_KEY)?.is_none(),
        })
    }

    /// After a restore: a new session with every contact who gave us a re-key invite (the
    /// introduction carries a fresh re-key invite for them); the others are marked as needing
    /// a new invite. Every chat says what happened. Contacts already handled by this restore
    /// (a restored line with a row id above `since`) are skipped, so running it again is safe.
    async fn rekey_all(&self, since: i64) -> Result<()> {
        let s = self.s()?;
        let rows: Vec<RekeyRow> =
            s.db.conn()
                .prepare(
                    // A contact under a key warning is not re-keyed (review BK-15, INV-ID-2):
                    // their invite is dropped below, and they need a new one.
                    "SELECT id, address, my_token,
                       CASE WHEN key_warning = 0 THEN rekey_link END,
                       CASE WHEN key_warning = 0 THEN rekey_sealed END
                     FROM contacts c WHERE blocked = 0 AND NOT EXISTS (SELECT 1 FROM messages m
                       WHERE m.contact = c.id AND m.kind = 'restored' AND m.mine = 1 AND m.id > ?1)",
                )?
                .query_map([since], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
        for (contact, address, my_token, link, sealed) in rows {
            #[cfg(feature = "test-hooks")]
            if self.take_rekey_budget() {
                return Err(ClientError::Storage);
            }
            let ok = match (link, sealed) {
                (Some(link), Some(sealed)) => self
                    .rekey_one(contact, &address, &my_token, &link, &sealed)
                    .await
                    .is_ok(),
                _ => false,
            };
            // Best effort: the restore is done, and one contact's row is no reason to stop
            // (review BK-6). A contact reached got the line with the re-key itself.
            if !ok {
                let _ = mark_unreached(s.db.conn(), contact);
            }
        }
        self.emit(ChangeKind::Contacts, None);
        Ok(())
    }

    async fn rekey_one(
        &self,
        contact: i64,
        address: &str,
        my_token: &[u8],
        link: &str,
        sealed: &[u8],
    ) -> Result<()> {
        let s = self.s()?;
        let addr = Address::parse(address).map_err(|_| ClientError::Storage)?;
        let theirs = s.account.contact_identity(&addr)?.ok_or(ClientError::Storage)?;
        let r = RekeyInvite {
            link: link.to_owned(),
            sealed_package: sealed.to_vec(),
        };
        let invite =
            check_rekey(&r, &theirs.serialize(), &s.pin, now_secs()).ok_or(ClientError::InviteInvalid)?;
        // One savepoint: a failed redemption leaves no stray re-key invite behind either.
        let row = self
            .atomically(async {
                let (rekey, until, id) = self.new_rekey(&addr, my_token).await?;
                let fields = IntroFields {
                    mailbox_id: s.mailbox,
                    delivery_token: arr32(my_token)?,
                    display_name: (!s.name.is_empty()).then(|| s.name.clone()),
                    rekey: Some(rekey),
                };
                let red = s
                    .account
                    .redeem_invite(&mut rng(), &invite, sealed, fields, now_secs())
                    .await?;
                if red.contact != addr {
                    return Err(ClientError::InviteInvalid);
                }
                s.db.conn().execute(
                    "UPDATE contacts SET rekey_link = NULL, rekey_sealed = NULL, rekey_until = 0, needs_invite = 0,
                       rekey_mine_until = ?2, rekey_mine_id = ?3, rekey_pending_ms = ?4 WHERE id = ?1",
                    params![contact, i64::try_from(until).unwrap_or(i64::MAX), id.to_vec(), now_ms()],
                )?;
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status, envelope)
                     VALUES (?1, 1, 'control', ?2, ?3, 'sending', ?4)",
                    params![contact, RESTORE_TAG, now_ms(), red.envelope],
                )?;
                let row = s.db.conn().last_insert_rowid();
                // The chat line in the same transaction, which also marks this contact as
                // handled if the restore has to run again (BK2-2).
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 1, 'restored', '', ?2, 'sent')",
                    params![contact, now_ms()],
                )?;
                Ok(row)
            })
            .await?;
        self.deliver(row).await;
        Ok(())
    }
}

/// A contact our restore could not reach: marked, with a line in their chat.
fn mark_unreached(conn: &rusqlite::Connection, contact: i64) -> Result<()> {
    conn.execute("UPDATE contacts SET needs_invite = 1 WHERE id = ?1", [contact])?;
    conn.execute(
        "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 1, 'restored', 'needs-invite', ?2, 'sent')",
        params![contact, now_ms()],
    )?;
    Ok(())
}

/// Revokes one of our invites; one already gone (used, expired and swept) is not an error
/// (review BK-11), or a single missing record would block every later renewal.
async fn revoke_quietly(
    account: &veil_core::account::Account<crate::db::SqlBackend>,
    id: &[u8; 16],
) -> Result<()> {
    match account.revoke_invite(id).await {
        Ok(()) | Err(veil_core::CoreError::InviteInvalid) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
