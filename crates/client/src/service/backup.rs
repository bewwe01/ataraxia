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
use rusqlite::params;
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
/// The tag on a queued re-key invite, so a newer one replaces it.
const TAG: &str = "rekey";
/// The tag on the introduction a restore sends each contact.
const RESTORE_TAG: &str = "restore";
/// A re-key invite is replaced when it has less than this left.
const RENEW_BEFORE_SECS: u64 = 30 * 24 * 3600;
/// Contacts given a new re-key invite per round (as for profiles).
const PER_ROUND: usize = 4;

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
}

/// A path inside an SQL string literal.
fn sql_path(p: &Path) -> Result<String> {
    Ok(p.to_str().ok_or(ClientError::Storage)?.replace('\'', "''"))
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
         UPDATE {schema}.contacts SET rekey_mine_until = 0, rekey_mine_id = NULL, profile_sent = NULL, intro = NULL;"
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
    let r = conn
        .query_row("SELECT sqlcipher_export('bak')", [], |_| Ok(()))
        .map_err(ClientError::from)
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
        let horizon = i64::try_from(now_secs().saturating_add(RENEW_BEFORE_SECS)).unwrap_or(i64::MAX);
        let Ok(mut due) =
            s.db.conn()
                .prepare(
                    "SELECT id FROM contacts WHERE blocked = 0 AND key_warning = 0 AND intro IS NULL
                 AND rekey_mine_until < ?1",
                )
                .and_then(|mut st| {
                    st.query_map([horizon], |r| r.get::<_, i64>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
        else {
            return;
        };
        due.shuffle(&mut rng());
        due.truncate(PER_ROUND);
        for contact in due {
            let _ = self.give_rekey(contact).await;
        }
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
        let created = self.new_rekey(&addr, &my_token).await?;
        let id = self
            .atomically(async {
                if let Some(old) = old.as_deref().and_then(|o| <[u8; 16]>::try_from(o).ok()) {
                    s.account.revoke_invite(&old).await?;
                }
                s.db.conn().execute(
                    "DELETE FROM messages WHERE contact = ?1 AND mine = 1 AND kind = 'control' AND body = ?2",
                    params![contact, TAG],
                )?;
                let id = self
                    .queue_control_as(contact, Body::Rekey(created.0), None, TAG)
                    .await?;
                s.db.conn().execute(
                    "UPDATE contacts SET rekey_mine_until = ?2, rekey_mine_id = ?3 WHERE id = ?1",
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
        if check_rekey(r, &theirs.serialize(), &s.pin, now_secs()).is_some() {
            s.db.conn().execute(
                "UPDATE contacts SET rekey_link = ?2, rekey_sealed = ?3, needs_invite = 0 WHERE id = ?1",
                params![contact, r.link, r.sealed_package],
            )?;
        }
        Ok(())
    }

    /// A known contact redeemed our re-key invite: they restored Veil from a backup (inside
    /// `process`'s transaction). Same identity key, so the same contact and safety number;
    /// what we queued for them under the old session can no longer be read, so it is marked
    /// failed, and they get a new re-key invite and our profile again.
    pub(super) fn receive_restore(
        &self,
        contact: i64,
        address: &Address,
        intro: &ContactIntro,
    ) -> Result<()> {
        let s = self.s()?;
        let conn = s.db.conn();
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
        let (code, new) = if let Some(c) = s.db.setting(CODE_KEY)? {
            let c = core::str::from_utf8(&c).map_err(|_| ClientError::Storage)?;
            (BackupCode::parse(c).map_err(|_| ClientError::Storage)?, false)
        } else {
            let c = BackupCode::generate(&mut rng());
            s.db.set_setting(CODE_KEY, c.expose().as_bytes())?;
            (c, true)
        };
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
            drop(out);
            std::fs::rename(&tmp, self.dir.join(BACKUP_FILE)).map_err(|_| ClientError::Storage)?;
            std::fs::metadata(self.dir.join(BACKUP_FILE))
                .map(|m| m.len())
                .map_err(|_| ClientError::Storage)
        });
        remove_db(&export);
        let bytes = r?;
        Ok(BackupView {
            code: new.then(|| code.display().to_string()),
            bytes,
        })
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

    /// After a restore: a new session with every contact who gave us a re-key invite (the
    /// introduction carries a fresh re-key invite for them); the others are marked as needing
    /// a new invite. Every chat says what happened.
    pub(super) async fn rekey_all(&self) -> Result<RestoreView> {
        let s = self.s()?;
        let rows: Vec<RekeyRow> =
            s.db.conn()
                .prepare(
                    "SELECT id, address, my_token, rekey_link, rekey_sealed FROM contacts WHERE blocked = 0",
                )?
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
        let mut view = RestoreView {
            contacts: 0,
            need_invite: 0,
        };
        for (contact, address, my_token, link, sealed) in rows {
            view.contacts = view.contacts.saturating_add(1);
            let ok = match (link, sealed) {
                (Some(link), Some(sealed)) => self
                    .rekey_one(contact, &address, &my_token, &link, &sealed)
                    .await
                    .is_ok(),
                _ => false,
            };
            let conn = s.db.conn();
            if !ok {
                view.need_invite = view.need_invite.saturating_add(1);
                conn.execute("UPDATE contacts SET needs_invite = 1 WHERE id = ?1", [contact])?;
            }
            conn.execute(
                "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 1, 'restored', ?2, ?3, 'sent')",
                params![contact, if ok { "" } else { "needs-invite" }, now_ms()],
            )?;
        }
        self.emit(ChangeKind::Contacts, None);
        Ok(view)
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
                    "UPDATE contacts SET rekey_link = NULL, rekey_sealed = NULL, needs_invite = 0,
                       rekey_mine_until = ?2, rekey_mine_id = ?3 WHERE id = ?1",
                    params![contact, i64::try_from(until).unwrap_or(i64::MAX), id.to_vec()],
                )?;
                s.db.conn().execute(
                    "INSERT INTO messages (contact, mine, kind, body, at_ms, status, envelope)
                     VALUES (?1, 1, 'control', ?2, ?3, 'sending', ?4)",
                    params![contact, RESTORE_TAG, now_ms(), red.envelope],
                )?;
                Ok(s.db.conn().last_insert_rowid())
            })
            .await?;
        self.deliver(row).await;
        Ok(())
    }
}
