//! The local store: one `SQLCipher` database (ADR-0005), keyed by the vault's DB key. It holds the
//! protocol state (`kv`, behind [`veil_core::store::KvBackend`]) and the app tables (contacts,
//! messages, settings, invites). Nothing is written outside it (INV-REST-1).

use std::path::Path;
use std::rc::Rc;

use rusqlite::{Connection, OptionalExtension as _, params};
use veil_core::store::{KvBackend, Write};
use zeroize::Zeroizing;

use crate::{ClientError, Result};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kv (k BLOB PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  mailbox BLOB NOT NULL,
  token BLOB NOT NULL,
  my_token BLOB NOT NULL,
  intro BLOB,
  unread INTEGER NOT NULL DEFAULT 0,
  added_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  contact INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
  mine INTEGER NOT NULL,
  body TEXT NOT NULL,
  at_ms INTEGER NOT NULL,
  status TEXT NOT NULL,
  envelope BLOB,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS messages_by_contact ON messages(contact, id);
CREATE TABLE IF NOT EXISTS invites (id BLOB PRIMARY KEY, token BLOB NOT NULL, expires INTEGER NOT NULL) WITHOUT ROWID;
";

/// Schema changes after the first release, in order. `PRAGMA user_version` counts how many
/// have been applied; each runs once, in a transaction with the version bump.
const MIGRATIONS: &[&str] = &[
    // 1: blocking, disappearing messages, the key-change warning, receipts.
    "ALTER TABLE contacts ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN timer_secs INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN timer_peer_ms INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN mailbox_peer_ms INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN key_warning INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text';
     ALTER TABLE messages ADD COLUMN msg_id BLOB;
     ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER;
     ALTER TABLE messages ADD COLUMN receipt INTEGER NOT NULL DEFAULT 0;
     CREATE INDEX messages_by_expiry ON messages(expires_at_ms) WHERE expires_at_ms IS NOT NULL;
     CREATE INDEX messages_by_msg_id ON messages(contact, msg_id);
     CREATE TABLE token_removals (hash BLOB PRIMARY KEY) WITHOUT ROWID;",
    // 2: replies, edits, remote deletes and reactions (milestone 2).
    "ALTER TABLE messages ADD COLUMN reply_to BLOB;
     ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0;
     CREATE TABLE reactions (
       message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
       mine INTEGER NOT NULL,
       emoji TEXT NOT NULL,
       PRIMARY KEY (message, mine)
     ) WITHOUT ROWID;",
    // 3: photos, files and voice notes (milestone 3). The file and its ciphertext chunks
    // stay inside SQLCipher; they go with their message.
    "CREATE TABLE attachments (
       message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
       kind TEXT NOT NULL,
       mime TEXT NOT NULL,
       name TEXT,
       size INTEGER NOT NULL,
       duration_ms INTEGER,
       waveform BLOB,
       thumbnail BLOB,
       blob_id BLOB NOT NULL,
       att_key BLOB NOT NULL,
       nonce_prefix BLOB NOT NULL,
       sha256 BLOB NOT NULL,
       padded_size INTEGER NOT NULL,
       total_chunks INTEGER NOT NULL,
       next_chunk INTEGER NOT NULL DEFAULT 0,
       state TEXT NOT NULL,
       upload_token BLOB,
       attempts INTEGER NOT NULL DEFAULT 0,
       -- Backoff: a failing transfer waits and does not hold up the others (review M3-4).
       next_attempt_ms INTEGER NOT NULL DEFAULT 0,
       -- Automatic fresh re-uploads after the relay refused the upload token (review M3-7).
       restarts INTEGER NOT NULL DEFAULT 0,
       -- Shown, played or saved at least once (review M3R2-5).
       opened INTEGER NOT NULL DEFAULT 0,
       timer_secs INTEGER,
       data BLOB
     );
     CREATE INDEX attachments_pending ON attachments(state) WHERE state IN ('upload', 'download');
     CREATE TABLE attachment_chunks (
       message INTEGER NOT NULL REFERENCES attachments(message) ON DELETE CASCADE,
       idx INTEGER NOT NULL,
       data BLOB NOT NULL,
       PRIMARY KEY (message, idx)
     );",
];

fn migrate(conn: &Connection) -> Result<()> {
    let have: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (n, sql) in MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(n)
            .map_err(|_| ClientError::Storage)?
            .saturating_add(1);
        if version <= have {
            continue;
        }
        conn.execute_batch(&format!("BEGIN; {sql} PRAGMA user_version = {version}; COMMIT;"))
            .inspect_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
            })?;
    }
    Ok(())
}

/// An open, unlocked database. Cheap to clone (shared connection; single-threaded actor).
#[derive(Clone)]
pub struct Db(Rc<Connection>);

impl core::fmt::Debug for Db {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Db")
    }
}

fn hex(b: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(b.len().saturating_mul(2)));
    for byte in b {
        for nibble in [byte >> 4, byte & 0x0F] {
            s.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    s
}

impl Db {
    /// Opens (or creates) the database with a raw 256-bit key. A wrong key fails here, at the
    /// first read, not later.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;
        // SQLCipher logs to stderr/logcat by default; nothing from the store goes to logs.
        conn.execute_batch("PRAGMA cipher_log_level = NONE;")?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex(key).as_str()));
        conn.execute_batch(&pragma)?;
        // Never spill decrypted pages to temp files; wipe freed memory (SQLCipher defaults
        // already zero pages, this makes it explicit).
        conn.execute_batch(
            "PRAGMA temp_store = MEMORY; PRAGMA cipher_memory_security = ON; PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;",
        )?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|_| ClientError::WrongPassphrase)?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self(Rc::new(conn)))
    }

    pub fn conn(&self) -> &Connection {
        &self.0
    }

    pub fn setting(&self, k: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .0
            .query_row("SELECT v FROM settings WHERE k = ?1", [k], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?
            .map(Zeroizing::new))
    }

    pub fn set_setting(&self, k: &str, v: &[u8]) -> Result<()> {
        self.0.execute(
            "INSERT OR REPLACE INTO settings (k, v) VALUES (?1, ?2)",
            params![k, v],
        )?;
        Ok(())
    }
}

/// [`KvBackend`] over the `kv` table. Every `apply` is one `SQLite` transaction (INV-STATE-1).
pub struct SqlBackend(pub Db);

impl KvBackend for SqlBackend {
    fn get(&self, key: &[u8]) -> veil_core::Result<Option<Zeroizing<Vec<u8>>>> {
        self.0
            .conn()
            .query_row("SELECT v FROM kv WHERE k = ?1", [key], |r| r.get::<_, Vec<u8>>(0))
            .optional()
            .map(|v| v.map(Zeroizing::new))
            .map_err(|_| veil_core::CoreError::Storage)
    }

    fn keys_with_prefix(&self, prefix: &[u8]) -> veil_core::Result<Vec<Vec<u8>>> {
        let mut stmt = self
            .0
            .conn()
            .prepare("SELECT k FROM kv WHERE substr(k, 1, ?2) = ?1")
            .map_err(|_| veil_core::CoreError::Storage)?;
        let len = i64::try_from(prefix.len()).map_err(|_| veil_core::CoreError::Storage)?;
        let rows = stmt
            .query_map(params![prefix, len], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| veil_core::CoreError::Storage)?;
        rows.collect::<core::result::Result<Vec<_>, _>>()
            .map_err(|_| veil_core::CoreError::Storage)
    }

    /// A savepoint rather than a transaction, so the batch nests inside an outer savepoint
    /// when the client commits the core's state together with its own rows (review P4-6).
    fn apply(&mut self, batch: &[Write]) -> veil_core::Result<()> {
        let conn = self.0.conn();
        conn.execute_batch("SAVEPOINT kv_apply")
            .map_err(|_| veil_core::CoreError::Storage)?;
        let r = batch.iter().try_for_each(|(k, v)| {
            match v {
                Some(v) => conn.execute(
                    "INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)",
                    params![k, v.as_slice()],
                ),
                None => conn.execute("DELETE FROM kv WHERE k = ?1", [k]),
            }
            .map(|_| ())
        });
        let end = if r.is_ok() {
            "RELEASE kv_apply"
        } else {
            "ROLLBACK TO kv_apply; RELEASE kv_apply"
        };
        if conn.execute_batch(end).is_err() {
            // Leave no savepoint behind; an enclosing `atomically` rolls back the rest.
            let _ = conn.execute_batch("ROLLBACK TO kv_apply; RELEASE kv_apply");
            return Err(veil_core::CoreError::Storage);
        }
        r.map_err(|_| veil_core::CoreError::Storage)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_at_rest_and_wrong_key_refused() {
        let dir = std::env::temp_dir().join(format!("veil-db-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("veil.db");
        let key = [7u8; 32];
        {
            let db = Db::open(&path, &key).unwrap();
            db.set_setting("canary", b"plaintext-canary-7e11").unwrap();
            let mut b = SqlBackend(db);
            b.apply(&[(b"k1".to_vec(), Some(Zeroizing::new(b"kv-canary-7e11".to_vec())))])
                .unwrap();
            assert_eq!(b.get(b"k1").unwrap().unwrap().as_slice(), b"kv-canary-7e11");
            assert_eq!(b.keys_with_prefix(b"k").unwrap(), vec![b"k1".to_vec()]);
        }
        let raw = std::fs::read(&path).unwrap();
        for needle in [&b"canary-7e11"[..], b"SQLite format", b"settings"] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle),
                "plaintext on disk"
            );
        }
        assert_eq!(
            Db::open(&path, &[8u8; 32]).unwrap_err(),
            ClientError::WrongPassphrase
        );
        let db = Db::open(&path, &key).unwrap();
        assert_eq!(
            db.setting("canary").unwrap().unwrap().as_slice(),
            b"plaintext-canary-7e11"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A database from before the migrations keeps its rows and gains the new columns; opening
    /// again changes nothing.
    #[test]
    fn migrates_an_old_database_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("veil.db");
        let key = [5u8; 32];
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex(&key).as_str()))
                .unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            conn.execute(
                "INSERT INTO contacts (address, name, mailbox, token, my_token, added_ms)
                 VALUES ('a', 'Old', x'00', x'00', x'00', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO messages (contact, mine, body, at_ms, status) VALUES (1, 0, 'hi', 1, 'received')",
                [],
            )
            .unwrap();
        }
        for _ in 0..2 {
            let db = Db::open(&path, &key).unwrap();
            let c = db.conn();
            let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(usize::try_from(v).unwrap(), MIGRATIONS.len());
            let row: (String, bool, u32, bool) = c
                .query_row(
                    "SELECT name, blocked, timer_secs, key_warning FROM contacts",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(row, ("Old".into(), false, 0, false));
            let kind: String = c
                .query_row("SELECT kind FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(kind, "text");
            let secure: i64 = c.query_row("PRAGMA secure_delete", [], |r| r.get(0)).unwrap();
            assert_eq!(secure, 1);
        }
    }

    /// A preview.4 database (version 1) gains the milestone 2 schema, and reactions go with
    /// their message (review M2-9).
    #[test]
    fn migrates_a_version_1_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("veil.db");
        let key = [6u8; 32];
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex(&key).as_str()))
                .unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            conn.execute_batch(&format!(
                "BEGIN; {} PRAGMA user_version = 1; COMMIT;",
                MIGRATIONS[0]
            ))
            .unwrap();
            conn.execute(
                "INSERT INTO contacts (address, name, mailbox, token, my_token, added_ms)
                 VALUES ('a', 'Old', x'00', x'00', x'00', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO messages (contact, mine, body, at_ms, status, msg_id) VALUES (1, 0, 'hi', 1, 'received', x'01')",
                [],
            )
            .unwrap();
        }
        let db = Db::open(&path, &key).unwrap();
        let c = db.conn();
        let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(usize::try_from(v).unwrap(), MIGRATIONS.len());
        let row: (String, bool, bool, Option<Vec<u8>>) = c
            .query_row("SELECT body, edited, deleted, reply_to FROM messages", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(row, ("hi".into(), false, false, None));
        c.execute(
            "INSERT INTO reactions (message, mine, emoji) VALUES (1, 1, 'x')",
            [],
        )
        .unwrap();
        c.execute("DELETE FROM messages WHERE id = 1", []).unwrap();
        let left: i64 = c
            .query_row("SELECT count(*) FROM reactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "reactions cascade with their message");
    }

    /// `apply` nests inside an outer savepoint: the outer rollback undoes it, the outer release
    /// commits it, and nothing is left open either way (review P4-6, P4R2-2).
    #[test]
    fn apply_nests_in_an_outer_savepoint() {
        let dir = std::env::temp_dir().join(format!("veil-db-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("veil.db"), &[9u8; 32]).unwrap();
        let mut b = SqlBackend(db.clone());
        let w = |k: &[u8]| vec![(k.to_vec(), Some(Zeroizing::new(b"v".to_vec())))];

        db.conn().execute_batch("SAVEPOINT outer_sp").unwrap();
        b.apply(&w(b"rolled-back")).unwrap();
        db.set_setting("row", b"x").unwrap();
        db.conn()
            .execute_batch("ROLLBACK TO outer_sp; RELEASE outer_sp")
            .unwrap();
        assert!(db.conn().is_autocommit());
        assert!(b.get(b"rolled-back").unwrap().is_none());
        assert!(db.setting("row").unwrap().is_none());

        db.conn().execute_batch("SAVEPOINT outer_sp").unwrap();
        b.apply(&w(b"kept")).unwrap();
        db.conn().execute_batch("RELEASE outer_sp").unwrap();
        assert!(db.conn().is_autocommit());
        assert!(b.get(b"kept").unwrap().is_some());

        // Standalone, apply is its own transaction.
        b.apply(&w(b"alone")).unwrap();
        assert!(db.conn().is_autocommit());
        drop((b, db));
        let db = Db::open(&dir.join("veil.db"), &[9u8; 32]).unwrap();
        let b = SqlBackend(db);
        assert!(b.get(b"kept").unwrap().is_some() && b.get(b"alone").unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
