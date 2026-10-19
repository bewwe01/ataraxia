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
  envelope BLOB
);
CREATE INDEX IF NOT EXISTS messages_by_contact ON messages(contact, id);
CREATE TABLE IF NOT EXISTS invites (id BLOB PRIMARY KEY, token BLOB NOT NULL, expires INTEGER NOT NULL) WITHOUT ROWID;
";

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
            "PRAGMA temp_store = MEMORY; PRAGMA cipher_memory_security = ON; PRAGMA foreign_keys = ON;",
        )?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|_| ClientError::WrongPassphrase)?;
        conn.execute_batch(SCHEMA)?;
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

    fn apply(&mut self, batch: &[Write]) -> veil_core::Result<()> {
        let tx = self
            .0
            .conn()
            .unchecked_transaction()
            .map_err(|_| veil_core::CoreError::Storage)?;
        for (k, v) in batch {
            let r = match v {
                Some(v) => tx.execute(
                    "INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)",
                    params![k, v.as_slice()],
                ),
                None => tx.execute("DELETE FROM kv WHERE k = ?1", [k]),
            };
            r.map_err(|_| veil_core::CoreError::Storage)?;
        }
        tx.commit().map_err(|_| veil_core::CoreError::Storage)
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
}
