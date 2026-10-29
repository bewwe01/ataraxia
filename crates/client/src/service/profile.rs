//! Profiles (milestone 4.5, ADR-0020): the user's name, a one-line status and a picture, sent
//! to contacts end-to-end encrypted as `Content::Profile`, never to the relay in the clear.
//! The user chooses who sees the picture (all contacts, verified contacts or nobody, and can
//! hide it from one contact). A contact's own name never replaces a nickname the user chose,
//! nor takes the name of another contact (INV-ID-2 relies on names to warn about key changes).

use base64::Engine as _;
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use veil_core::content::{Body, MAX_PICTURE_LEN, Profile};

use super::look::image_mime;
use super::{Actor, ChangeKind, clean_name, clean_name_long, name_key};
use crate::{ClientError, Result, now_ms};

pub const MAX_STATUS: usize = 140;
const STATUS_KEY: &str = "profile.status";
const VISIBILITY_KEY: &str = "profile.visibility";
const REV_KEY: &str = "profile.rev";
/// Our own picture's owner in `pictures` (contact ids are > 0).
const ME: i64 = 0;
/// The tag on a queued profile message, so a newer one replaces it.
const TAG: &str = "profile";

/// Who sees the user's picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PictureVisibility {
    All,
    Verified,
    Nobody,
}

impl PictureVisibility {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Verified => "verified",
            Self::Nobody => "nobody",
        }
    }
    fn parse(s: &[u8]) -> Self {
        match s {
            b"all" => Self::All,
            b"verified" => Self::Verified,
            // Anything unknown shows the picture to nobody.
            _ => Self::Nobody,
        }
    }
}

/// The user's own profile, for Settings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub name: String,
    pub status: String,
    /// Changes whenever the picture does (for the webview's cache); `None` without one.
    pub picture: Option<String>,
    pub visibility: PictureVisibility,
}

/// A picture from the webview: base64 of a JPEG, PNG or WebP of at most [`MAX_PICTURE_LEN`].
fn decode_picture(b64: &str) -> Result<(&'static str, Vec<u8>)> {
    if b64.len() > MAX_PICTURE_LEN / 3 * 4 + 4 {
        return Err(ClientError::TooLarge);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| ClientError::BadInput)?;
    if bytes.len() > MAX_PICTURE_LEN {
        return Err(ClientError::TooLarge);
    }
    let mime = image_mime(&bytes).ok_or(ClientError::BadInput)?;
    Ok((mime, bytes))
}

/// The cache key the webview gets for a picture row.
fn token(local: bool, rev: i64) -> String {
    format!("{}{rev}", if local { "l" } else { "p" })
}

/// What one contact gets from us.
struct Outgoing {
    name: String,
    status: String,
    picture: Option<Vec<u8>>,
}

impl Outgoing {
    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        for part in [self.name.as_bytes(), self.status.as_bytes()] {
            h.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            h.update(part);
        }
        match &self.picture {
            Some(p) => {
                h.update([1]);
                h.update(p);
            }
            None => h.update([0]),
        }
        h.finalize().to_vec()
    }
}

impl Actor {
    fn setting_str(&self, key: &str) -> Result<String> {
        let v = self.s()?.db.setting(key)?.unwrap_or_default();
        Ok(String::from_utf8(v.to_vec()).unwrap_or_default())
    }

    fn visibility(&self) -> Result<PictureVisibility> {
        // Nobody until the user chooses.
        Ok(self
            .s()?
            .db
            .setting(VISIBILITY_KEY)?
            .map_or(PictureVisibility::Nobody, |v| PictureVisibility::parse(&v)))
    }

    /// A new profile revision: later than the last, and than the clock.
    fn bump_rev(&self) -> Result<u64> {
        let last: u64 = self.setting_str(REV_KEY)?.parse().unwrap_or(0);
        let rev = last.saturating_add(1).max(u64::try_from(now_ms()).unwrap_or(0));
        self.s()?.db.set_setting(REV_KEY, rev.to_string().as_bytes())?;
        Ok(rev)
    }

    fn picture_row(&self, owner: i64, local: bool) -> Result<Option<(String, Vec<u8>, i64)>> {
        Ok(self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT mime, data, rev FROM pictures WHERE owner = ?1 AND local = ?2",
                params![owner, local],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    pub(super) fn profile(&self) -> Result<ProfileView> {
        Ok(ProfileView {
            name: self.s()?.name.clone(),
            status: self.setting_str(STATUS_KEY)?,
            picture: self.picture_row(ME, false)?.map(|(_, _, rev)| token(false, rev)),
            visibility: self.visibility()?,
        })
    }

    /// Changes the user's name and status, and tells contacts.
    pub(super) async fn set_profile(&mut self, name: &str, status: &str) -> Result<()> {
        let name = clean_name(name);
        let status = clean_name_long(status, MAX_STATUS);
        {
            let s = self.s()?;
            s.db.set_setting("name", name.as_bytes())?;
            s.db.set_setting(STATUS_KEY, status.as_bytes())?;
        }
        if let Some(s) = self.session.as_mut() {
            s.name = name;
        }
        self.emit(ChangeKind::Contacts, None);
        self.sync_profiles(None).await;
        Ok(())
    }

    /// Sets (base64) or removes (`None`) the user's picture, and tells contacts who see it.
    pub(super) async fn set_my_picture(&self, picture: Option<String>) -> Result<()> {
        let rev = i64::try_from(self.bump_rev()?).unwrap_or(i64::MAX);
        self.store_picture(ME, false, picture.as_deref(), rev)?;
        self.emit(ChangeKind::Contacts, None);
        self.sync_profiles(None).await;
        Ok(())
    }

    pub(super) async fn set_picture_visibility(&self, v: PictureVisibility) -> Result<()> {
        self.s()?.db.set_setting(VISIBILITY_KEY, v.as_str().as_bytes())?;
        self.emit(ChangeKind::Contacts, None);
        self.sync_profiles(None).await;
        Ok(())
    }

    /// Hides the user's picture from one contact (or shows it again, as the setting allows).
    pub(super) async fn set_picture_hidden(&self, contact: i64, hidden: bool) -> Result<()> {
        let n = self.s()?.db.conn().execute(
            "UPDATE contacts SET picture_hidden = ?2 WHERE id = ?1",
            params![contact, hidden],
        )?;
        if n == 0 {
            return Err(ClientError::UnknownContact);
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        self.sync_profiles(Some(contact)).await;
        Ok(())
    }

    /// A picture for a contact that only the user sees; it shows instead of theirs.
    pub(super) fn set_contact_picture(&self, contact: i64, picture: Option<&str>) -> Result<()> {
        self.known(contact)?;
        self.store_picture(contact, true, picture, now_ms())?;
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    /// Sets a contact's nickname, or with `None` goes back to the name they chose.
    pub(super) fn set_nickname(&self, contact: i64, nickname: Option<&str>) -> Result<()> {
        self.known(contact)?;
        let conn = self.s()?.db.conn();
        match nickname.map(clean_name) {
            Some(n) if n.is_empty() => return Err(ClientError::BadInput),
            Some(n) => {
                conn.execute(
                    "UPDATE contacts SET name = ?2, nickname = 1 WHERE id = ?1",
                    params![contact, n],
                )?;
            }
            None => {
                conn.execute("UPDATE contacts SET nickname = 0 WHERE id = ?1", [contact])?;
                let theirs: Option<String> = conn.query_row(
                    "SELECT profile_name FROM contacts WHERE id = ?1",
                    [contact],
                    |r| r.get(0),
                )?;
                if let Some(theirs) = theirs {
                    self.adopt_name(contact, &theirs)?;
                }
            }
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    fn known(&self, contact: i64) -> Result<()> {
        let known: bool = self
            .s()?
            .db
            .conn()
            .query_row("SELECT 1 FROM contacts WHERE id = ?1", [contact], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if known {
            Ok(())
        } else {
            Err(ClientError::UnknownContact)
        }
    }

    fn store_picture(&self, owner: i64, local: bool, b64: Option<&str>, rev: i64) -> Result<()> {
        let conn = self.s()?.db.conn();
        match b64 {
            Some(b64) => {
                let (mime, bytes) = decode_picture(b64)?;
                conn.execute(
                    "INSERT OR REPLACE INTO pictures (owner, local, mime, data, rev) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![owner, local, mime, bytes, rev],
                )?;
            }
            None => {
                conn.execute(
                    "DELETE FROM pictures WHERE owner = ?1 AND local = ?2",
                    params![owner, local],
                )?;
            }
        }
        Ok(())
    }

    /// A picture to show, as a `data:` URL: ours (`None`), or a contact's (the one the user
    /// gave them, else their own).
    pub(super) fn picture(&self, contact: Option<i64>) -> Result<Option<String>> {
        let row = match contact {
            None => self.picture_row(ME, false)?,
            Some(c) => match self.picture_row(c, true)? {
                Some(r) => Some(r),
                None => self.picture_row(c, false)?,
            },
        };
        Ok(row.and_then(|(mime, data, _)| {
            let mime = image_mime(&data).filter(|m| *m == mime)?;
            Some(format!(
                "data:{mime};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(data)
            ))
        }))
    }

    /// A contact's profile (inside `process`'s transaction). Older revisions are ignored; a
    /// picture that is not an image is dropped.
    pub(super) fn receive_profile(&self, contact: i64, p: &Profile) -> Result<()> {
        let rev = i64::try_from(p.rev).unwrap_or(i64::MAX);
        let conn = self.s()?.db.conn();
        let newer = conn.execute(
            "UPDATE contacts SET profile_rev = ?2 WHERE id = ?1 AND profile_rev < ?2",
            params![contact, rev],
        )?;
        if newer == 0 {
            return Ok(());
        }
        let name = clean_name(&p.name);
        let status = clean_name_long(&p.status, MAX_STATUS);
        conn.execute(
            "UPDATE contacts SET profile_name = ?2, profile_status = ?3 WHERE id = ?1",
            params![contact, (!name.is_empty()).then_some(&name), status],
        )?;
        let picture = p.picture.as_deref().and_then(|b| image_mime(b).map(|m| (m, b)));
        match picture {
            Some((mime, bytes)) => {
                conn.execute(
                    "INSERT OR REPLACE INTO pictures (owner, local, mime, data, rev) VALUES (?1, 0, ?2, ?3, ?4)",
                    params![contact, mime, bytes, rev],
                )?;
            }
            None => {
                conn.execute("DELETE FROM pictures WHERE owner = ?1 AND local = 0", [contact])?;
            }
        }
        let nickname: bool =
            conn.query_row("SELECT nickname FROM contacts WHERE id = ?1", [contact], |r| {
                r.get(0)
            })?;
        if !nickname && !name.is_empty() {
            self.adopt_name(contact, &name)?;
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    /// Shows a contact under the name they chose, unless another contact already has it: then
    /// the name stays, and the profile shows theirs beside it (a contact cannot pass as another).
    fn adopt_name(&self, contact: i64, name: &str) -> Result<()> {
        let conn = self.s()?.db.conn();
        let key = name_key(name);
        let mut stmt = conn.prepare("SELECT name FROM contacts WHERE id != ?1")?;
        let taken = stmt
            .query_map([contact], |r| r.get::<_, String>(0))?
            .filter_map(core::result::Result::ok)
            .any(|n| name_key(&n) == key);
        if !taken {
            conn.execute(
                "UPDATE contacts SET name = ?2 WHERE id = ?1",
                params![contact, name],
            )?;
        }
        Ok(())
    }

    /// Sends each contact (or one) our profile, if it changed since they last got it. Each
    /// gets the picture only if they may see it. Runs after changes and on every retry tick.
    pub(super) async fn sync_profiles(&self, only: Option<i64>) {
        let Ok(due) = self.profiles_due(only) else { return };
        if due.is_empty() {
            return;
        }
        // Every send is a new revision: what one contact gets can change (the picture shown
        // or taken back) without the profile itself changing.
        let Ok(rev) = self.bump_rev() else { return };
        for (contact, out, digest) in due {
            let body = Body::Profile(Profile {
                rev,
                name: out.name,
                status: out.status,
                picture: out.picture,
            });
            let Ok(s) = self.s() else { return };
            // A newer profile replaces one still waiting to go out.
            let _ = s.db.conn().execute(
                "DELETE FROM messages WHERE contact = ?1 AND mine = 1 AND kind = 'control' AND body = ?2",
                params![contact, TAG],
            );
            let Ok(id) = self.queue_control_as(contact, body, None, TAG).await else {
                continue;
            };
            let _ = s.db.conn().execute(
                "UPDATE contacts SET profile_sent = ?2 WHERE id = ?1",
                params![contact, digest],
            );
            self.deliver(id).await;
        }
    }

    /// The contacts whose copy of our profile is out of date, with what they should have.
    fn profiles_due(&self, only: Option<i64>) -> Result<Vec<(i64, Outgoing, Vec<u8>)>> {
        let s = self.s()?;
        let name = s.name.clone();
        let status = self.setting_str(STATUS_KEY)?;
        let visibility = self.visibility()?;
        let picture = self.picture_row(ME, false)?.map(|(_, data, _)| data);
        // Nothing to say yet: no name, status or picture was ever set.
        if name.is_empty() && status.is_empty() && picture.is_none() {
            return Ok(Vec::new());
        }
        let mut stmt = s.db.conn().prepare(
            "SELECT id, verified, picture_hidden, key_warning, profile_sent FROM contacts
             WHERE blocked = 0 AND (?1 IS NULL OR id = ?1)",
        )?;
        let rows = stmt
            .query_map([only], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let mut due = Vec::new();
        for (id, verified, hidden, key_warning, sent) in rows {
            // Never to someone who may be an impostor (an unresolved key-change warning).
            let shows = !hidden
                && !key_warning
                && match visibility {
                    PictureVisibility::All => true,
                    PictureVisibility::Verified => verified,
                    PictureVisibility::Nobody => false,
                };
            let out = Outgoing {
                name: name.clone(),
                status: status.clone(),
                picture: picture.clone().filter(|_| shows),
            };
            let digest = out.digest();
            if sent.as_deref() != Some(digest.as_slice()) {
                due.push((id, out, digest));
            }
        }
        Ok(due)
    }
}

/// The profile part of a contact's view.
pub(super) struct ContactProfile {
    pub their_name: Option<String>,
    pub status: Option<String>,
    pub nickname: bool,
    pub picture: Option<String>,
    pub picture_hidden: bool,
}

pub(super) fn contact_profile(conn: &rusqlite::Connection, id: i64, shown: &str) -> Result<ContactProfile> {
    let (their_name, status, nickname, picture_hidden): (Option<String>, Option<String>, bool, bool) = conn
        .query_row(
        "SELECT profile_name, profile_status, nickname, picture_hidden FROM contacts WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let picture: Option<(bool, i64)> = conn
        .query_row(
            "SELECT local, rev FROM pictures WHERE owner = ?1 ORDER BY local DESC LIMIT 1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(ContactProfile {
        their_name: their_name.filter(|n| n != shown),
        status: status.filter(|st| !st.is_empty()),
        nickname,
        picture: picture.map(|(local, rev)| token(local, rev)),
        picture_hidden,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pictures_are_checked() {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        assert!(decode_picture(&b64(&[0xFF, 0xD8, 0xFF, 0xE0, 1, 2])).is_ok());
        assert_eq!(decode_picture(&b64(b"<svg/>")).err(), Some(ClientError::BadInput));
        assert_eq!(decode_picture("not base64!").err(), Some(ClientError::BadInput));
        let mut big = vec![0xFF, 0xD8, 0xFF];
        big.resize(MAX_PICTURE_LEN + 1, 0);
        assert_eq!(decode_picture(&b64(&big)).err(), Some(ClientError::TooLarge));
    }

    #[test]
    fn visibility_defaults_to_nobody() {
        assert_eq!(PictureVisibility::parse(b"all"), PictureVisibility::All);
        assert_eq!(PictureVisibility::parse(b"verified"), PictureVisibility::Verified);
        assert_eq!(PictureVisibility::parse(b"ALL"), PictureVisibility::Nobody);
        assert_eq!(PictureVisibility::parse(b""), PictureVisibility::Nobody);
    }

    #[test]
    fn digests_tell_what_was_sent() {
        let o = |name: &str, status: &str, picture: Option<&[u8]>| Outgoing {
            name: name.into(),
            status: status.into(),
            picture: picture.map(<[u8]>::to_vec),
        };
        let a = o("Al", "ice", None).digest();
        assert_ne!(a, o("Ali", "ce", None).digest(), "fields are length-prefixed");
        assert_ne!(
            a,
            o("Al", "ice", Some(b"")).digest(),
            "an empty picture is still one"
        );
        assert_eq!(a, o("Al", "ice", None).digest());
    }
}
