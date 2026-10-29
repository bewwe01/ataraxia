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
use super::{Actor, ChangeKind, MAX_ATTEMPTS, clean_name, clean_name_long, name_key, rng};
use crate::{ClientError, Result, now_ms};
use rand::seq::SliceRandom as _;
use zeroize::Zeroizing;

pub const MAX_STATUS: usize = 140;
const STATUS_KEY: &str = "profile.status";
const VISIBILITY_KEY: &str = "profile.visibility";
const REV_KEY: &str = "profile.rev";
/// Our own picture's owner in `pictures` (contact ids are > 0).
const ME: i64 = 0;
/// The tag on a queued profile message, so a newer one replaces it.
const TAG: &str = "profile";
/// A picture's longest side. Anything larger could make the webview decode a huge image from
/// a few kilobytes (review PR-1); the app sends 512 px.
pub const MAX_PICTURE_SIDE: u16 = 1024;
/// Contacts sent a changed profile per round: a change reaches everyone over a few minutes
/// rather than as one burst that links all their mailboxes at the relay (review PR-5).
const PER_ROUND: usize = 4;

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

/// Width and height from a JPEG's start-of-frame segment; `None` if there is none or the
/// segments do not add up.
fn jpeg_dims(b: &[u8]) -> Option<(u16, u16)> {
    let mut i = 2usize; // after FF D8
    while let (Some(&0xFF), Some(&m)) = (b.get(i), b.get(i.checked_add(1)?)) {
        let at = |k: usize| b.get(i.checked_add(k)?).copied();
        let len = usize::from(u16::from_be_bytes([at(2)?, at(3)?]));
        if matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) {
            let h = u16::from_be_bytes([at(5)?, at(6)?]);
            let w = u16::from_be_bytes([at(7)?, at(8)?]);
            return Some((w, h));
        }
        i = i.checked_add(2)?.checked_add(len)?;
    }
    None
}

/// A picture we accept, from the user or a contact: a JPEG (the app's redrawn, metadata-free
/// form) of at most [`MAX_PICTURE_LEN`] bytes and [`MAX_PICTURE_SIDE`] pixels a side.
fn picture_ok(b: &[u8]) -> bool {
    b.len() <= MAX_PICTURE_LEN
        && image_mime(b) == Some("image/jpeg")
        && jpeg_dims(b).is_some_and(|(w, h)| w > 0 && h > 0 && w <= MAX_PICTURE_SIDE && h <= MAX_PICTURE_SIDE)
}

/// A picture from the webview, as base64 (see [`picture_ok`]). Wiped on every path.
fn decode_picture(b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    if b64.len() > MAX_PICTURE_LEN / 3 * 4 + 4 {
        return Err(ClientError::TooLarge);
    }
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| ClientError::BadInput)?,
    );
    if bytes.len() > MAX_PICTURE_LEN {
        return Err(ClientError::TooLarge);
    }
    if !picture_ok(&bytes) {
        return Err(ClientError::BadInput);
    }
    Ok(bytes)
}

/// A picture as a `data:` URL, sized up front so no unwiped copies are left behind.
fn data_url(mime: &str, data: &[u8]) -> Option<String> {
    let prefix = format!("data:{mime};base64,");
    let mut url = String::with_capacity(prefix.len().checked_add(base64::encoded_len(data.len(), true)?)?);
    url.push_str(&prefix);
    base64::engine::general_purpose::STANDARD.encode_string(data, &mut url);
    Some(url)
}

/// The cache key the webview gets for a picture row.
fn token(local: bool, rev: i64) -> String {
    format!("{}{rev}", if local { "l" } else { "p" })
}

/// A stored picture: its type, bytes and revision.
type PictureRow = (String, Zeroizing<Vec<u8>>, i64);

/// What one contact gets from us; the picture by its hash (it is read once per round).
struct Outgoing<'a> {
    name: &'a str,
    status: &'a str,
    picture: Option<&'a [u8; 32]>,
}

impl Outgoing<'_> {
    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        for part in [self.name.as_bytes(), self.status.as_bytes()] {
            h.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            h.update(part);
        }
        match self.picture {
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

    fn picture_row(&self, owner: i64, local: bool) -> Result<Option<PictureRow>> {
        Ok(self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT mime, data, rev FROM pictures WHERE owner = ?1 AND local = ?2",
                params![owner, local],
                |r| Ok((r.get(0)?, Zeroizing::new(r.get(1)?), r.get(2)?)),
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
    pub(super) async fn set_my_picture(&self, picture: Option<Zeroizing<String>>) -> Result<()> {
        let rev = i64::try_from(self.bump_rev()?).unwrap_or(i64::MAX);
        self.store_picture(ME, false, picture, rev)?;
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
    pub(super) fn set_contact_picture(&self, contact: i64, picture: Option<Zeroizing<String>>) -> Result<()> {
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
                let theirs: Option<String> = conn.query_row(
                    "SELECT profile_name FROM contacts WHERE id = ?1",
                    [contact],
                    |r| r.get(0),
                )?;
                // Only when their name can be shown: otherwise the nickname stays a nickname,
                // and the user is told (review PR-15).
                let theirs = theirs.ok_or(ClientError::BadInput)?;
                if !self.adopt_name(contact, &theirs, false)? {
                    return Err(ClientError::NameTaken);
                }
                conn.execute("UPDATE contacts SET nickname = 0 WHERE id = ?1", [contact])?;
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

    fn store_picture(&self, owner: i64, local: bool, b64: Option<Zeroizing<String>>, rev: i64) -> Result<()> {
        let conn = self.s()?.db.conn();
        match b64 {
            Some(b64) => {
                let bytes = decode_picture(&b64)?;
                conn.execute(
                    "INSERT OR REPLACE INTO pictures (owner, local, mime, data, rev) VALUES (?1, ?2, 'image/jpeg', ?3, ?4)",
                    params![owner, local, &**bytes, rev],
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
        // Checked again on the way out, so a row stored by an older build cannot get through.
        Ok(row.and_then(|(mime, data, _)| {
            (mime == "image/jpeg" && picture_ok(&data))
                .then(|| data_url(&mime, &data))
                .flatten()
        }))
    }

    /// A contact's profile (inside `process`'s transaction). Older revisions are ignored; a
    /// picture that is not a small JPEG is dropped (review PR-1).
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
        match p.picture.as_deref().filter(|b| picture_ok(b)) {
            Some(bytes) => {
                conn.execute(
                    "INSERT OR REPLACE INTO pictures (owner, local, mime, data, rev) VALUES (?1, 0, 'image/jpeg', ?2, ?3)",
                    params![contact, bytes, rev],
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
            self.adopt_name(contact, &name, true)?;
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }

    /// Shows a contact under the name they chose, unless it looks like another contact's
    /// name, shown or self-chosen (`name_key` folds case, spacing and look-alike letters): then
    /// the name stays, and the profile shows theirs beside it, so a contact cannot pass as
    /// another (review PR-6). A change of shown name is written into the chat as a line when
    /// `announce`, so it is never silent. Returns whether the name is now shown.
    fn adopt_name(&self, contact: i64, name: &str, announce: bool) -> Result<bool> {
        let conn = self.s()?.db.conn();
        let key = name_key(name);
        let mut stmt = conn.prepare(
            "SELECT name FROM contacts WHERE id != ?1
             UNION ALL SELECT profile_name FROM contacts WHERE id != ?1 AND profile_name IS NOT NULL",
        )?;
        let taken = stmt
            .query_map([contact], |r| r.get::<_, String>(0))?
            .filter_map(core::result::Result::ok)
            .any(|n| name_key(&n) == key);
        if taken {
            return Ok(false);
        }
        let old: String =
            conn.query_row("SELECT name FROM contacts WHERE id = ?1", [contact], |r| r.get(0))?;
        if old == name {
            return Ok(true);
        }
        conn.execute(
            "UPDATE contacts SET name = ?2 WHERE id = ?1",
            params![contact, name],
        )?;
        if announce {
            // A local line (never sent): "<old> is now called <new>".
            conn.execute(
                "INSERT INTO messages (contact, mine, kind, body, at_ms, status) VALUES (?1, 0, 'renamed', ?2, ?3, 'received')",
                params![contact, format!("{old}\n{name}"), now_ms()],
            )?;
            self.emit(ChangeKind::Messages, Some(contact));
        }
        Ok(true)
    }

    /// Sends each contact (or one) our profile, if it changed since they last got it. Each
    /// gets the picture only if they may see it. Runs after changes and on every retry tick;
    /// a round for all contacts sends to at most [`PER_ROUND`] of them, in random order.
    pub(super) async fn sync_profiles(&self, only: Option<i64>) {
        let Ok(mut due) = self.profiles_due(only) else {
            return;
        };
        if due.is_empty() {
            return;
        }
        if only.is_none() {
            due.shuffle(&mut rng());
            due.truncate(PER_ROUND);
        }
        let Ok(s) = self.s() else { return };
        let name = s.name.clone();
        let Ok(status) = self.setting_str(STATUS_KEY) else {
            return;
        };
        let Ok(picture) = self.picture_row(ME, false) else {
            return;
        };
        // Every send is a new revision: what one contact gets can change (the picture shown
        // or taken back) without the profile itself changing.
        let Ok(rev) = self.bump_rev() else { return };
        for (contact, shows, digest) in due {
            let picture = picture
                .as_ref()
                .filter(|_| shows)
                .map(|(_, data, _)| data.to_vec());
            // Every profile is padded to the same size, so the envelope's size does not tell the
            // relay who may see the picture (review PR-5).
            let pad = vec![0u8; MAX_PICTURE_LEN.saturating_sub(picture.as_ref().map_or(0, Vec::len))];
            let body = Body::Profile(Profile {
                rev,
                name: name.clone(),
                status: status.clone(),
                picture,
                pad,
            });
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

    /// The contacts whose copy of our profile is out of date: whether each may see the
    /// picture, and the digest of what they should have.
    fn profiles_due(&self, only: Option<i64>) -> Result<Vec<(i64, bool, Vec<u8>)>> {
        let s = self.s()?;
        let name = s.name.clone();
        let status = self.setting_str(STATUS_KEY)?;
        let visibility = self.visibility()?;
        // The picture is hashed once per round, not copied per contact (review PR-7).
        let picture: Option<[u8; 32]> = self
            .picture_row(ME, false)?
            .map(|(_, data, _)| Sha256::digest(&*data).into());
        // Nothing to say yet: no name, status or picture was ever set.
        if name.is_empty() && status.is_empty() && picture.is_none() {
            return Ok(Vec::new());
        }
        // A contact with an unresolved key-change warning gets nothing (they may be an
        // impostor; review PR-11); one whose last profile was given up on is due again, so a
        // picture taken back is never left on their screen (review PR-4).
        let mut stmt = s.db.conn().prepare(
            "SELECT c.id, c.verified, c.picture_hidden,
               CASE WHEN EXISTS (SELECT 1 FROM messages m WHERE m.contact = c.id AND m.mine = 1
                 AND m.kind = 'control' AND m.body = ?2 AND m.attempts >= ?3) THEN NULL ELSE c.profile_sent END
             FROM contacts c WHERE c.blocked = 0 AND c.key_warning = 0 AND (?1 IS NULL OR c.id = ?1)",
        )?;
        let rows = stmt
            .query_map(params![only, TAG, MAX_ATTEMPTS], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let mut due = Vec::new();
        for (id, verified, hidden, sent) in rows {
            let shows = !hidden
                && match visibility {
                    PictureVisibility::All => true,
                    PictureVisibility::Verified => verified,
                    PictureVisibility::Nobody => false,
                };
            let digest = Outgoing {
                name: &name,
                status: &status,
                picture: picture.as_ref().filter(|_| shows),
            }
            .digest();
            if sent.as_deref() != Some(digest.as_slice()) {
                due.push((id, shows, digest));
            }
        }
        Ok(due)
    }
}

/// After the user accepted a key change (`old` merged into `new`): the chat keeps its look
/// (colour, wallpaper and its photo; review LK-11) and the user's choices about this person
/// (picture hidden from them, nickname, the picture only the user sees; review PR-2).
pub(super) fn carry_over(conn: &rusqlite::Connection, old: i64, contact: i64) -> Result<()> {
    // The chat keeps its look: colour, wallpaper and its photo (review LK-11).
    conn.execute(
        "UPDATE contacts SET
           accent_hue = coalesce(accent_hue, (SELECT accent_hue FROM contacts WHERE id = ?1)),
           wallpaper = coalesce(wallpaper, (SELECT wallpaper FROM contacts WHERE id = ?1))
         WHERE id = ?2",
        params![old, contact],
    )?;
    // The user's choices about this person: whether they see the user's
    // picture, the nickname and the picture only the user sees (review PR-2).
    conn.execute(
        "UPDATE contacts SET
           picture_hidden = picture_hidden OR (SELECT picture_hidden FROM contacts WHERE id = ?1),
           name = CASE WHEN (SELECT nickname FROM contacts WHERE id = ?1) = 1
                       THEN (SELECT name FROM contacts WHERE id = ?1) ELSE name END,
           nickname = nickname OR (SELECT nickname FROM contacts WHERE id = ?1)
         WHERE id = ?2",
        params![old, contact],
    )?;
    conn.execute(
        "UPDATE OR IGNORE pictures SET owner = ?2 WHERE owner = ?1 AND local = 1",
        params![old, contact],
    )?;
    conn.execute(
        "UPDATE OR IGNORE wallpaper_photos SET owner = ?2 WHERE owner = ?1
         AND (SELECT wallpaper FROM contacts WHERE id = ?2) LIKE 'photo:%'",
        params![old, contact],
    )?;
    Ok(())
}

/// Forgets what a contact was last sent and drops a profile still waiting to go out to them,
/// so the next round sends what is current.
pub(super) fn forget_sent(conn: &rusqlite::Connection, contact: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM messages WHERE contact = ?1 AND mine = 1 AND kind = 'control' AND body = ?2",
        params![contact, TAG],
    )?;
    conn.execute("UPDATE contacts SET profile_sent = NULL WHERE id = ?1", [contact])?;
    Ok(())
}

/// The profile part of a contact's view.
pub(super) struct ContactProfile {
    pub their_name: Option<String>,
    pub status: Option<String>,
    pub nickname: bool,
    pub picture: Option<String>,
    pub local_picture: bool,
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
        local_picture: picture.is_some_and(|(local, _)| local),
        picture_hidden,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JPEG start: SOI, an APP0 segment, then a start-of-frame of `w` × `h`.
    pub(crate) fn jpeg(w: u16, h: u16) -> Vec<u8> {
        let mut b = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0, 0, 0xFF, 0xC0, 0x00, 0x11, 8,
        ];
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&w.to_be_bytes());
        b.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        b
    }

    #[test]
    fn pictures_are_checked() {
        let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        assert_eq!(jpeg_dims(&jpeg(512, 384)), Some((512, 384)));
        assert!(decode_picture(&enc(&jpeg(512, 512))).is_ok());
        assert!(decode_picture(&enc(&jpeg(1024, 1))).is_ok());
        // A few bytes that would make the webview decode a gigabyte (review PR-1).
        assert_eq!(
            decode_picture(&enc(&jpeg(60000, 60000))).err(),
            Some(ClientError::BadInput)
        );
        assert_eq!(
            decode_picture(&enc(&jpeg(1025, 10))).err(),
            Some(ClientError::BadInput)
        );
        assert_eq!(
            decode_picture(&enc(&jpeg(0, 10))).err(),
            Some(ClientError::BadInput)
        );
        // No frame header, not a JPEG, or not base64.
        assert_eq!(
            decode_picture(&enc(&[0xFF, 0xD8, 0xFF, 0xE0, 1, 2])).err(),
            Some(ClientError::BadInput)
        );
        assert_eq!(
            decode_picture(&enc(b"\x89PNG\r\n\x1a\n....")).err(),
            Some(ClientError::BadInput)
        );
        assert_eq!(decode_picture(&enc(b"<svg/>")).err(), Some(ClientError::BadInput));
        assert_eq!(decode_picture("not base64!").err(), Some(ClientError::BadInput));
        let mut big = jpeg(10, 10);
        big.resize(MAX_PICTURE_LEN + 1, 0);
        assert_eq!(decode_picture(&enc(&big)).err(), Some(ClientError::TooLarge));
        // Segment lengths that run off the end never panic.
        for cut in 0..jpeg(5, 5).len() {
            let _ = jpeg_dims(&jpeg(5, 5)[..cut]);
        }
        assert_eq!(jpeg_dims(&[0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF]), None);
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
        let zero = [0u8; 32];
        let o = |name: &'static str, status: &'static str, picture: Option<&'static [u8; 32]>| Outgoing {
            name,
            status,
            picture,
        };
        let a = o("Al", "ice", None).digest();
        assert_ne!(a, o("Ali", "ce", None).digest(), "fields are length-prefixed");
        assert_ne!(
            a,
            Outgoing {
                name: "Al",
                status: "ice",
                picture: Some(&zero)
            }
            .digest(),
            "a picture counts"
        );
        assert_eq!(a, o("Al", "ice", None).digest());
    }
}
