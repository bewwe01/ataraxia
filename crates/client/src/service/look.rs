//! Chat wallpapers and per-chat colour (milestone 4.5, ADR-0019). The rest of the look (theme,
//! accent, bubbles, text size) is a display preference the webview keeps itself; wallpapers live
//! here because a wallpaper can be the user's own photo, which must not be stored in the clear
//! (CLAUDE.md rule 6). Nothing here is ever sent to anyone.

use base64::Engine as _;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use super::{Actor, ChangeKind};
use crate::{ClientError, Result};

/// Built-in wallpapers; the webview draws them from design tokens.
pub const PRESETS: [&str; 6] = ["dusk", "aurora", "grid", "dots", "waves", "paper"];
/// A downscaled photo is well under this; anything bigger is refused.
pub const MAX_PHOTO_BYTES: usize = 3 * 1024 * 1024;
const MAX_DIM: u8 = 80;
const MAX_BLUR: u8 = 24;
/// The settings key of the default wallpaper, and the photo owner it uses (contact ids are > 0).
const GLOBAL_KEY: &str = "look.wallpaper";
const GLOBAL_OWNER: i64 = 0;

/// A wallpaper as the webview sees it (the photo itself comes separately). Stored as
/// `<preset or "photo">:<dim>:<blur>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WallpaperView {
    /// One of [`PRESETS`], or `None` for the user's photo.
    pub preset: Option<String>,
    pub photo: bool,
    /// Darkening over it, in percent (0–80).
    pub dim: u8,
    /// Blur in CSS pixels (0–24).
    pub blur: u8,
}

/// What the webview asks for. A new photo comes as base64 (the IPC carries JSON); `keep_photo`
/// changes dim or blur and keeps the photo already set.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WallpaperInput {
    pub preset: Option<String>,
    pub photo: Option<String>,
    #[serde(default)]
    pub keep_photo: bool,
    pub dim: u8,
    pub blur: u8,
}

/// Redacted: the photo is the user's.
impl core::fmt::Debug for WallpaperInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WallpaperInput")
            .field("preset", &self.preset)
            .field("keep_photo", &self.keep_photo)
            .finish_non_exhaustive()
    }
}

/// The image type, by its first bytes; anything else is refused.
fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("image/png"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        _ => None,
    }
}

/// A checked wallpaper and, for a new photo, its bytes and type.
pub(super) struct Checked {
    view: Option<WallpaperView>,
    photo: Option<(&'static str, Vec<u8>)>,
    keep_photo: bool,
}

pub(super) fn check(input: Option<WallpaperInput>) -> Result<Checked> {
    let Some(i) = input else {
        return Ok(Checked {
            view: None,
            photo: None,
            keep_photo: false,
        });
    };
    if i.dim > MAX_DIM || i.blur > MAX_BLUR {
        return Err(ClientError::BadInput);
    }
    let (preset, photo) = match (i.preset, i.photo, i.keep_photo) {
        (Some(p), None, false) if PRESETS.contains(&p.as_str()) => (Some(p), None),
        (None, Some(b64), false) => {
            // Base64 is 4/3 the size: refuse before decoding anything too big.
            if b64.len() > MAX_PHOTO_BYTES / 3 * 4 + 4 {
                return Err(ClientError::TooLarge);
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| ClientError::BadInput)?;
            if bytes.len() > MAX_PHOTO_BYTES {
                return Err(ClientError::TooLarge);
            }
            let mime = image_mime(&bytes).ok_or(ClientError::BadInput)?;
            (None, Some((mime, bytes)))
        }
        (None, None, true) => (None, None),
        _ => return Err(ClientError::BadInput),
    };
    let is_photo = preset.is_none();
    Ok(Checked {
        view: Some(WallpaperView {
            preset,
            photo: is_photo,
            dim: i.dim,
            blur: i.blur,
        }),
        photo,
        keep_photo: i.keep_photo,
    })
}

impl WallpaperView {
    fn stored(&self) -> String {
        format!(
            "{}:{}:{}",
            self.preset.as_deref().unwrap_or("photo"),
            self.dim,
            self.blur
        )
    }
}

/// A stored wallpaper back; `None` for anything malformed.
pub(super) fn parse(stored: Option<&str>) -> Option<WallpaperView> {
    let mut parts = stored?.split(':');
    let kind = parts.next()?;
    let dim: u8 = parts.next()?.parse().ok()?;
    let blur: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || dim > MAX_DIM || blur > MAX_BLUR {
        return None;
    }
    let preset = match kind {
        "photo" => None,
        p if PRESETS.contains(&p) => Some(p.to_owned()),
        _ => return None,
    };
    Some(WallpaperView {
        photo: preset.is_none(),
        preset,
        dim,
        blur,
    })
}

impl Actor {
    /// The default wallpaper for chats without their own.
    pub(super) fn wallpaper(&self) -> Result<Option<WallpaperView>> {
        let raw = self.s()?.db.setting(GLOBAL_KEY)?;
        Ok(raw.and_then(|v| parse(core::str::from_utf8(&v).ok())))
    }

    /// Sets (or with `None`, clears) the default wallpaper, or one chat's. The photo and the
    /// setting change together or not at all.
    pub(super) async fn set_wallpaper(
        &self,
        contact: Option<i64>,
        input: Option<WallpaperInput>,
    ) -> Result<()> {
        let checked = check(input)?;
        self.atomically(async { self.write_wallpaper(contact, &checked) })
            .await?;
        self.emit(ChangeKind::Contacts, contact);
        Ok(())
    }

    fn write_wallpaper(&self, contact: Option<i64>, checked: &Checked) -> Result<()> {
        let s = self.s()?;
        let conn = s.db.conn();
        let owner = if let Some(id) = contact {
            let known: bool = conn
                .query_row("SELECT 1 FROM contacts WHERE id = ?1", [id], |_| Ok(true))
                .optional()?
                .unwrap_or(false);
            if !known {
                return Err(ClientError::UnknownContact);
            }
            id
        } else {
            GLOBAL_OWNER
        };
        let has_photo: bool = conn
            .query_row("SELECT 1 FROM wallpaper_photos WHERE owner = ?1", [owner], |_| {
                Ok(true)
            })
            .optional()?
            .unwrap_or(false);
        if checked.keep_photo && !has_photo {
            return Err(ClientError::BadInput);
        }
        if let Some((mime, bytes)) = &checked.photo {
            conn.execute(
                "INSERT OR REPLACE INTO wallpaper_photos (owner, mime, data) VALUES (?1, ?2, ?3)",
                rusqlite::params![owner, mime, bytes],
            )?;
        } else if !checked.keep_photo {
            conn.execute("DELETE FROM wallpaper_photos WHERE owner = ?1", [owner])?;
        }
        let stored = checked.view.as_ref().map(WallpaperView::stored);
        if let Some(id) = contact {
            conn.execute(
                "UPDATE contacts SET wallpaper = ?2 WHERE id = ?1",
                rusqlite::params![id, stored],
            )?;
        } else if let Some(v) = stored {
            s.db.set_setting(GLOBAL_KEY, v.as_bytes())?;
        } else {
            conn.execute("DELETE FROM settings WHERE k = ?1", [GLOBAL_KEY])?;
        }
        Ok(())
    }

    /// The photo of the default wallpaper (`None`) or of a chat's, as a `data:` URL for display.
    pub(super) fn wallpaper_photo(&self, contact: Option<i64>) -> Result<Option<String>> {
        let owner = contact.unwrap_or(GLOBAL_OWNER);
        let row: Option<(String, Vec<u8>)> = self
            .s()?
            .db
            .conn()
            .query_row(
                "SELECT mime, data FROM wallpaper_photos WHERE owner = ?1",
                [owner],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(mime, data)| {
            let mime = image_mime(&data).filter(|m| *m == mime)?;
            Some(format!(
                "data:{mime};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(data)
            ))
        }))
    }

    /// A chat's own bubble colour, as a hue (0–359), or `None` for the app's accent.
    pub(super) fn set_chat_accent(&self, contact: i64, hue: Option<u16>) -> Result<()> {
        if hue.is_some_and(|h| h >= 360) {
            return Err(ClientError::BadInput);
        }
        let n = self.s()?.db.conn().execute(
            "UPDATE contacts SET accent_hue = ?2 WHERE id = ?1",
            rusqlite::params![contact, hue],
        )?;
        if n == 0 {
            return Err(ClientError::UnknownContact);
        }
        self.emit(ChangeKind::Contacts, Some(contact));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(preset: Option<&str>, photo: Option<&[u8]>, keep: bool, dim: u8, blur: u8) -> WallpaperInput {
        WallpaperInput {
            preset: preset.map(str::to_owned),
            photo: photo.map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
            keep_photo: keep,
            dim,
            blur,
        }
    }

    #[test]
    fn wallpapers_are_checked() {
        const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10];
        assert!(check(Some(input(Some("dusk"), None, false, 30, 0))).is_ok());
        assert!(check(Some(input(None, Some(JPEG), false, 0, 8))).is_ok());
        assert!(check(Some(input(None, None, true, 10, 0))).is_ok());
        assert!(check(None).is_ok_and(|c| c.view.is_none()));
        for bad in [
            input(Some("nope"), None, false, 0, 0),
            input(Some("dusk"), Some(JPEG), false, 0, 0),
            input(None, None, false, 0, 0),
            input(Some("dusk"), None, false, 81, 0),
            input(Some("dusk"), None, false, 0, 25),
            // Not an image (a script, say): refused by its first bytes.
            input(None, Some(b"<svg onload=alert(1)>"), false, 0, 0),
            input(Some("dusk"), None, true, 0, 0),
        ] {
            assert!(check(Some(bad)).is_err());
        }
        let mut huge = vec![0xFF, 0xD8, 0xFF];
        huge.resize(MAX_PHOTO_BYTES + 1, 0);
        assert_eq!(
            check(Some(input(None, Some(&huge), false, 0, 0))).err(),
            Some(ClientError::TooLarge)
        );
        assert_eq!(image_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_mime(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
    }

    #[test]
    fn stored_wallpapers_parse_strictly() {
        let dots = parse(Some("dots:20:0")).unwrap();
        assert_eq!(
            (dots.preset.as_deref(), dots.photo, dots.dim),
            (Some("dots"), false, 20)
        );
        let photo = parse(Some("photo:0:4")).unwrap();
        assert!(photo.photo && photo.preset.is_none());
        assert_eq!(parse(Some(&dots.stored())), Some(dots));
        for bad in [
            "x:0:0",
            "dots:99:0",
            "dots:0:30",
            "dots:0:0:1",
            "dots:0",
            "dots:-1:0",
            "",
        ] {
            assert!(parse(Some(bad)).is_none(), "{bad}");
        }
        assert!(parse(None).is_none());
    }
}
