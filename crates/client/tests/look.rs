//! Milestone 4.5, Look (ADR-0019): chat wallpapers and per-chat colour, kept in the encrypted
//! database (a wallpaper can be the user's own photo), never sent to anyone.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64::Engine as _;
use common::*;
use veil_client::ClientError;
use veil_client::service::WallpaperInput;
use zeroize::Zeroizing;

fn preset(name: &str, dim: u8) -> WallpaperInput {
    WallpaperInput {
        preset: Some(name.into()),
        photo: None,
        keep_photo: false,
        dim,
        blur: 0,
    }
}

/// A tiny but real JPEG start (the app sends downscaled JPEGs).
const JPEG: &[u8] = &[
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1,
];
const PHOTO_MARK: &[u8] = b"wallpaper-photo-at-rest-probe";

fn photo() -> WallpaperInput {
    let mut bytes = JPEG.to_vec();
    bytes.extend_from_slice(PHOTO_MARK);
    WallpaperInput {
        preset: None,
        photo: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        keep_photo: false,
        dim: 20,
        blur: 8,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallpapers_and_chat_colours() {
    let r = relay().await;
    let (alice, bob) = (user(&r, "Alice").await, user(&r, "Bob").await);
    let (a_bob, b_alice) = pair(&alice.client, &bob.client).await;
    let c = &alice.client;

    // Default wallpaper: a preset, then cleared.
    assert_eq!(c.wallpaper().await.unwrap(), None);
    c.set_wallpaper(None, Some(preset("dusk", 30))).await.unwrap();
    let w = c.wallpaper().await.unwrap().unwrap();
    assert_eq!((w.preset.as_deref(), w.photo, w.dim), (Some("dusk"), false, 30));

    // A chat's own photo wallpaper and colour; the other side knows nothing of either.
    c.set_wallpaper(Some(a_bob.id), Some(photo())).await.unwrap();
    c.set_chat_accent(a_bob.id, Some(200)).await.unwrap();
    let view = c
        .contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == a_bob.id)
        .unwrap();
    assert_eq!(view.accent_hue, Some(200));
    let cw = view.wallpaper.unwrap();
    assert!(cw.photo && cw.preset.is_none() && cw.dim == 20 && cw.blur == 8);
    let url = c.wallpaper_photo(Some(a_bob.id)).await.unwrap().unwrap();
    assert!(url.starts_with("data:image/jpeg;base64,"));
    let theirs = bob
        .client
        .contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == b_alice.id)
        .unwrap();
    assert!(theirs.wallpaper.is_none() && theirs.accent_hue.is_none());

    // Keeping the photo while changing the dim; then back to a preset drops the photo.
    let keep = WallpaperInput {
        preset: None,
        photo: None,
        keep_photo: true,
        dim: 50,
        blur: 0,
    };
    c.set_wallpaper(Some(a_bob.id), Some(keep.clone())).await.unwrap();
    assert!(c.wallpaper_photo(Some(a_bob.id)).await.unwrap().is_some());
    c.set_wallpaper(Some(a_bob.id), Some(preset("dots", 0)))
        .await
        .unwrap();
    assert!(c.wallpaper_photo(Some(a_bob.id)).await.unwrap().is_none());
    // Nothing to keep now.
    assert_eq!(
        c.set_wallpaper(Some(a_bob.id), Some(keep)).await.unwrap_err(),
        ClientError::BadInput
    );

    // Refused: unknown presets, non-images, absurd values, unknown chats.
    let svg = WallpaperInput {
        photo: Some(base64::engine::general_purpose::STANDARD.encode(b"<svg onload=alert(1)>")),
        ..photo()
    };
    for bad in [preset("nope", 0), preset("dusk", 99), svg] {
        assert_eq!(
            c.set_wallpaper(None, Some(bad)).await.unwrap_err(),
            ClientError::BadInput
        );
    }
    assert_eq!(
        c.set_chat_accent(a_bob.id, Some(360)).await.unwrap_err(),
        ClientError::BadInput
    );
    assert_eq!(
        c.set_chat_accent(9999, Some(1)).await.unwrap_err(),
        ClientError::UnknownContact
    );
    assert_eq!(
        c.set_wallpaper(Some(9999), Some(preset("dusk", 0)))
            .await
            .unwrap_err(),
        ClientError::UnknownContact
    );

    // The photo is encrypted at rest like everything else.
    c.set_wallpaper(Some(a_bob.id), Some(photo())).await.unwrap();
    c.lock().await.unwrap();
    assert!(
        !tree_contains(alice.dir(), PHOTO_MARK),
        "wallpaper photo found in the clear"
    );
    c.unlock(Zeroizing::new("correct horse battery".into()))
        .await
        .unwrap();
    assert!(c.wallpaper_photo(Some(a_bob.id)).await.unwrap().is_some());

    // Deleting the chat deletes its photo; the default stays.
    c.delete_contact(a_bob.id).await.unwrap();
    assert!(c.wallpaper_photo(Some(a_bob.id)).await.unwrap().is_none());
    assert!(c.wallpaper().await.unwrap().is_some());
    c.set_wallpaper(None, None).await.unwrap();
    assert_eq!(c.wallpaper().await.unwrap(), None);
}
