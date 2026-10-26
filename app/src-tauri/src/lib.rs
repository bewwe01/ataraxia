//! The Tauri shell: maps the commands in `app/src/ipc.ts` onto [`veil_client::service::Client`].
//!
//! Everything returned here is display data (CLAUDE.md rule 2). Errors cross as the short,
//! content-free `Display` strings of [`veil_client::ClientError`].
#![forbid(unsafe_code)]

mod native;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter as _, Manager as _, State};
use veil_client::ClientError;
use veil_client::service::{
    AppState, AttachmentInput, ChangeKind, Client, ContactView, InviteView, MeView, MessageView, PrivacyView,
    SafetyView, SearchHit, SecurityView, SetupInput, UnlockInfo, UnlockOutcome,
};
use veil_client::unlock::SecretKind;

use native::NativeError;

/// The Android package the native plugin lives in (checked by `app/android/harden.py`).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const ANDROID_PACKAGE: &str = "org.veil.app";
use zeroize::Zeroizing;

type Res<T> = Result<T, String>;

#[allow(clippy::needless_pass_by_value)]
fn err(e: ClientError) -> String {
    e.to_string()
}

#[derive(Clone, Serialize)]
struct Changed {
    kind: ChangeKind,
    contact: Option<i64>,
}

/// The setup form. The passphrase is wiped when this is dropped.
#[derive(Deserialize)]
struct SetupForm {
    relay: String,
    pin: String,
    name: String,
    kind: SecretKind,
    passphrase: Zeroizing<String>,
}

#[tauri::command]
async fn app_state(c: State<'_, Client>) -> Res<AppState> {
    c.state().await.map_err(err)
}

#[tauri::command]
async fn setup(c: State<'_, Client>, input: SetupForm) -> Res<()> {
    let SetupForm {
        relay,
        pin,
        name,
        kind,
        passphrase,
    } = input;
    c.setup(SetupInput {
        relay,
        pin,
        name,
        kind,
        passphrase,
    })
    .await
    .map_err(err)
}

/// Destroys what lives outside Veil's data directory after a Purge PIN: the Keystore key and
/// the webview's storage (theme settings). The UI is told "wrong PIN or password" (ADR-0012).
async fn finish_purge(app: &AppHandle) {
    native::delete_key(app).await;
    for w in app.webview_windows().values() {
        let _ = w.clear_all_browsing_data();
    }
}

#[tauri::command]
async fn unlock(app: AppHandle, c: State<'_, Client>, passphrase: Zeroizing<String>) -> Res<()> {
    match c.unlock(passphrase).await.map_err(err)? {
        UnlockOutcome::Unlocked => Ok(()),
        UnlockOutcome::Purged { during_wait } => {
            finish_purge(&app).await;
            // The same answer any other attempt would get at this moment (review UR3-1).
            Err(err(if during_wait {
                ClientError::RetryLater
            } else {
                ClientError::WrongPassphrase
            }))
        }
    }
}

#[tauri::command]
async fn unlock_info(c: State<'_, Client>) -> Res<UnlockInfo> {
    let mut info = c.unlock_info().await.map_err(err)?;
    info.biometric &= native::biometric_platform();
    Ok(info)
}

#[tauri::command]
async fn security(c: State<'_, Client>) -> Res<SecurityView> {
    c.security().await.map_err(err)
}

#[tauri::command]
async fn change_secret(
    c: State<'_, Client>,
    current: Zeroizing<String>,
    kind: SecretKind,
    next: Zeroizing<String>,
) -> Res<()> {
    c.change_secret(current, kind, next).await.map_err(err)
}

#[tauri::command]
async fn set_purge(c: State<'_, Client>, current: Zeroizing<String>, purge: Zeroizing<String>) -> Res<()> {
    c.set_purge(current, purge).await.map_err(err)
}

#[tauri::command]
async fn clear_purge(c: State<'_, Client>, current: Zeroizing<String>) -> Res<()> {
    c.clear_purge(current).await.map_err(err)
}

fn native_err(e: NativeError) -> String {
    match e {
        NativeError::Unavailable => "Biometric unlock is not available on this device".into(),
        NativeError::Cancelled => "Cancelled".into(),
        NativeError::KeyGone => {
            "Your fingerprints or face data changed, so biometric unlock was turned off. Use your PIN or password, then turn it on again in Settings.".into()
        }
        NativeError::Lockout => "Too many fingerprint attempts. Use your PIN or password.".into(),
        NativeError::Failed => "Biometric unlock failed".into(),
    }
}

/// What this device offers, for showing or hiding settings.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeInfo {
    android: bool,
    biometric: bool,
    screenshot_setting: bool,
    screenshots_allowed: bool,
}

#[tauri::command]
async fn native_info(app: AppHandle) -> NativeInfo {
    NativeInfo {
        android: cfg!(target_os = "android"),
        biometric: native::biometric_available(&app).await,
        screenshot_setting: cfg!(target_os = "android"),
        screenshots_allowed: native::screenshots_allowed(&app).await,
    }
}

/// Turns biometric unlock on: checks the PIN or password, then has the Keystore seal a fresh
/// secret behind a biometric prompt. The secret never reaches the webview.
#[tauri::command]
async fn biometric_enable(app: AppHandle, c: State<'_, Client>, current: Zeroizing<String>) -> Res<()> {
    let secret = c.biometric_prepare(current).await.map_err(err)?;
    let result = match native::seal(&app, &secret).await {
        Ok(sealed) => c.biometric_commit(sealed).await.map_err(err),
        Err(e) => Err(native_err(e)),
    };
    if result.is_err() {
        // Leave nothing half-enabled: no files, no Keystore key (review U-9).
        let _ = c.biometric_disable().await;
        native::delete_key(&app).await;
    }
    result
}

#[tauri::command]
async fn biometric_disable(app: AppHandle, c: State<'_, Client>) -> Res<()> {
    c.biometric_disable().await.map_err(err)?;
    native::delete_key(&app).await;
    Ok(())
}

#[tauri::command]
async fn unlock_biometric(app: AppHandle, c: State<'_, Client>) -> Res<()> {
    let Some(blob) = c.biometric_sealed().await.map_err(err)? else {
        return Err(native_err(NativeError::Unavailable));
    };
    match native::open(&app, &blob).await {
        Ok(secret) => c.unlock_biometric(secret).await.map_err(err),
        Err(NativeError::KeyGone) => {
            let _ = c.biometric_disable().await;
            Err(native_err(NativeError::KeyGone))
        }
        Err(e) => Err(native_err(e)),
    }
}

#[tauri::command]
async fn set_screenshots_allowed(app: AppHandle, c: State<'_, Client>, allow: bool) -> Res<()> {
    // Only from Settings, while unlocked (review U-11).
    if c.state().await.map_err(err)? != AppState::Unlocked {
        return Err(err(ClientError::Locked));
    }
    native::set_screenshots_allowed(&app, allow)
        .await
        .map_err(native_err)
}

#[tauri::command]
async fn set_dark_bars(app: AppHandle, dark: bool) {
    native::set_dark_bars(&app, dark).await;
}

#[tauri::command]
async fn lock(c: State<'_, Client>) -> Res<()> {
    c.lock().await.map_err(err)
}

#[tauri::command]
async fn touch(c: State<'_, Client>) -> Res<()> {
    c.touch().await.map_err(err)
}

#[tauri::command]
async fn reset(c: State<'_, Client>) -> Res<()> {
    c.reset().await.map_err(err)
}

#[tauri::command]
async fn me(c: State<'_, Client>) -> Res<MeView> {
    c.me().await.map_err(err)
}

#[tauri::command]
async fn contacts(c: State<'_, Client>) -> Res<Vec<ContactView>> {
    c.contacts().await.map_err(err)
}

#[tauri::command]
async fn messages(c: State<'_, Client>, contact: i64) -> Res<Vec<MessageView>> {
    c.messages(contact).await.map_err(err)
}

#[tauri::command]
async fn send(c: State<'_, Client>, contact: i64, text: String) -> Res<MessageView> {
    c.send(contact, text).await.map_err(err)
}

#[tauri::command]
async fn reply(c: State<'_, Client>, contact: i64, text: String, to: i64) -> Res<MessageView> {
    c.reply(contact, text, to).await.map_err(err)
}

#[tauri::command]
async fn react(c: State<'_, Client>, message: i64, emoji: Option<String>) -> Res<()> {
    c.react(message, emoji).await.map_err(err)
}

#[tauri::command]
async fn edit_message(c: State<'_, Client>, message: i64, text: String) -> Res<()> {
    c.edit_message(message, text).await.map_err(err)
}

#[tauri::command]
async fn delete_for_everyone(c: State<'_, Client>, message: i64) -> Res<()> {
    c.delete_for_everyone(message).await.map_err(err)
}

#[tauri::command]
async fn delete_for_me(c: State<'_, Client>, message: i64) -> Res<()> {
    c.delete_for_me(message).await.map_err(err)
}

#[tauri::command]
async fn search(c: State<'_, Client>, query: String) -> Res<Vec<SearchHit>> {
    c.search(query).await.map_err(err)
}

#[tauri::command]
async fn verify_scanned(c: State<'_, Client>, contact: i64, code: String) -> Res<bool> {
    c.verify_scanned(contact, code).await.map_err(err)
}

/// What the UI sends ahead of a file's bytes (see `ipc.sendAttachment`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentMeta {
    contact: i64,
    kind: String,
    mime: String,
    name: Option<String>,
    duration_ms: Option<u32>,
    waveform: Option<Vec<u8>>,
    thumbnail: Option<Vec<u8>>,
}

/// Body: 4-byte big-endian length of a JSON [`AttachmentMeta`], the JSON, then the file. One
/// binary IPC call, so a 25 MB file does not go through JSON.
#[tauri::command]
async fn send_attachment(c: State<'_, Client>, request: tauri::ipc::Request<'_>) -> Res<MessageView> {
    let tauri::ipc::InvokeBody::Raw(body) = request.body() else {
        return Err(err(ClientError::BadInput));
    };
    let (len, rest) = body
        .split_at_checked(4)
        .ok_or_else(|| err(ClientError::BadInput))?;
    let len = usize::try_from(u32::from_be_bytes(
        len.try_into().map_err(|_| err(ClientError::BadInput))?,
    ))
    .map_err(|_| err(ClientError::BadInput))?;
    if len > 64 * 1024 {
        return Err(err(ClientError::BadInput));
    }
    let (meta, data) = rest
        .split_at_checked(len)
        .ok_or_else(|| err(ClientError::BadInput))?;
    let meta: AttachmentMeta = serde_json::from_slice(meta).map_err(|_| err(ClientError::BadInput))?;
    c.send_attachment(
        meta.contact,
        AttachmentInput {
            kind: meta.kind,
            mime: meta.mime,
            name: meta.name,
            data: Zeroizing::new(data.to_vec()),
            thumbnail: meta.thumbnail,
            duration_ms: meta.duration_ms,
            waveform: meta.waveform,
        },
    )
    .await
    .map_err(err)
}

/// The file of an attachment, as raw bytes for the UI to show or play. Display data: it is
/// what the user sent or received.
#[tauri::command]
async fn attachment_data(c: State<'_, Client>, message: i64) -> Res<tauri::ipc::Response> {
    let (_, _, data) = c.attachment_data(message).await.map_err(err)?;
    Ok(tauri::ipc::Response::new(data.to_vec()))
}

/// Saves a received file where the user picks (Android). Elsewhere the UI saves through the
/// webview's download, so this says "unsupported".
#[tauri::command]
async fn save_attachment(app: AppHandle, c: State<'_, Client>, message: i64) -> Res<()> {
    if !cfg!(target_os = "android") {
        return Err("Unsupported".into());
    }
    let (mime, name, data) = c.attachment_data(message).await.map_err(err)?;
    let name = name.unwrap_or_else(|| "file".into());
    match native::save_file(&app, &name, &mime, &data).await {
        Ok(()) => Ok(()),
        Err(NativeError::Cancelled) => Err("Cancelled".into()),
        Err(e) => Err(native_err(e)),
    }
}

#[tauri::command]
async fn retry_attachment(c: State<'_, Client>, message: i64) -> Res<()> {
    c.retry_attachment(message).await.map_err(err)
}

#[tauri::command]
async fn mark_read(c: State<'_, Client>, contact: i64) -> Res<()> {
    c.mark_read(contact).await.map_err(err)
}

#[tauri::command]
async fn create_invite(c: State<'_, Client>) -> Res<InviteView> {
    c.create_invite().await.map_err(err)
}

#[tauri::command]
async fn accept_invite(c: State<'_, Client>, link: String) -> Res<ContactView> {
    c.accept_invite(link).await.map_err(err)
}

#[tauri::command]
async fn safety_number(c: State<'_, Client>, contact: i64) -> Res<SafetyView> {
    c.safety(contact).await.map_err(err)
}

#[tauri::command]
async fn set_verified(c: State<'_, Client>, contact: i64, verified: bool) -> Res<()> {
    c.set_verified(contact, verified).await.map_err(err)
}

#[tauri::command]
async fn rename_contact(c: State<'_, Client>, contact: i64, name: String) -> Res<()> {
    c.rename(contact, name).await.map_err(err)
}

#[tauri::command]
async fn delete_contact(c: State<'_, Client>, contact: i64) -> Res<()> {
    c.delete_contact(contact).await.map_err(err)
}

#[tauri::command]
async fn set_blocked(c: State<'_, Client>, contact: i64, blocked: bool) -> Res<()> {
    c.set_blocked(contact, blocked).await.map_err(err)
}

#[tauri::command]
async fn set_timer(c: State<'_, Client>, contact: i64, secs: u32) -> Res<()> {
    c.set_timer(contact, secs).await.map_err(err)
}

#[tauri::command]
async fn dismiss_key_warning(c: State<'_, Client>, contact: i64) -> Res<()> {
    c.dismiss_key_warning(contact).await.map_err(err)
}

#[tauri::command]
async fn privacy(c: State<'_, Client>) -> Res<PrivacyView> {
    c.privacy().await.map_err(err)
}

#[tauri::command]
async fn set_privacy(c: State<'_, Client>, privacy: PrivacyView) -> Res<()> {
    c.set_privacy(privacy).await.map_err(err)
}

#[tauri::command]
async fn typing(c: State<'_, Client>, contact: i64, started: bool) -> Res<()> {
    c.typing(contact, started).await.map_err(err)
}

/// Veil's files live in their own folder inside the app data directory, which on Android and
/// Windows also holds the WebView's data (review U-1). Files from 0.1 previews, which sat at
/// the top level, are moved in once.
fn data_dir(base: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let dir = base.join("vault");
    std::fs::create_dir_all(&dir)?;
    // Idempotent, header last: an interrupted move is finished on the next start, and the
    // vault only counts as moved once everything else is there (review UR2-4).
    let header = "vault.hdr";
    let files = veil_client::service::DATA_FILES
        .iter()
        .filter(|f| **f != header)
        .chain([&header]);
    for f in files {
        let from = base.join(f);
        if from.exists() && !dir.join(f).exists() {
            std::fs::rename(&from, dir.join(f))?;
        }
    }
    // Once the vault has moved, top-level copies are debris (review UR3-5).
    if dir.join(header).exists() {
        for f in veil_client::service::DATA_FILES {
            let _ = std::fs::remove_file(base.join(f));
        }
    }
    Ok(dir)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(native::plugin())
        .setup(|app| {
            let dir = data_dir(&app.path().app_data_dir()?)?;
            let handle = app.handle().clone();
            let notify = std::sync::Arc::new(move |kind: ChangeKind, contact: Option<i64>| {
                let _ = handle.emit("veil://changed", Changed { kind, contact });
            });
            let client = Client::start_with(
                dir,
                veil_client::service::default_kdf(),
                notify,
                veil_client::service::AUTO_LOCK,
                native::guard(app.handle()),
            )
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            app.manage(client);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            setup,
            unlock,
            lock,
            unlock_info,
            security,
            change_secret,
            set_purge,
            clear_purge,
            native_info,
            biometric_enable,
            biometric_disable,
            unlock_biometric,
            set_screenshots_allowed,
            set_dark_bars,
            touch,
            reset,
            me,
            contacts,
            messages,
            send,
            mark_read,
            create_invite,
            accept_invite,
            safety_number,
            set_verified,
            rename_contact,
            delete_contact,
            set_blocked,
            set_timer,
            dismiss_key_warning,
            privacy,
            set_privacy,
            typing,
            reply,
            react,
            edit_message,
            delete_for_everyone,
            delete_for_me,
            search,
            verify_scanned,
            send_attachment,
            attachment_data,
            save_attachment,
            retry_attachment
        ])
        .run(tauri::generate_context!());
    if result.is_err() {
        std::process::exit(1);
    }
}
