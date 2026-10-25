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
    AppState, ChangeKind, Client, ContactView, InviteView, MeView, MessageView, SafetyView, SecurityView,
    SetupInput, UnlockInfo, UnlockOutcome,
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
        UnlockOutcome::Purged => {
            finish_purge(&app).await;
            Err(err(ClientError::WrongPassphrase))
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
        NativeError::Failed => "Biometric unlock failed".into(),
    }
}

/// What this device offers, for showing or hiding settings.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeInfo {
    biometric: bool,
    screenshot_setting: bool,
    screenshots_allowed: bool,
}

#[tauri::command]
async fn native_info(app: AppHandle) -> NativeInfo {
    NativeInfo {
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
    match native::seal(&app, &secret).await {
        Ok(sealed) => c.biometric_commit(sealed).await.map_err(err),
        Err(e) => {
            let _ = c.biometric_disable().await;
            Err(native_err(e))
        }
    }
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
async fn set_screenshots_allowed(app: AppHandle, allow: bool) -> Res<()> {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(native::plugin())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let handle = app.handle().clone();
            let notify = std::sync::Arc::new(move |kind: ChangeKind, contact: Option<i64>| {
                let _ = handle.emit("veil://changed", Changed { kind, contact });
            });
            let client = Client::start(dir, veil_client::service::default_kdf(), notify)
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
            rename_contact
        ])
        .run(tauri::generate_context!());
    if result.is_err() {
        std::process::exit(1);
    }
}
