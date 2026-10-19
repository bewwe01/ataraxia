//! The Tauri shell: maps the commands in `app/src/ipc.ts` onto [`veil_client::service::Client`].
//!
//! Everything returned here is display data (CLAUDE.md rule 2). Errors cross as the short,
//! content-free `Display` strings of [`veil_client::ClientError`].
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use tauri::{Emitter as _, Manager as _, State};
use veil_client::ClientError;
use veil_client::service::{
    AppState, ChangeKind, Client, ContactView, InviteView, MeView, MessageView, SafetyView, SetupInput,
};
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
    passphrase: Zeroizing<String>,
}

#[tauri::command]
async fn app_state(c: State<'_, Client>) -> Res<AppState> {
    c.state().await.map_err(err)
}

#[tauri::command]
async fn setup(c: State<'_, Client>, input: SetupForm) -> Res<()> {
    let SetupForm { relay, pin, name, passphrase } = input;
    c.setup(SetupInput { relay, pin, name, passphrase }).await.map_err(err)
}

#[tauri::command]
async fn unlock(c: State<'_, Client>, passphrase: Zeroizing<String>) -> Res<()> {
    c.unlock(passphrase).await.map_err(err)
}

#[tauri::command]
async fn lock(c: State<'_, Client>) -> Res<()> {
    c.lock().await.map_err(err)
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
