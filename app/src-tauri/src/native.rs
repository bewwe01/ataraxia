//! Bridge to the Android code in `app/android/VeilNativePlugin.kt`: biometric sealing in the
//! Android Keystore, the screenshot setting and the system-bar colours. Desktop builds get
//! stubs that report "not available".
//!
//! Only this Rust code calls the plugin. The webview cannot: Tauri rejects `plugin:` IPC calls
//! that no capability allows, and `capabilities/default.json` allows nothing for `veil-native`
//! (ADR-0012). So the biometric secret moves between Rust and the Keystore only.

use tauri::Runtime;
use tauri::plugin::TauriPlugin;

/// Why a native call failed, for the user-facing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub enum NativeError {
    Unavailable,
    Cancelled,
    /// The Keystore key was invalidated (e.g. a fingerprint was added) or deleted.
    KeyGone,
    /// Too many failed biometric tries; the system locked biometrics for a while.
    Lockout,
    Failed,
}

#[cfg(target_os = "android")]
mod imp {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde::{Deserialize, Serialize};
    use tauri::plugin::PluginHandle;
    use tauri::plugin::mobile::PluginInvokeError;
    use tauri::{AppHandle, Manager as _, Runtime};
    use zeroize::Zeroizing;

    use super::NativeError;

    pub struct Native<R: Runtime>(pub PluginHandle<R>);

    #[derive(Deserialize)]
    struct Flag {
        value: bool,
    }
    #[derive(Serialize)]
    struct FlagArg {
        value: bool,
    }
    #[derive(Serialize)]
    struct SealArg {
        secret: Zeroizing<String>,
    }
    #[derive(Deserialize)]
    struct Sealed {
        blob: String,
    }
    #[derive(Serialize)]
    struct OpenArg {
        blob: String,
    }
    #[derive(Deserialize)]
    struct Opened {
        secret: Zeroizing<String>,
    }
    #[derive(Deserialize)]
    struct Empty {}

    fn handle<R: Runtime>(app: &AppHandle<R>) -> Result<PluginHandle<R>, NativeError> {
        app.try_state::<Native<R>>()
            .map(|n| n.0.clone())
            .ok_or(NativeError::Unavailable)
    }

    fn map(e: &PluginInvokeError) -> NativeError {
        match e {
            PluginInvokeError::InvokeRejected(r) => match r.code.as_deref() {
                Some("CANCELLED") => NativeError::Cancelled,
                Some("KEY_GONE") => NativeError::KeyGone,
                Some("UNAVAILABLE") => NativeError::Unavailable,
                Some("LOCKOUT") => NativeError::Lockout,
                _ => NativeError::Failed,
            },
            _ => NativeError::Failed,
        }
    }

    /// Seals the vault's device secret with a hardware Keystore key (no user authentication).
    /// Called from the client actor's own thread, never the main thread, so the blocking call
    /// is fine (review U-2).
    pub struct KeystoreGuard<R: Runtime>(pub PluginHandle<R>);

    /// Runs a blocking plugin call on its own thread with a timeout, so a lost response (for
    /// example the activity being destroyed) cannot hang or kill the client actor (UR2-8).
    fn call<R: Runtime, T: serde::de::DeserializeOwned + Send + 'static>(
        h: &PluginHandle<R>,
        cmd: &'static str,
        arg: serde_json::Value,
    ) -> Option<T> {
        let h = h.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("veil-keystore".into())
            .spawn(move || {
                let _ = tx.send(h.run_mobile_plugin::<T>(cmd, arg).ok());
            })
            .ok()?;
        rx.recv_timeout(std::time::Duration::from_secs(10)).ok().flatten()
    }

    impl<R: Runtime> veil_client::keystore::DeviceGuard for KeystoreGuard<R> {
        fn seal(&self, secret: &[u8; 32]) -> Option<Vec<u8>> {
            let arg = serde_json::json!({ "secret": B64.encode(secret) });
            let r: Sealed = call(&self.0, "deviceSeal", arg)?;
            B64.decode(r.blob).ok()
        }

        fn open(&self, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
            let r: Opened = call(
                &self.0,
                "deviceOpen",
                serde_json::json!({ "blob": B64.encode(blob) }),
            )?;
            let raw = Zeroizing::new(B64.decode(r.secret.as_bytes()).ok()?);
            let mut out = Zeroizing::new([0u8; 32]);
            if raw.len() != 32 {
                return None;
            }
            out.copy_from_slice(&raw);
            Some(out)
        }

        fn destroy(&self) -> bool {
            call::<R, Flag>(&self.0, "deviceDestroy", serde_json::Value::Null).is_some_and(|f| f.value)
        }
    }

    pub fn guard<R: Runtime>(app: &AppHandle<R>) -> veil_client::keystore::Guard {
        let h = handle(app).ok()?;
        Some(std::sync::Arc::new(KeystoreGuard(h)))
    }

    pub async fn biometric_available<R: Runtime>(app: &AppHandle<R>) -> bool {
        let Ok(h) = handle(app) else { return false };
        h.run_mobile_plugin_async::<Flag>("biometricAvailable", ())
            .await
            .is_ok_and(|f| f.value)
    }

    pub async fn seal<R: Runtime>(app: &AppHandle<R>, secret: &[u8; 32]) -> Result<Vec<u8>, NativeError> {
        let h = handle(app)?;
        let arg = SealArg {
            secret: Zeroizing::new(B64.encode(secret)),
        };
        let r: Sealed = h
            .run_mobile_plugin_async("seal", arg)
            .await
            .map_err(|e| map(&e))?;
        B64.decode(r.blob).map_err(|_| NativeError::Failed)
    }

    pub async fn open<R: Runtime>(
        app: &AppHandle<R>,
        blob: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, NativeError> {
        let h = handle(app)?;
        let r: Opened = h
            .run_mobile_plugin_async(
                "open",
                OpenArg {
                    blob: B64.encode(blob),
                },
            )
            .await
            .map_err(|e| map(&e))?;
        let raw = Zeroizing::new(B64.decode(r.secret.as_bytes()).map_err(|_| NativeError::Failed)?);
        let mut out = Zeroizing::new([0u8; 32]);
        if raw.len() != 32 {
            return Err(NativeError::Failed);
        }
        out.copy_from_slice(&raw);
        Ok(out)
    }

    pub async fn delete_key<R: Runtime>(app: &AppHandle<R>) {
        if let Ok(h) = handle(app) {
            let _ = h.run_mobile_plugin_async::<Option<Empty>>("deleteKey", ()).await;
        }
    }

    pub async fn screenshots_allowed<R: Runtime>(app: &AppHandle<R>) -> bool {
        let Ok(h) = handle(app) else { return false };
        h.run_mobile_plugin_async::<Flag>("screenshotsAllowed", ())
            .await
            .is_ok_and(|f| f.value)
    }

    pub async fn set_screenshots_allowed<R: Runtime>(
        app: &AppHandle<R>,
        allow: bool,
    ) -> Result<(), NativeError> {
        let h = handle(app)?;
        h.run_mobile_plugin_async::<Option<Empty>>("setScreenshotsAllowed", FlagArg { value: allow })
            .await
            .map(|_| ())
            .map_err(|e| map(&e))
    }

    pub async fn set_dark_bars<R: Runtime>(app: &AppHandle<R>, dark: bool) {
        if let Ok(h) = handle(app) {
            let _ = h
                .run_mobile_plugin_async::<Option<Empty>>("setDarkBars", FlagArg { value: dark })
                .await;
        }
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use tauri::{AppHandle, Runtime};
    use zeroize::Zeroizing;

    use super::NativeError;

    pub fn guard<R: Runtime>(_: &AppHandle<R>) -> veil_client::keystore::Guard {
        None
    }
    #[allow(clippy::unused_async)]
    pub async fn biometric_available<R: Runtime>(_: &AppHandle<R>) -> bool {
        false
    }
    #[allow(clippy::unused_async)]
    pub async fn seal<R: Runtime>(_: &AppHandle<R>, _: &[u8; 32]) -> Result<Vec<u8>, NativeError> {
        Err(NativeError::Unavailable)
    }
    #[allow(clippy::unused_async)]
    pub async fn open<R: Runtime>(_: &AppHandle<R>, _: &[u8]) -> Result<Zeroizing<[u8; 32]>, NativeError> {
        Err(NativeError::Unavailable)
    }
    #[allow(clippy::unused_async)]
    pub async fn delete_key<R: Runtime>(_: &AppHandle<R>) {}
    #[allow(clippy::unused_async)]
    pub async fn screenshots_allowed<R: Runtime>(_: &AppHandle<R>) -> bool {
        // Desktop windows can always be captured; there is no setting to show.
        true
    }
    #[allow(clippy::unused_async)]
    pub async fn set_screenshots_allowed<R: Runtime>(_: &AppHandle<R>, _: bool) -> Result<(), NativeError> {
        Err(NativeError::Unavailable)
    }
    #[allow(clippy::unused_async)]
    pub async fn set_dark_bars<R: Runtime>(_: &AppHandle<R>, _: bool) {}
}

pub use imp::*;

/// Registers the Android plugin; a no-op plugin elsewhere.
pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("veil-native")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                use tauri::Manager as _;
                let h = _api.register_android_plugin(super::ANDROID_PACKAGE, "VeilNativePlugin")?;
                _app.manage(imp::Native(h));
            }
            Ok(())
        })
        .build()
}

/// Whether this build can show a biometric option at all.
pub const fn biometric_platform() -> bool {
    cfg!(target_os = "android")
}
