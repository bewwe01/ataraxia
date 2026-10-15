//! Phase 1 spike: report what WebRTC the platform webview offers.
#![forbid(unsafe_code)]

use tauri::{WebviewUrl, WebviewWindowBuilder};

const MAX_REPORT: usize = 64 * 1024;

fn emit(line: &str) {
    #[cfg(target_os = "android")]
    log::info!("{line}");
    #[cfg(not(target_os = "android"))]
    println!("{line}");
}

#[tauri::command]
fn report(app: tauri::AppHandle, result: String) {
    if result.len() > MAX_REPORT {
        emit("VEIL_PROBE_RESULT {\"error\":\"oversized report\"}");
    } else {
        emit(&format!("VEIL_PROBE_RESULT {result}"));
    }
    if std::env::var_os("VEIL_PROBE_EXIT").is_some() {
        app.exit(0);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "android")]
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("VeilProbe"));

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![report])
        .setup(|app| {
            // Start blank so platform settings are applied BEFORE the probe page loads.
            let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("blank.html".into())).title("Veil WebRTC probe").build()?;
            #[cfg(target_os = "linux")]
            {
                let enable = std::env::var_os("VEIL_ENABLE_WEBRTC").is_some();
                win.with_webview(move |wv| {
                    use webkit2gtk::{SettingsExt, WebViewExt};
                    if let Some(s) = wv.inner().settings() {
                        emit(&format!("VEIL_PROBE_INFO webkit enable-webrtc default={} media-stream default={}", s.enables_webrtc(), s.enables_media_stream()));
                        if enable {
                            s.set_enable_webrtc(true);
                            s.set_enable_media_stream(true);
                            emit("VEIL_PROBE_INFO set enable-webrtc=true enable-media-stream=true");
                        }
                    }
                })?;
            }
            win.eval("location.replace('index.html')")?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running probe");
}
