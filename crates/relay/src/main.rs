//! `veil-relay`: the Veil relay server.
//!
//! ```text
//! veil-relay gen-cert <dir> <dns-name>...   create cert.pem/key.pem, print the SPKI pin
//! veil-relay pin <cert.pem> <key.pem>       print the SPKI pin of an existing pair
//! veil-relay [serve]                        run (configured by environment variables)
//! ```
//!
//! Environment (all optional except where noted):
//! * `VEIL_RELAY_LISTEN` (default `0.0.0.0:8443`)
//! * `VEIL_RELAY_DATA` (default `/data`): database directory
//! * `VEIL_RELAY_CERT`, `VEIL_RELAY_KEY` (default `<data>/tls/cert.pem`, `<data>/tls/key.pem`)
//! * `VEIL_TURN_SECRET_FILE`: file holding coturn's `static-auth-secret` (enables TURN)
//! * `VEIL_TURN_URLS`: comma-separated `turn:`/`turns:` URLs handed to clients
//! * `VEIL_QUOTA_ENVELOPES_MB` (default 1024), `VEIL_QUOTA_BLOBS_MB` (default 4096): disk caps for
//!   queued envelopes and attachment blobs
//! * `VEIL_MAX_CONN_PER_SOURCE` (default 32): concurrent connections per IPv4 address or
//!   IPv6 /64. Every other per-source allowance scales with it; raise it when a proxy makes
//!   many clients share one source address
//! * `VEIL_DB_CACHE_MB` (default 64): database page cache, the main part of the relay's memory
//! * `VEIL_LOG` (default `info`): `error`, `warn`, `info` or `debug`
#![forbid(unsafe_code)]

use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use veil_relay::server::{self, Config, Shared};
use veil_relay::store::Store;
use veil_relay::tls;
use veil_relay::turn::TurnConfig;
use zeroize::Zeroizing;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn out(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

fn fail(line: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "veil-relay: {line}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen-cert") => {
            let (Some(dir), names) = (args.get(1), args.get(2..).unwrap_or_default().to_vec()) else {
                return fail("usage: veil-relay gen-cert <dir> <dns-name>...");
            };
            if names.is_empty() {
                return fail("give at least one DNS name or IP the clients will use");
            }
            match tls::generate(&PathBuf::from(dir), names) {
                Ok(pin) => {
                    out(&format!("SPKI SHA-256 pin: {}", tls::hex(&pin)));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        Some("pin") => {
            let (Some(cert), Some(key)) = (args.get(1), args.get(2)) else {
                return fail("usage: veil-relay pin <cert.pem> <key.pem>");
            };
            match tls::load(&PathBuf::from(cert), &PathBuf::from(key)) {
                Ok((_, pin)) => {
                    out(&tls::hex(&pin));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        None | Some("serve") => serve(),
        Some(_) => fail("unknown command (gen-cert, pin, serve)"),
    }
}

/// Storage caps and the per-source connection cap from the environment.
fn limits_from_env(cfg: &mut Config) -> Result<(), String> {
    for (name, slot) in [
        (
            "VEIL_QUOTA_ENVELOPES_MB",
            &mut cfg.quotas.max_envelope_bytes_total,
        ),
        ("VEIL_QUOTA_BLOBS_MB", &mut cfg.quotas.max_blob_bytes_total),
    ] {
        if let Some(v) = env(name) {
            match v.parse::<u64>().ok().and_then(|mb| mb.checked_mul(1024 * 1024)) {
                Some(bytes) if bytes > 0 => *slot = bytes,
                _ => return Err(format!("{name} must be a positive number of megabytes")),
            }
        }
    }
    if let Some(v) = env("VEIL_MAX_CONN_PER_SOURCE") {
        match v.parse::<u32>() {
            Ok(n) if (1..=1024).contains(&n) => cfg.set_per_source_connections(n),
            _ => return Err("VEIL_MAX_CONN_PER_SOURCE must be between 1 and 1024".into()),
        }
    }
    Ok(())
}

fn serve() -> ExitCode {
    let level = match env("VEIL_LOG").as_deref() {
        Some("error") => tracing::Level::ERROR,
        Some("warn") => tracing::Level::WARN,
        Some("debug") => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let data = PathBuf::from(env("VEIL_RELAY_DATA").unwrap_or_else(|| "/data".into()));
    let cert = env("VEIL_RELAY_CERT").map_or_else(|| data.join("tls/cert.pem"), PathBuf::from);
    let key = env("VEIL_RELAY_KEY").map_or_else(|| data.join("tls/key.pem"), PathBuf::from);
    let listen = env("VEIL_RELAY_LISTEN").unwrap_or_else(|| "0.0.0.0:8443".into());

    let (tls_config, pin) = match tls::load(&cert, &key) {
        Ok(v) => v,
        Err(e) => return fail(&format!("TLS: {e} (run `veil-relay gen-cert` first)")),
    };
    let mut cfg = Config::default();
    if let Err(e) = limits_from_env(&mut cfg) {
        return fail(&e);
    }
    if let Some(path) = env("VEIL_TURN_SECRET_FILE") {
        let Ok(raw) = std::fs::read(&path).map(Zeroizing::new) else {
            return fail("cannot read VEIL_TURN_SECRET_FILE");
        };
        let secret = Zeroizing::new(raw.trim_ascii().to_vec());
        drop(raw);
        if secret.len() < 32 {
            return fail("the TURN secret must be at least 32 bytes");
        }
        let urls: Vec<String> = env("VEIL_TURN_URLS")
            .unwrap_or_default()
            .split(',')
            .map(|u| u.trim().to_owned())
            .filter(|u| !u.is_empty())
            .collect();
        if urls.is_empty()
            || urls.len() > 4
            || !urls
                .iter()
                .all(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        {
            return fail("VEIL_TURN_URLS must list 1-4 turn:/turns: URLs");
        }
        cfg.turn = Some(TurnConfig {
            secret,
            urls,
            ttl_secs: 3600,
        });
    }
    let cache_mb = match env("VEIL_DB_CACHE_MB").map(|v| v.parse::<usize>()) {
        None => 64,
        Some(Ok(mb)) if (8..=4096).contains(&mb) => mb,
        Some(_) => return fail("VEIL_DB_CACHE_MB must be between 8 and 4096"),
    };
    let store = match Store::open_with_cache(
        &data.join("relay.redb"),
        cfg.quotas,
        cache_mb.saturating_mul(1024 * 1024),
    ) {
        Ok(s) => s,
        Err(e) => return fail(&format!("database: {e}")),
    };
    let turn_enabled = cfg.turn.is_some();
    let shared = Shared::new(store, cfg, pin, server::system_clock());

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        return fail("cannot start the async runtime");
    };
    rt.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::bind(&listen).await else {
            return fail(&format!("cannot listen on {listen}"));
        };
        // Operator-facing startup facts only: no client data is ever logged.
        tracing::info!(listen = %listen, pin = %tls::hex(&pin), turn = turn_enabled, "veil-relay started");
        // SIGTERM is what `docker stop` sends; as PID 1 it is otherwise ignored (P3-9).
        let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) else {
            return fail("cannot install the SIGTERM handler");
        };
        let shutdown = async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        };
        server::serve(listener, tls_config, shared, shutdown).await;
        tracing::info!("veil-relay stopped");
        ExitCode::SUCCESS
    })
}
