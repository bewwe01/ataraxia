//! Voice and video calls (milestone 6, ADR-0018, PROTOCOL §8).
//!
//! Media runs in the webview's WebRTC stack, relay-only (`iceTransportPolicy: "relay"`) through
//! the TURN server the relay names. Rust carries the signaling: offers, answers, hangups and
//! "busy" travel as `Content::Call` over the end-to-end encrypted session, and every SDP is
//! rebuilt by the core's allowlist filter in both directions (INV-NET-1, INV-NET-4), so the
//! DTLS fingerprint that keys the media is authenticated by the session.
//!
//! Signals a contact sends are kept in memory only (never in the database) until the UI
//! takes them, and go with the session when Veil locks.

use std::collections::VecDeque;
use std::net::IpAddr;

use serde::Serialize;
use veil_core::content::{Body, Call, CallKind};
use veil_core::ice::{self, Mode, SdpRole};
use veil_wire::{Request, Response};

use super::{Actor, ChangeKind};
use crate::{ClientError, Result, now_ms};

/// A call signal not delivered within this long is dropped by the receiver, and our own
/// queued copy expires: a late offer must never ring.
const SIGNAL_TTL_MS: i64 = 60_000;
/// Incoming signals kept for the UI to take; older ones are dropped first.
const MAX_PENDING: usize = 32;

/// One TURN server for the webview's `RTCPeerConnection`.
#[derive(Clone, Serialize)]
pub struct IceServerView {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// Redacted: the login is a short-lived token (review C6-10).
impl core::fmt::Debug for IceServerView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IceServerView")
            .field("urls", &self.urls)
            .finish_non_exhaustive()
    }
}

/// What the webview needs to start or answer a call: the TURN servers it may use. The
/// credentials are the relay's short-lived TURN login (no identity in them), not Veil keys.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSetup {
    pub ice_servers: Vec<IceServerView>,
}

/// A call signal from a contact, after filtering, for the UI.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSignal {
    pub contact: i64,
    /// 32 hex characters.
    pub call_id: String,
    /// `offer`, `answer`, `hangup` or `busy`.
    pub kind: String,
    /// Offers and answers: the filtered SDP.
    pub sdp: Option<String>,
    /// Offers: whether the caller asks for video.
    pub video: bool,
}

/// Redacted: the SDP holds the call's ICE password and fingerprint (review C6-10).
impl core::fmt::Debug for CallSignal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallSignal")
            .field("contact", &self.contact)
            .field("kind", &self.kind)
            .field("video", &self.video)
            .finish_non_exhaustive()
    }
}

/// What the UI sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outgoing {
    Offer,
    Answer,
    Hangup,
    Busy,
}

impl Outgoing {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "offer" => Self::Offer,
            "answer" => Self::Answer,
            "hangup" => Self::Hangup,
            "busy" => Self::Busy,
            _ => return None,
        })
    }
}

/// The relay's host, when the user configured it as a private or tailnet IP: the one non-public
/// TURN address we accept, because it is the user's own server (ADR-0018).
pub(super) fn own_turn(relay_addr: &str) -> Vec<IpAddr> {
    host_of(relay_addr)
        .and_then(|h| h.parse::<IpAddr>().ok())
        .into_iter()
        .collect()
}

/// `host` from `host:port`, `[v6]:port` or a bare host.
fn host_of(addr: &str) -> Option<&str> {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h);
    }
    match addr.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => Some(h),
        // A bare host, or a bare IPv6 address.
        _ => Some(addr),
    }
}

/// Whether the webview may use this TURN URL. The relay is not trusted to point us at our own
/// network: an IP must be public, or be the relay's own private address; a name must look like
/// a public DNS name, ending in an alphabetic top-level label, so shorthand IPv4 that resolvers
/// accept (`127.1`, `192.168.1`, `0x7f.1`) is refused (review C6-3). A name is only checked
/// for its form: what it resolves to is up to DNS (ADR-0018, Costs).
pub(super) fn turn_url_ok(url: &str, own: &[IpAddr]) -> bool {
    let Some(rest) = url.strip_prefix("turn:").or_else(|| url.strip_prefix("turns:")) else {
        return false;
    };
    if url.len() > 256 || !url.is_ascii() || url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return false;
    }
    let target = rest.split('?').next().unwrap_or_default();
    let Some(host) = host_of(target) else { return false };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return own.contains(&ip) || is_public(ip);
    }
    let lower = host.to_ascii_lowercase();
    // Names that only mean something on a local network.
    let local = ["local", "localhost", "internal", "lan", "home.arpa"]
        .iter()
        .any(|suffix| lower == *suffix || lower.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.')));
    let tld_ok = lower
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
    lower.contains('.')
        && tld_ok
        && !local
        && lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Whether a signal sent at `sent_at_ms` (the sender's clock) is too old to act on: its TTL
/// plus 30 s for clocks that disagree. A sender whose clock is further behind than that cannot
/// call (ADR-0018, Costs); one ahead is not penalised.
fn is_stale(now_ms: i64, sent_at_ms: u64) -> bool {
    let sent = i64::try_from(sent_at_ms).unwrap_or(i64::MAX);
    now_ms.saturating_sub(sent) > SIGNAL_TTL_MS + 30_000
}

/// Public unicast, judged the way the core judges relay candidates.
fn is_public(ip: IpAddr) -> bool {
    let line = format!("candidate:1 1 udp 1 {ip} 9 typ relay");
    ice::filter_candidate(&line, Mode::RelayOnly).is_some()
}

/// A video call is one whose first video section (the camera, ADR-0018) is sending. Voice
/// calls carry the same sections with the camera inactive, so screen sharing needs no new offer.
fn video_in(sdp: &str) -> bool {
    let mut camera = sdp
        .split("\r\n")
        .skip_while(|l| !l.starts_with("m=video "))
        .skip(1)
        .take_while(|l| !l.starts_with("m="));
    !camera.any(|l| l == "a=inactive" || l == "a=recvonly")
        && sdp.split("\r\n").any(|l| l.starts_with("m=video "))
}

fn decode_id(hex: &str) -> Result<Vec<u8>> {
    if hex.len() != 32 {
        return Err(ClientError::BadInput);
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or(ClientError::BadInput)
        })
        .collect()
}

fn encode_id(id: &[u8]) -> String {
    use core::fmt::Write as _;
    id.iter().fold(String::with_capacity(32), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Incoming signals waiting for the UI (in memory only).
#[derive(Default)]
pub(super) struct Pending(std::cell::RefCell<VecDeque<CallSignal>>);

impl Pending {
    fn push(&self, s: CallSignal) {
        let mut q = self.0.borrow_mut();
        if q.len() >= MAX_PENDING {
            q.pop_front();
        }
        q.push_back(s);
    }

    fn take(&self) -> Vec<CallSignal> {
        self.0.borrow_mut().drain(..).collect()
    }
}

impl Actor {
    /// TURN servers for a call with `contact` (who must exist and not be blocked).
    pub(super) async fn call_setup(&self, contact: i64) -> Result<CallSetup> {
        let s = self.s()?;
        let blocked: bool =
            s.db.conn()
                .query_row("SELECT blocked FROM contacts WHERE id = ?1", [contact], |r| {
                    r.get(0)
                })
                .map_err(|_| ClientError::UnknownContact)?;
        if blocked {
            return Err(ClientError::Blocked);
        }
        let own = own_turn(&s.relay_addr);
        let Response::Turn(t) = self
            .call(Request::TurnCredentials(veil_wire::MailboxRef {
                mailbox_id: s.mailbox.to_vec(),
            }))
            .await
            .map_err(|e| match e {
                // The relay has no TURN server configured.
                ClientError::Rejected(veil_wire::ErrorCode::Unsupported) => ClientError::NoCalls,
                e => e,
            })?
        else {
            return Err(ClientError::Relay);
        };
        let urls: Vec<String> = t.urls.into_iter().filter(|u| turn_url_ok(u, &own)).collect();
        if urls.is_empty() || t.username.is_empty() || t.credential.is_empty() {
            return Err(ClientError::NoCalls);
        }
        Ok(CallSetup {
            ice_servers: vec![IceServerView {
                urls,
                username: t.username,
                credential: t.credential,
            }],
        })
    }

    /// Sends one signal now. Offers and answers are filtered first; nothing is kept for later
    /// beyond a minute, so a call that could not be signalled never rings afterwards.
    pub(super) async fn call_send(
        &mut self,
        contact: i64,
        call_id: &str,
        kind: Outgoing,
        sdp: Option<String>,
    ) -> Result<()> {
        let s = self.s()?;
        let id = decode_id(call_id)?;
        let own = own_turn(&s.relay_addr);
        let filtered = |role| -> Result<String> {
            let raw = sdp.as_deref().ok_or(ClientError::BadInput)?;
            ice::filter_sdp_with(raw, Mode::RelayOnly, role, &own).map_err(|_| ClientError::BadInput)
        };
        let kind = match kind {
            Outgoing::Offer => CallKind::Offer(filtered(SdpRole::Offer)?),
            Outgoing::Answer => CallKind::Answer(filtered(SdpRole::Answer)?),
            Outgoing::Hangup => CallKind::Hangup("ended".into()),
            Outgoing::Busy => CallKind::Busy(true),
        };
        let body = Body::Call(Call {
            call_id: id,
            kind: Some(kind),
        });
        let expires = now_ms().saturating_add(SIGNAL_TTL_MS);
        let row = self
            .atomically(async { self.queue_control(contact, body, Some(expires)).await })
            .await?;
        if self.deliver(row).await {
            Ok(())
        } else {
            // A call signal is only worth sending now: never retried after a reconnect, where a
            // late offer would ring for a call the caller gave up on (review C6-2). Gone from
            // the database too, so nothing of a call stays at rest (C6-6).
            self.s()?
                .db
                .conn()
                .execute("DELETE FROM messages WHERE id = ?1 AND kind = 'control'", [row])?;
            Err(ClientError::Unreachable)
        }
    }

    /// The signals that arrived since the last call; each is returned once.
    pub(super) fn call_signals(&self) -> Result<Vec<CallSignal>> {
        Ok(self.s()?.calls.take())
    }

    /// A call signal from a contact (inside `process`'s transaction). Stale, malformed or
    /// unfilterable signals are dropped; an offer also asks the shell to ring.
    pub(super) fn receive_call(&self, contact: i64, sent_at_ms: u64, c: Call) -> Result<()> {
        let s = self.s()?;
        let blocked: bool =
            s.db.conn()
                .query_row("SELECT blocked FROM contacts WHERE id = ?1", [contact], |r| {
                    r.get(0)
                })?;
        if blocked || is_stale(now_ms(), sent_at_ms) {
            return Ok(());
        }
        let own = own_turn(&s.relay_addr);
        let incoming = |sdp: &str, role| ice::filter_sdp_with(sdp, Mode::RelayOnly, role, &own).ok();
        let (kind, sdp) = match c.kind {
            Some(CallKind::Offer(sdp)) => ("offer", incoming(&sdp, SdpRole::Offer)),
            Some(CallKind::Answer(sdp)) => ("answer", incoming(&sdp, SdpRole::Answer)),
            Some(CallKind::Hangup(_)) => ("hangup", None),
            Some(CallKind::Busy(_)) => ("busy", None),
            // Trickled candidates: we send complete SDPs, so there is nothing to add them to.
            Some(CallKind::Ice(_)) | None => return Ok(()),
        };
        if matches!(kind, "offer" | "answer") && sdp.is_none() {
            return Ok(());
        }
        let video = sdp.as_deref().is_some_and(video_in);
        s.calls.push(CallSignal {
            contact,
            call_id: encode_id(&c.call_id),
            kind: kind.into(),
            sdp,
            video,
        });
        if kind == "offer" {
            self.emit(ChangeKind::Ringing, Some(contact));
        }
        self.emit(ChangeKind::Call, Some(contact));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_signals_are_stale() {
        let now = 1_800_000_000_000_i64;
        let at = |ago: i64| u64::try_from(now - ago).unwrap();
        assert!(!is_stale(now, at(0)));
        assert!(!is_stale(now, at(89_000)));
        assert!(!is_stale(now, at(90_000)));
        assert!(is_stale(now, at(90_001)));
        assert!(is_stale(now, at(91_000)));
        assert!(is_stale(now, 0));
        // From the future (a clock ahead) and absurd values: not stale, no overflow.
        assert!(!is_stale(now, at(-3_600_000)));
        assert!(!is_stale(now, u64::MAX));
        assert!(is_stale(i64::MAX, 0));
    }

    #[test]
    fn turn_urls_from_the_relay_are_checked() {
        let own = own_turn("100.101.102.103:8443");
        assert!(turn_url_ok("turn:100.101.102.103:3478?transport=udp", &own));
        assert!(turn_url_ok("turns:relay.example.org:443?transport=tcp", &own));
        assert!(turn_url_ok("turn:8.8.4.4:3478", &own));
        for bad in [
            "turn:192.168.1.1:3478",
            "turn:100.101.102.104:3478",
            "turn:127.0.0.1",
            "turn:router.lan:3478",
            "turn:printer.local",
            "turn:localhost:3478",
            "stun:8.8.4.4:3478",
            "http://8.8.4.4",
            "turn:8.8.4.4:3478 ?x",
            // Shorthand IPv4 that system resolvers accept (review C6-3).
            "turn:127.1:3478",
            "turn:10.1",
            "turn:192.168.1:3478?transport=tcp",
            "turn:0x7f.1",
            "turn:1.2.3.4.5",
        ] {
            assert!(!turn_url_ok(bad, &own), "{bad}");
        }
        // A relay reached by name: no private TURN address is anyone's own.
        assert!(own_turn("relay.example.org:8443").is_empty());
        assert!(!turn_url_ok(
            "turn:100.101.102.103:3478",
            &own_turn("relay.example.org:8443")
        ));
        assert_eq!(
            own_turn("[fd00::1]:8443"),
            vec!["fd00::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn the_camera_section_tells_voice_from_video() {
        let call = |camera: &str| {
            format!(
                "v=0\r\nm=audio 9 X 111\r\na=sendrecv\r\nm=video 9 X 96\r\na={camera}\r\n\
                 m=video 9 X 96\r\na=sendrecv\r\nm=audio 9 X 111\r\na=sendrecv\r\n"
            )
        };
        assert!(video_in(&call("sendrecv")));
        assert!(video_in(&call("sendonly")));
        assert!(!video_in(&call("inactive")));
        assert!(!video_in(&call("recvonly")));
        assert!(!video_in("v=0\r\nm=audio 9 X 111\r\na=sendrecv\r\n"));
        // Real Chromium calls (crates/core/tests/vectors/sdp), after the filter.
        let own: [std::net::IpAddr; 1] = [std::net::Ipv4Addr::LOCALHOST.into()];
        for (sdp, role, video) in [
            (
                include_str!("../../../core/tests/vectors/sdp/chromium-video-offer.sdp"),
                ice::SdpRole::Offer,
                true,
            ),
            (
                include_str!("../../../core/tests/vectors/sdp/chromium-video-answer.sdp"),
                ice::SdpRole::Answer,
                true,
            ),
            (
                include_str!("../../../core/tests/vectors/sdp/chromium-voice-offer.sdp"),
                ice::SdpRole::Offer,
                false,
            ),
            (
                include_str!("../../../core/tests/vectors/sdp/chromium-voice-answer.sdp"),
                ice::SdpRole::Answer,
                false,
            ),
        ] {
            let out = ice::filter_sdp_with(sdp, ice::Mode::RelayOnly, role, &own).unwrap();
            assert_eq!(video_in(&out), video);
        }
    }

    #[test]
    fn call_ids_round_trip_and_are_checked() {
        let id = vec![0xab; 16];
        assert_eq!(decode_id(&encode_id(&id)).unwrap(), id);
        assert!(decode_id("abc").is_err());
        assert!(decode_id(&"zz".repeat(16)).is_err());
    }
}
