//! Notifications while Veil is locked (milestone 4, ADR-0016).
//!
//! When Veil locks with notifications on, the session (database, account, message keys) is
//! dropped as always, but the relay address, its pin, the mailbox id and the mailbox signing
//! key stay in memory. A connection authenticated with them hears the relay's "something
//! arrived" pushes. It never fetches, so it learns nothing about what arrived or from whom:
//! the notice says only "You may have new messages". The key is zeroized when Veil unlocks,
//! resets, purges or the process ends.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use veil_wire::ServerFrame;

use super::{Actor, ChangeKind, Session, authenticate};
use crate::relay::Relay;
use crate::{ClientError, Result};

/// At most one "you may have new messages" notice per this long.
const NOTICE_EVERY: Duration = Duration::from_mins(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

type Connected = Result<(Relay, mpsc::Receiver<ServerFrame>)>;

pub(super) struct Watcher {
    relay_addr: String,
    pin: [u8; 32],
    mailbox: [u8; 32],
    /// Zeroized on drop (`ed25519-dalek` with `zeroize`).
    key: ed25519_dalek::SigningKey,
    relay: Option<Relay>,
    pushes: Option<mpsc::Receiver<ServerFrame>>,
    connecting: Option<tokio::task::JoinHandle<Connected>>,
    next_attempt: Instant,
    backoff: Duration,
    last_notice: Option<Instant>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(h) = self.connecting.take() {
            h.abort();
        }
    }
}

/// What the run loop hears from the watcher.
pub(super) enum Event {
    Push(Option<ServerFrame>),
    Connected(core::result::Result<Connected, tokio::task::JoinError>),
}

impl Watcher {
    /// Waits for a push or the end of a connection attempt.
    pub(super) async fn next_event(&mut self) -> Event {
        if let Some(h) = self.connecting.as_mut() {
            return Event::Connected(h.await);
        }
        match self.pushes.as_mut() {
            Some(p) => Event::Push(p.recv().await),
            None => std::future::pending().await,
        }
    }

    pub(super) fn from_session(s: &Session) -> Self {
        Self {
            relay_addr: s.relay_addr.clone(),
            pin: s.pin,
            mailbox: s.mailbox,
            key: s.mbox_key.clone(),
            relay: None,
            pushes: None,
            connecting: None,
            next_attempt: Instant::now(),
            backoff: Duration::from_secs(2),
            last_notice: None,
        }
    }
}

impl Actor {
    pub(super) fn watcher_event(&mut self, e: Event) {
        match e {
            Event::Push(frame) => self.watcher_push(frame.as_ref()),
            Event::Connected(r) => self.watcher_connected(r),
        }
    }

    /// Starts a connection in the background if it is time; never blocks the actor.
    pub(super) fn watcher_tick(&mut self) {
        let Some(w) = self.watcher.as_mut() else { return };
        if w.relay.is_some() || w.connecting.is_some() || Instant::now() < w.next_attempt {
            return;
        }
        let (addr, pin, mailbox, key) = (w.relay_addr.clone(), w.pin, w.mailbox, w.key.clone());
        w.connecting = Some(tokio::task::spawn_local(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, async {
                let (relay, pushes) = Relay::connect(&addr, pin).await?;
                authenticate(&relay, &pin, &mailbox, &key).await?;
                Ok((relay, pushes))
            })
            .await
            .map_err(|_| ClientError::Unreachable)?
        }));
    }

    fn watcher_connected(&mut self, result: core::result::Result<Connected, tokio::task::JoinError>) {
        let Some(w) = self.watcher.as_mut() else { return };
        w.connecting = None;
        if let Ok(Ok((relay, pushes))) = result {
            w.relay = Some(relay);
            w.pushes = Some(pushes);
            w.backoff = Duration::from_secs(2);
        } else {
            w.backoff = w.backoff.saturating_mul(2).min(Duration::from_mins(5));
            w.next_attempt = Instant::now().checked_add(w.backoff).unwrap_or_else(Instant::now);
        }
    }

    fn watcher_push(&mut self, frame: Option<&ServerFrame>) {
        let Some(w) = self.watcher.as_mut() else { return };
        if frame.is_none() {
            w.relay = None;
            w.pushes = None;
            w.next_attempt = Instant::now().checked_add(w.backoff).unwrap_or_else(Instant::now);
            return;
        }
        if w.last_notice.is_some_and(|t| t.elapsed() < NOTICE_EVERY) {
            return;
        }
        w.last_notice = Some(Instant::now());
        // No contact: while locked Veil cannot know who it is from, or whether it is a message.
        self.emit(ChangeKind::Incoming, None);
    }
}
