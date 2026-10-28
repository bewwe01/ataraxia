// The call screen (DESIGN.md §6 `<CallScreen>`, `<CallControls>`, `<TransportChip>`; proto
// `callContent`). It sits over whatever screen was open, for ringing, calling and the call
// itself. Calls are always relayed: the chip says so.
//
// Sound: every <video> here is muted, and the other side's voice and their shared screen's
// sound play through their own <audio> elements, so deafening silences both and the stream
// volume applies to the screen's sound only.
import { useCallback, useEffect, useRef, useState } from "react";
import { calls, canShare, QUALITIES, type CallState, type Quality } from "../calls";
import type { ContactView } from "../ipc";
import { Avatar, Icon, useDialogKeys } from "../ui";

const QUALITY_KEY = "veil.shareQuality";

function savedQuality(): Quality {
  try {
    const q = localStorage.getItem(QUALITY_KEY);
    if (q === "1080p60" || q === "720p30") return q;
  } catch {
    // No storage: use the default.
  }
  return "1080p60";
}

function saveQuality(q: Quality) {
  try {
    localStorage.setItem(QUALITY_KEY, q);
  } catch {
    // Not remembered; nothing else changes.
  }
}

function clock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
}

/** A silent `<video>` showing a stream. */
function StreamVideo({ stream, className, label }: { stream: MediaStream | null; className: string; label: string }) {
  const el = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (el.current && el.current.srcObject !== stream) el.current.srcObject = stream;
  }, [stream]);
  return <video ref={el} className={className} autoPlay playsInline muted aria-label={label} />;
}

/** Plays a stream's sound. */
function StreamAudio({ stream, muted, volume = 1 }: { stream: MediaStream | null; muted: boolean; volume?: number }) {
  const el = useRef<HTMLAudioElement>(null);
  useEffect(() => {
    if (el.current && el.current.srcObject !== stream) el.current.srcObject = stream;
  }, [stream]);
  useEffect(() => {
    if (el.current) el.current.volume = volume;
  }, [volume]);
  return <audio ref={el} autoPlay muted={muted} />;
}

function Ctl({ icon, label, text, pressed, tone, expanded, onClick }: { icon: string; label: string; text: string; pressed?: boolean; tone?: "end" | "accept"; expanded?: boolean; onClick: () => void }) {
  return (
    <span className="call-ctl">
      <button className={`icon-btn ${tone ?? ""}`} type="button" aria-label={label} aria-pressed={pressed} aria-expanded={expanded} onClick={onClick}>
        <Icon name={icon} />
      </button>
      {text}
    </span>
  );
}

/** One state pill: an icon and words, so the state never rests on colour alone. */
function Pill({ icon, text }: { icon: string; text: string }) {
  return (
    <span className="call-state">
      <Icon name={icon} />
      {text}
    </span>
  );
}

/** The quality bubble for screen sharing (owner's reference: a "Stream Mode" radio list). */
function ShareSheet({ call, onClose }: { call: CallState; onClose: () => void }) {
  const [quality, setQuality] = useState<Quality>(call.sharing ?? savedQuality());
  const box = useRef<HTMLDivElement>(null);

  // Focus the chosen quality once, when the bubble opens; Escape closes it and Tab stays in it.
  useEffect(() => {
    box.current?.querySelector<HTMLInputElement>("input:checked")?.focus();
  }, []);
  useDialogKeys(box, onClose);

  const pick = (q: Quality) => {
    setQuality(q);
    saveQuality(q);
    // A running share changes at once.
    if (call.sharing) void calls.share(q);
  };

  return (
    <>
      <div className="share-scrim" aria-hidden="true" onClick={onClose} />
      <div className="share-sheet" role="dialog" aria-modal="true" aria-labelledby="share-title" ref={box}>
        <div className="share-head">
          <span id="share-title">Stream quality</span>
          <button className="icon-btn" type="button" aria-label="Close" onClick={onClose}>
            <Icon name="x" />
          </button>
        </div>
        <div role="radiogroup" aria-labelledby="share-title">
          {(Object.keys(QUALITIES) as Quality[]).map((q) => (
            <label key={q} className="share-option">
              <span>
                <span className="share-option-title">{QUALITIES[q].title}</span>
                <span className="share-option-detail">{QUALITIES[q].detail}</span>
              </span>
              <input type="radio" name="share-quality" checked={quality === q} onChange={() => pick(q)} />
            </label>
          ))}
        </div>
        {call.sharing ? (
          <button className="btn btn-danger btn-block" type="button" onClick={() => { calls.stopShare(); onClose(); }}>
            Stop sharing
          </button>
        ) : (
          <button className="btn btn-primary btn-block" type="button" onClick={() => { onClose(); void calls.share(quality); }}>
            Share screen
          </button>
        )}
      </div>
    </>
  );
}

export function CallScreen({ call, contact }: { call: CallState; contact: ContactView | undefined }) {
  const [now, setNow] = useState(Date.now());
  const [sheet, setSheet] = useState(false);
  const first = useRef<HTMLDivElement>(null);
  // Stable, so the bubble's effects do not rerun with the clock (review C6-4); focus goes back
  // to the Share button.
  const closeSheet = useCallback(() => {
    setSheet(false);
    first.current?.querySelector<HTMLButtonElement>('button[aria-label="Share screen"]')?.focus();
  }, []);
  const name = contact?.name ?? "Contact";
  const live = call.phase === "active";
  const theirScreen = live && call.peer.sharing && (call.remoteScreen?.getVideoTracks().length ?? 0) > 0;
  const theirCamera = live && call.video && !call.peer.cameraOff && call.remote !== null;
  const myCamera = call.video && call.phase !== "incoming" && call.local !== null && !call.cameraOff;
  // Picture when there is one of theirs to show; otherwise their avatar.
  const visual = theirScreen || theirCamera;

  useEffect(() => {
    if (!live) {
      setSheet(false);
      return;
    }
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [live]);

  // Focus the main action when the screen appears or changes phase.
  useEffect(() => {
    first.current?.querySelector<HTMLButtonElement>("button")?.focus();
  }, [call.phase]);

  const status =
    call.phase === "incoming" ? `Incoming ${call.video ? "video" : "voice"} call`
    : call.phase === "calling" ? "Calling…"
    : call.phase === "connecting" ? "Connecting…"
    : call.phase === "ended" ? call.ended ?? "Call ended"
    : clock(now - (call.startedAt ?? now));

  const chip = (
    <span className="transport-chip relay" aria-describedby="call-relay">
      <Icon name="shield" />Relayed · IP hidden
      <span className="sr-only" id="call-relay">Relayed through your TURN server. {name} cannot see your IP address.</span>
    </span>
  );

  // Who is muted, deafened or sharing: shown the same way on both ends.
  const pills = live ? (
    <div className="call-states">
      {call.peer.deafened ? <Pill icon="headphones-off" text={`${name} is deafened`} />
        : call.peer.muted ? <Pill icon="mic-off" text={`${name} is muted`} /> : null}
      {call.deafened ? <Pill icon="headphones-off" text="You're deafened" />
        : call.muted ? <Pill icon="mic-off" text="You're muted" /> : null}
      {call.sharing ? <Pill icon="screen-share" text="You're sharing your screen" /> : null}
    </div>
  ) : null;

  let controls;
  if (call.phase === "incoming") {
    controls = (
      <>
        <Ctl icon="phone-off" tone="end" label="Decline" text="Decline" onClick={() => calls.decline()} />
        <Ctl icon={call.video ? "video" : "phone"} tone="accept" label={`Accept ${call.video ? "video" : "voice"} call`} text="Accept" onClick={() => void calls.accept()} />
      </>
    );
  } else if (call.phase === "ended") {
    controls = null;
  } else {
    const micOff = call.muted || call.deafened;
    controls = (
      <>
        <Ctl icon={micOff ? "mic-off" : "mic"} label="Mute microphone" text={micOff ? "Unmute" : "Mute"} pressed={micOff} onClick={() => calls.toggleMute()} />
        <Ctl icon={call.deafened ? "headphones-off" : "headphones"} label="Deafen" text={call.deafened ? "Undeafen" : "Deafen"} pressed={call.deafened} onClick={() => calls.toggleDeafen()} />
        {call.video ? (
          <>
            <Ctl icon={call.cameraOff ? "video-off" : "video"} label="Turn camera off" text="Camera" pressed={call.cameraOff} onClick={() => calls.toggleCamera()} />
            {canShare ? null : <Ctl icon="flip" label="Switch camera" text="Flip" onClick={() => void calls.flip()} />}
          </>
        ) : canShare ? null : (
          <Ctl icon="speaker" label="Speaker" text="Speaker" pressed={call.speaker} onClick={() => calls.toggleSpeaker()} />
        )}
        {canShare && live ? (
          <Ctl icon="screen-share" label="Share screen" text={call.sharing ? "Sharing" : "Share"} pressed={call.sharing !== null} expanded={sheet} onClick={() => setSheet((s) => !s)} />
        ) : null}
        <Ctl icon="phone-off" tone="end" label="End call" text="End" onClick={() => calls.hangup()} />
      </>
    );
  }

  const identity = (
    <div className="stack center call-id">
      <span className="levels">
        {call.phase === "ended" || call.phase === "active" ? null : (<><i></i><i></i><i></i></>)}
        {contact ? <Avatar initials={contact.initials} hue={contact.hue} size="xxl" /> : null}
      </span>
      <span className="call-name">{name}</span>
      <span className="call-time" role="timer" aria-live="off">{status}</span>
      {chip}
      {pills}
    </div>
  );

  return (
    <div className="call-overlay" role="dialog" aria-modal="true" aria-label={`${call.video ? "Video" : "Voice"} call with ${name}`}>
      <section className={`call ${visual ? "video" : "audio"}${theirScreen ? " watching" : ""}`}>
        <span className="call-bg">
          {theirScreen ? <StreamVideo stream={call.remoteScreen} className="call-video screen" label={`${name}'s screen`} />
            : theirCamera ? <StreamVideo stream={call.remote} className="call-video" label={`${name}'s video`} /> : null}
        </span>
        <StreamAudio stream={call.remote} muted={call.deafened} />
        {theirScreen ? <StreamAudio stream={call.remoteScreen} muted={call.deafened} volume={call.streamVolume} /> : null}
        {visual ? (
          <div className="call-top">
            <span className="call-name">{name}</span>
            <span className="call-time" role="timer" aria-live="off">{status}</span>
            {chip}
            <span className="e2e"><Icon name="lock" />End-to-end encrypted</span>
            {pills}
          </div>
        ) : (
          <div className="call-top"><span className="e2e"><Icon name="lock" />End-to-end encrypted</span></div>
        )}
        {theirScreen && theirCamera ? (
          <div className="self-view peer-view">
            <StreamVideo stream={call.remote} className="self-video" label={`${name}'s video`} />
            <span>{name}</span>
          </div>
        ) : null}
        {myCamera ? (
          <div className="self-view">
            <StreamVideo stream={call.local} className="self-video mine" label="Your camera preview" />
            <span>You</span>
          </div>
        ) : null}
        <div className="call-stage">{visual ? null : identity}</div>
        {theirScreen ? (
          <div className="stream-volume">
            <button className="icon-btn" type="button" aria-label={call.streamVolume > 0 ? "Mute stream sound" : "Unmute stream sound"} onClick={() => calls.setStreamVolume(call.streamVolume > 0 ? 0 : 1)}>
              <Icon name={call.streamVolume > 0 ? "speaker" : "volume-off"} />
            </button>
            <input type="range" min={0} max={100} step={1} value={Math.round(call.streamVolume * 100)} aria-label="Stream volume" aria-valuetext={`${Math.round(call.streamVolume * 100)}%`} onChange={(e) => calls.setStreamVolume(Number(e.target.value) / 100)} />
          </div>
        ) : null}
        <div className="call-controls" ref={first}>{controls}</div>
        {sheet && live ? <ShareSheet call={call} onClose={closeSheet} /> : null}
      </section>
      {/* Phase changes are announced once; the running clock is not. */}
      <span className="sr-only" role="status">{live ? `Call connected${call.peer.sharing ? `. ${name} is sharing their screen` : ""}${call.peer.deafened ? `. ${name} is deafened` : call.peer.muted ? `. ${name} is muted` : ""}` : status}</span>
    </div>
  );
}
