// Voice and video calls (milestone 6, ADR-0018). Media runs in this webview's WebRTC, always
// relay-only through the TURN server the relay names: `iceTransportPolicy: "relay"` stops the
// browser from even gathering host or server-reflexive candidates, so the other side never
// learns our IP (INV-NET-1). Signaling goes through Rust, which rebuilds every SDP from an
// allowlist and carries it over the encrypted session; the DTLS fingerprint in that SDP keys
// the media, so the relay and the TURN server only ever see ciphertext (INV-NET-4).
//
// Candidates are gathered completely before the offer or answer is sent (no trickle): with
// relay-only there are only one or two of them, and it keeps signaling to one message each way.
//
// Every call has the same media sections, in this order (`Slot`): microphone, camera, screen,
// screen audio, then a data channel. All of them can send from the start, so turning the camera
// on in a voice call, or sharing the screen, only swaps a track into a section that is already
// there: no second offer. A voice call's camera section carries no stream (`a=msid:-`), which is
// how the other side (and Rust) tells voice from video. The data channel
// carries mute, deafen, camera and sharing state; it runs inside the call's DTLS, end to end.
import { useSyncExternalStore } from "react";
import { ipc, IpcError, type CallSetup, type CallSignal } from "./ipc";

export type Phase = "incoming" | "calling" | "connecting" | "active" | "ended";

/** Screen-sharing quality (the owner's two choices). */
export type Quality = "1080p60" | "720p30";

export const QUALITIES: Record<Quality, { title: string; detail: string; width: number; height: number; fps: number; bitrate: number; hint: string }> = {
  "1080p60": { title: "Smooth", detail: "1080p, 60 fps · for games and video", width: 1920, height: 1080, fps: 60, bitrate: 6_000_000, hint: "motion" },
  "720p30": { title: "Light", detail: "720p, 30 fps · uses less data", width: 1280, height: 720, fps: 30, bitrate: 2_500_000, hint: "detail" },
};

/** What the other side told us over the data channel. */
export interface PeerState {
  muted: boolean;
  deafened: boolean;
  cameraOff: boolean;
  sharing: boolean;
}

const QUIET: PeerState = { muted: false, deafened: false, cameraOff: false, sharing: false };

/** The media sections, in SDP order. */
const enum Slot {
  Mic = 0,
  Camera = 1,
  Screen = 2,
  ScreenAudio = 3,
}

/** Whether this webview can share its screen (Android's WebView cannot). */
export const canShare = typeof navigator !== "undefined" && typeof navigator.mediaDevices?.getDisplayMedia === "function";

export interface CallState {
  id: string;
  contact: number;
  video: boolean;
  outgoing: boolean;
  phase: Phase;
  /** When media started flowing (ms since epoch). */
  startedAt: number | null;
  /** Why it ended, shown for a moment. */
  ended: string | null;
  muted: boolean;
  /** Deafened: our microphone is off and we hear nothing from them. */
  deafened: boolean;
  cameraOff: boolean;
  speaker: boolean;
  /** The quality we are sharing our screen at, or null. */
  sharing: Quality | null;
  local: MediaStream | null;
  /** Their microphone and camera. */
  remote: MediaStream | null;
  /** Their screen and its sound. */
  remoteScreen: MediaStream | null;
  peer: PeerState;
  /** Volume of their screen's sound, 0 to 1 (only here, never sent). */
  streamVolume: number;
  /** Their camera's picture is arriving (its track is not muted). */
  remoteCamera: boolean;
  /** Shown as a small bubble over the app instead of full screen. */
  minimized: boolean;
}

/** How long a call rings before it counts as unanswered. */
const RING_MS = 45_000;
/** Longest wait for ICE gathering (relay candidates come from one TURN round trip). */
const GATHER_MS = 6_000;
/** How long "Call ended" stays on screen. */
const ENDED_MS = 1_800;

function newId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function reason(err: unknown, fallback: string): string {
  if (err instanceof IpcError) return err.message;
  if (err instanceof DOMException && (err.name === "NotAllowedError" || err.name === "SecurityError")) {
    return "Veil may not use the microphone or camera. Allow it in your device's settings.";
  }
  if (err instanceof DOMException && err.name === "NotFoundError") return "No microphone or camera found.";
  return err instanceof Error && err.message ? err.message : fallback;
}

function fresh(id: string, contact: number, video: boolean, outgoing: boolean): CallState {
  return {
    id, contact, video, outgoing, phase: outgoing ? "calling" : "incoming", startedAt: null, ended: null,
    muted: false, deafened: false, cameraOff: !video, speaker: video, sharing: null,
    local: null, remote: null, remoteScreen: null, peer: QUIET, streamVolume: 1,
    remoteCamera: false, minimized: false,
  };
}

/** Strict parse of the other side's state message; anything else is ignored. */
function peerState(data: unknown): PeerState | null {
  if (typeof data !== "string" || data.length > 256) return null;
  try {
    const v: unknown = JSON.parse(data);
    if (typeof v !== "object" || v === null) return null;
    const o = v as Record<string, unknown>;
    const { muted, deafened, cameraOff, sharing } = o;
    if (typeof muted !== "boolean" || typeof deafened !== "boolean" || typeof cameraOff !== "boolean" || typeof sharing !== "boolean") return null;
    return { muted, deafened, cameraOff, sharing };
  } catch {
    return null;
  }
}

function media(video: boolean, facing: "user" | "environment" = "user"): Promise<MediaStream> {
  return navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    video: video ? { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } } : false,
  });
}

/** Resolves once ICE gathering is complete, or after GATHER_MS. */
function gathered(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const t = window.setTimeout(done, GATHER_MS);
    function done() {
      window.clearTimeout(t);
      pc.removeEventListener("icegatheringstatechange", check);
      resolve();
    }
    function check() {
      if (pc.iceGatheringState === "complete") done();
    }
    pc.addEventListener("icegatheringstatechange", check);
  });
}

/** The SDP to send: it must carry a relay candidate, or the TURN server was not reachable. */
function finalSdp(pc: RTCPeerConnection): string {
  const sdp = pc.localDescription?.sdp ?? "";
  if (!/ typ relay/.test(sdp)) throw new Error("Veil could not reach the call server (TURN). Check that it is running and reachable.");
  return sdp;
}

/** A simple ring for incoming calls: a two-tone pattern and vibration, until stopped. */
function ring(): () => void {
  let stopped = false;
  let ctx: AudioContext | null = null;
  try {
    ctx = new AudioContext();
  } catch {
    ctx = null;
  }
  const once = () => {
    if (stopped) return;
    navigator.vibrate?.([400, 300, 400]);
    if (ctx) {
      const t0 = ctx.currentTime;
      for (const [f, at] of [[440, 0], [480, 0], [440, 0.45], [480, 0.45]] as const) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.frequency.value = f;
        gain.gain.value = 0.06;
        osc.connect(gain).connect(ctx.destination);
        osc.start(t0 + at);
        osc.stop(t0 + at + 0.35);
      }
    }
  };
  once();
  const timer = window.setInterval(once, 2_500);
  return () => {
    stopped = true;
    window.clearInterval(timer);
    navigator.vibrate?.(0);
    void ctx?.close().catch(() => undefined);
  };
}

class CallManager {
  private current: CallState | null = null;
  private pc: RTCPeerConnection | null = null;
  private channel: RTCDataChannel | null = null;
  private screen: MediaStream | null = null;
  private offer: string | null = null;
  private ringTimer = 0;
  private keepAlive = 0;
  private clearTimer = 0;
  private stopRing: (() => void) | null = null;
  private listeners = new Set<() => void>();

  readonly subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  readonly snapshot = (): CallState | null => this.current;

  private emit() {
    for (const fn of this.listeners) fn();
  }

  /** Changes the live call; an ended call only changes through `end` (review C6-1). */
  private patch(p: Partial<CallState>, ending = false) {
    if (!this.current || (this.current.phase === "ended" && !ending)) return;
    this.current = { ...this.current, ...p };
    this.emit();
  }

  private busy(): boolean {
    return this.current !== null && this.current.phase !== "ended";
  }

  /** Whether call `id` is still the one in progress (not hung up, declined or replaced). */
  private live(id: string): boolean {
    return this.current?.id === id && this.current.phase !== "ended";
  }

  /** Lets go of what a setup that lost its call had taken: camera, microphone, connection. */
  private release(local: MediaStream | null, pc: RTCPeerConnection | null) {
    for (const t of local?.getTracks() ?? []) t.stop();
    if (pc) {
      pc.close();
      if (this.pc === pc) {
        this.pc = null;
        this.channel = null;
      }
    }
  }

  /** Starts a call to `contact`. */
  async start(contact: number, video: boolean): Promise<void> {
    if (this.busy()) return;
    window.clearTimeout(this.clearTimer);
    const id = newId();
    this.current = fresh(id, contact, video, true);
    this.emit();
    let local: MediaStream | null = null;
    let pc: RTCPeerConnection | null = null;
    try {
      const setup = await ipc.callSetup(contact);
      if (!this.live(id)) return;
      local = await media(video);
      if (!this.live(id)) return this.release(local, null);
      this.patch({ local });
      pc = this.peer(setup);
      // The sections every call has, in `Slot` order; the camera is inactive in a voice call.
      pc.addTransceiver(local.getAudioTracks()[0] ?? "audio", { direction: "sendrecv", streams: [local] });
      pc.addTransceiver(local.getVideoTracks()[0] ?? "video", { direction: "sendrecv", streams: video ? [local] : [] });
      pc.addTransceiver("video", { direction: "sendrecv" });
      pc.addTransceiver("audio", { direction: "sendrecv" });
      await pc.setLocalDescription(await pc.createOffer());
      await gathered(pc);
      if (!this.live(id)) return this.release(local, pc);
      await ipc.callSend(contact, id, "offer", finalSdp(pc));
      if (!this.live(id)) return;
      this.ringTimer = window.setTimeout(() => this.end("No answer", true), RING_MS);
    } catch (err) {
      if (this.live(id)) this.end(reason(err, "The call could not start"), false);
      else this.release(local, pc);
    }
  }

  /** Signals that arrived from Rust. */
  async handle(signals: CallSignal[]): Promise<void> {
    for (const s of signals) {
      if (s.kind === "offer") {
        const c = this.current;
        if (c && this.busy()) {
          // Both calling each other at once: the smaller call id goes ahead, on both sides,
          // so neither gets "Busy" (review C6-7). The other side ignores ours the same way.
          const glare = c.outgoing && c.phase === "calling" && s.contact === c.contact && s.callId !== c.id;
          if (!glare) {
            if (s.callId !== c.id) {
              void ipc.callSend(s.contact, s.callId, "busy").catch(() => undefined);
              // The shell may have shown "Incoming call" for it (review C6R2-4).
              void ipc.cancelCallNotice().catch(() => undefined);
            }
            continue;
          }
          if (s.callId > c.id) {
            void ipc.cancelCallNotice().catch(() => undefined);
            continue;
          }
          this.abandon();
        }
        window.clearTimeout(this.clearTimer);
        this.offer = s.sdp;
        this.current = fresh(s.callId, s.contact, s.video, false);
        this.stopRing = ring();
        this.ringTimer = window.setTimeout(() => this.end("Missed call", false), RING_MS);
        this.emit();
        continue;
      }
      const c = this.current;
      if (!c || c.phase === "ended" || s.callId !== c.id || s.contact !== c.contact) continue;
      if (s.kind === "answer" && c.outgoing && c.phase === "calling" && s.sdp && this.pc) {
        window.clearTimeout(this.ringTimer);
        this.patch({ phase: "connecting" });
        try {
          await this.pc.setRemoteDescription({ type: "answer", sdp: s.sdp });
        } catch (err) {
          this.end(reason(err, "The call could not connect"), true);
        }
      } else if (s.kind === "hangup") {
        this.end(c.phase === "incoming" ? "Missed call" : "Call ended", false);
      } else if (s.kind === "busy") {
        this.end("Busy", false);
      }
    }
  }

  /** Answers the ringing call. */
  async accept(): Promise<void> {
    const c = this.current;
    if (!c || c.phase !== "incoming" || !this.offer) return;
    this.stopRinging();
    window.clearTimeout(this.ringTimer);
    this.patch({ phase: "connecting" });
    const offer = this.offer;
    let local: MediaStream | null = null;
    let pc: RTCPeerConnection | null = null;
    try {
      const setup = await ipc.callSetup(c.contact);
      if (!this.live(c.id)) return;
      local = await media(c.video);
      if (!this.live(c.id)) return this.release(local, null);
      this.patch({ local });
      pc = this.peer(setup);
      await pc.setRemoteDescription({ type: "offer", sdp: offer });
      // The offer made the sections; fill ours in, in `Slot` order.
      const tx = pc.getTransceivers();
      if (tx.length < 4) throw new Error("The call could not connect");
      const mic = local.getAudioTracks()[0] ?? null;
      const cam = local.getVideoTracks()[0] ?? null;
      tx[Slot.Mic]!.direction = "sendrecv";
      await tx[Slot.Mic]!.sender.replaceTrack(mic);
      tx[Slot.Camera]!.direction = "sendrecv";
      await tx[Slot.Camera]!.sender.replaceTrack(c.video ? cam : null);
      tx[Slot.Screen]!.direction = "sendrecv";
      tx[Slot.ScreenAudio]!.direction = "sendrecv";
      tx[Slot.Mic]!.sender.setStreams?.(local);
      if (c.video) tx[Slot.Camera]!.sender.setStreams?.(local);
      await pc.setLocalDescription(await pc.createAnswer());
      await gathered(pc);
      if (!this.live(c.id)) return this.release(local, pc);
      await ipc.callSend(c.contact, c.id, "answer", finalSdp(pc));
    } catch (err) {
      if (this.live(c.id)) this.end(reason(err, "The call could not connect"), true);
      else this.release(local, pc);
    }
  }

  /** Drops our own outgoing call to take theirs instead (glare). The hangup for our id is
   *  ignored by them now, but ends a late copy of our offer at once (review C6R2-2). */
  private abandon() {
    const c = this.current;
    window.clearTimeout(this.ringTimer);
    if (c) void ipc.callSend(c.contact, c.id, "hangup").catch(() => undefined);
    this.release(c?.local ?? null, this.pc);
    this.current = null;
    this.emit();
  }

  decline(): void {
    if (this.current?.phase === "incoming") this.end("Declined", true);
  }

  hangup(): void {
    if (this.busy()) this.end("Call ended", true);
  }

  /** Veil locked: the session that carries signaling is gone. */
  drop(): void {
    if (this.busy()) this.end("Call ended", false);
  }

  /** Mute or unmute the microphone. Unmuting while deafened undeafens too. */
  toggleMute(): void {
    const c = this.current;
    if (!c) return;
    if (c.deafened) this.setVoice(false, false);
    else this.setVoice(!c.muted, false);
  }

  /** Deafen: the microphone goes off and we hear nothing; undeafen brings back the mute from before. */
  toggleDeafen(): void {
    const c = this.current;
    if (!c) return;
    this.setVoice(c.muted, !c.deafened);
  }

  private setVoice(muted: boolean, deafened: boolean) {
    const c = this.current;
    if (!c) return;
    for (const t of c.local?.getAudioTracks() ?? []) t.enabled = !(muted || deafened);
    this.patch({ muted, deafened });
    this.tell();
  }

  /** Camera on or off. In a voice call the first "on" opens the camera; the other side shows
   *  the picture once it arrives, with no new offer. */
  async toggleCamera(): Promise<void> {
    const c = this.current;
    if (!c?.local || c.phase === "incoming" || c.phase === "ended") return;
    const cameraOff = !c.cameraOff;
    if (c.local.getVideoTracks().length > 0 || cameraOff) {
      for (const t of c.local.getVideoTracks()) t.enabled = !cameraOff;
      this.patch({ cameraOff });
      this.tell();
      return;
    }
    // Only where the camera section was agreed to send: a call from preview.8 has it inactive,
    // and the camera would light up for nothing (review CB-2). Checked before opening it.
    const sendable = (t: RTCRtpTransceiver | undefined): t is RTCRtpTransceiver =>
      t !== undefined && (t.currentDirection === "sendrecv" || t.currentDirection === "sendonly");
    if (!sendable(this.pc?.getTransceivers()[Slot.Camera])) return;
    let next: MediaStreamTrack | undefined;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      next = stream.getVideoTracks()[0];
      const pc = this.pc;
      const camera = pc?.getTransceivers()[Slot.Camera];
      if (!next || !this.live(c.id) || !sendable(camera) || (this.current?.local?.getVideoTracks().length ?? 0) > 0) {
        next?.stop();
        return;
      }
      await camera.sender.replaceTrack(next);
      if (!this.live(c.id)) {
        next.stop();
        return;
      }
      const local = new MediaStream([...(this.current?.local?.getAudioTracks() ?? []), next]);
      // A phone held at arm's length for video: the loudspeaker, as in a video call.
      const speaker = canShare ? this.current?.speaker ?? false : true;
      this.patch({ local, cameraOff: false, speaker });
      if (!canShare) void ipc.callAudio(true, speaker).catch(() => undefined);
      this.tell();
    } catch {
      // No camera, or not allowed: the call goes on without it.
      next?.stop();
    }
  }

  /** Shrinks the call to a bubble over the app, or brings it back. */
  setMinimized(minimized: boolean): void {
    const c = this.current;
    if (!c || c.phase === "incoming" || c.minimized === minimized) return;
    // After the end, a tap on the bubble still shows the full "Call ended" (review CB-8).
    this.patch({ minimized }, c.phase === "ended");
  }

  /** Volume of their shared screen's sound, 0 to 1. */
  setStreamVolume(v: number): void {
    if (Number.isFinite(v)) this.patch({ streamVolume: Math.min(1, Math.max(0, v)) });
  }

  /** Shares the screen (or a window) at `q`, or changes the quality of a running share. */
  async share(q: Quality): Promise<void> {
    const c = this.current;
    const tx = this.pc?.getTransceivers();
    if (!c || c.phase !== "active" || !tx || tx.length < 4 || !canShare) return;
    const spec = QUALITIES[q];
    const constraints = { width: { ideal: spec.width, max: spec.width }, height: { ideal: spec.height, max: spec.height }, frameRate: { ideal: spec.fps, max: spec.fps } };
    const running = this.screen?.getVideoTracks()[0];
    try {
      if (running) {
        await running.applyConstraints(constraints);
        running.contentHint = spec.hint;
      } else {
        const screen = await navigator.mediaDevices.getDisplayMedia({ video: constraints, audio: true });
        if (this.current?.id !== c.id || this.current.phase !== "active") {
          for (const t of screen.getTracks()) t.stop();
          return;
        }
        const video = screen.getVideoTracks()[0];
        if (!video) {
          for (const t of screen.getTracks()) t.stop();
          return;
        }
        video.contentHint = spec.hint;
        // The system's own "Stop sharing" ends it as well.
        video.addEventListener("ended", () => this.stopShare());
        this.screen = screen;
        await tx[Slot.Screen]!.sender.replaceTrack(video);
        await tx[Slot.ScreenAudio]!.sender.replaceTrack(screen.getAudioTracks()[0] ?? null);
      }
      await this.limit(tx[Slot.Screen]!.sender, spec.bitrate, spec.fps);
      this.patch({ sharing: q });
      this.tell();
    } catch {
      // The user closed the picker, or sharing is not allowed: nothing changes.
      if (!running) this.stopShare();
    }
  }

  stopShare(): void {
    const tx = this.pc?.getTransceivers();
    for (const t of this.screen?.getTracks() ?? []) t.stop();
    this.screen = null;
    if (tx && tx.length >= 4) {
      void tx[Slot.Screen]!.sender.replaceTrack(null).catch(() => undefined);
      void tx[Slot.ScreenAudio]!.sender.replaceTrack(null).catch(() => undefined);
    }
    if (this.current?.sharing) {
      this.patch({ sharing: null });
      this.tell();
    }
  }

  private async limit(sender: RTCRtpSender, bitrate: number, fps: number) {
    try {
      const p = sender.getParameters();
      if (p.encodings.length === 0) p.encodings = [{}];
      for (const e of p.encodings) {
        e.maxBitrate = bitrate;
        e.maxFramerate = fps;
      }
      await sender.setParameters(p);
    } catch {
      // Not every engine takes these; the capture constraints still apply.
    }
  }

  /** Our state, to the other side over the data channel. */
  private tell() {
    const c = this.current;
    const ch = this.channel;
    if (!c || ch?.readyState !== "open") return;
    try {
      const cameraOff = c.cameraOff || !c.local?.getVideoTracks().length;
      ch.send(JSON.stringify({ muted: c.muted, deafened: c.deafened, cameraOff, sharing: c.sharing !== null }));
    } catch {
      // Closing: nothing to tell.
    }
  }

  /** Front or back camera, swapped without renegotiating. Only a camera is opened (no second
   *  microphone), and it is let go if the call ends meanwhile (review C6R2-1). */
  async flip(): Promise<void> {
    const c = this.current;
    const old = c?.local?.getVideoTracks()[0];
    if (!c || !old || !this.pc) return;
    const facing = old.getSettings().facingMode === "environment" ? "user" : "environment";
    let next: MediaStreamTrack | undefined;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      next = stream.getVideoTracks()[0];
      const pc = this.pc;
      if (!next || !this.live(c.id) || !pc) {
        next?.stop();
        return;
      }
      next.enabled = !(this.current?.cameraOff ?? true);
      await pc.getTransceivers()[Slot.Camera]?.sender.replaceTrack(next);
      if (!this.live(c.id)) {
        next.stop();
        return;
      }
      old.stop();
      this.patch({ local: new MediaStream([...(this.current?.local?.getAudioTracks() ?? []), next]) });
    } catch {
      // Only one camera, or it is busy: keep the current one.
      if (next && next !== this.current?.local?.getVideoTracks()[0]) next.stop();
    }
  }

  toggleSpeaker(): void {
    const c = this.current;
    if (!c) return;
    const speaker = !c.speaker;
    this.patch({ speaker });
    void ipc.callAudio(true, speaker).catch(() => undefined);
  }

  private stopRinging() {
    this.stopRing?.();
    this.stopRing = null;
  }

  private peer(setup: CallSetup): RTCPeerConnection {
    const pc = new RTCPeerConnection({
      iceServers: setup.iceServers,
      // Never host or server-reflexive candidates: the peer must not learn our IP (INV-NET-1).
      iceTransportPolicy: "relay",
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
    });
    this.pc = pc;
    // Negotiated on both sides with the same id, so it is part of the first offer.
    const ch = pc.createDataChannel("state", { negotiated: true, id: 0, ordered: true });
    this.channel = ch;
    ch.onopen = () => this.tell();
    ch.onmessage = (e: MessageEvent) => {
      const peer = peerState(e.data);
      if (peer && this.pc === pc) this.patch({ peer });
    };
    const remote = new MediaStream();
    const remoteScreen = new MediaStream();
    pc.ontrack = (e) => {
      const slot = pc.getTransceivers().indexOf(e.transceiver);
      if (slot === Slot.Screen || slot === Slot.ScreenAudio) {
        remoteScreen.addTrack(e.track);
        this.patch({ remoteScreen });
      } else if (slot === Slot.Mic || slot === Slot.Camera) {
        remote.addTrack(e.track);
        this.patch({ remote });
        if (slot === Slot.Camera) {
          // Their picture is shown only while it arrives, never a black frame.
          const camera = e.track;
          const update = () => {
            if (this.pc === pc) this.patch({ remoteCamera: !camera.muted && camera.readyState === "live" });
          };
          camera.addEventListener("mute", update);
          camera.addEventListener("unmute", update);
          camera.addEventListener("ended", update);
          update();
        }
      }
    };
    pc.onconnectionstatechange = () => {
      if (this.pc !== pc) return;
      if (pc.connectionState === "connected" && this.current?.phase === "connecting") {
        this.patch({ phase: "active", startedAt: Date.now() });
        void ipc.callAudio(true, this.current.speaker).catch(() => undefined);
        // A call is the user being here: keep Veil from auto-locking under it.
        this.keepAlive = window.setInterval(() => void ipc.touch().catch(() => undefined), 60_000);
      } else if (pc.connectionState === "failed") {
        this.end("The connection failed", true);
      }
    };
    return pc;
  }

  private end(why: string, tellThem: boolean) {
    const c = this.current;
    if (!c || c.phase === "ended") return;
    this.stopRinging();
    window.clearTimeout(this.ringTimer);
    window.clearInterval(this.keepAlive);
    if (tellThem) void ipc.callSend(c.contact, c.id, "hangup").catch(() => undefined);
    this.channel = null;
    this.pc?.close();
    this.pc = null;
    this.offer = null;
    for (const t of [...(c.local?.getTracks() ?? []), ...(this.screen?.getTracks() ?? [])]) t.stop();
    this.screen = null;
    void ipc.callAudio(false, false).catch(() => undefined);
    this.patch({ phase: "ended", ended: why, local: null, remote: null, remoteScreen: null, sharing: null, peer: QUIET }, true);
    this.clearTimer = window.setTimeout(() => {
      if (this.current?.id === c.id) {
        this.current = null;
        this.emit();
      }
    }, ENDED_MS);
  }
}

export const calls = new CallManager();

export function useCall(): CallState | null {
  return useSyncExternalStore(calls.subscribe, calls.snapshot);
}
