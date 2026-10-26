// Media helpers for attachments (milestone 3). Everything runs in the webview on this device:
// photos are re-encoded through a canvas, which drops EXIF data such as the GPS location and
// the camera model, and voice notes are recorded with MediaRecorder. Nothing is written to
// disk here and nothing goes to the network; the bytes go to Rust through `ipc.ts`.

/** Largest file Veil sends (the core allows 100 MiB; phones and relays like smaller). */
export const MAX_SEND_BYTES = 25 * 1024 * 1024;
/** Longest side of a sent photo. */
const PHOTO_PX = 2048;
/** Longest side of the inline preview, which travels inside the message (≤ 8 KiB). */
const THUMB_PX = 96;
const THUMB_MAX_BYTES = 8 * 1024;
/** Longest voice note. */
export const MAX_VOICE_MS = 5 * 60 * 1000;
/** Bars in a voice note's waveform. */
const WAVE_BARS = 48;

/** Image types shown inline; anything else is sent and shown as a file. SVG is never shown. */
export const INLINE_IMAGE = ["image/jpeg", "image/png", "image/webp", "image/gif"];
export const VOICE_TYPES = ["audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/aac"];

export interface Prepared {
  kind: "image" | "file" | "voice";
  mime: string;
  name: string | null;
  data: Uint8Array;
  thumbnail: Uint8Array | null;
  durationMs: number | null;
  waveform: Uint8Array | null;
}

function canvasBlob(c: HTMLCanvasElement, type: string, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => c.toBlob(resolve, type, quality));
}

async function loadImage(file: Blob): Promise<ImageBitmap> {
  return createImageBitmap(file);
}

function scaled(img: ImageBitmap, max: number): HTMLCanvasElement {
  const k = Math.min(1, max / Math.max(img.width, img.height));
  const c = document.createElement("canvas");
  c.width = Math.max(1, Math.round(img.width * k));
  c.height = Math.max(1, Math.round(img.height * k));
  c.getContext("2d")?.drawImage(img, 0, 0, c.width, c.height);
  return c;
}

/** A small JPEG preview, shrunk until it fits the core's 8 KiB limit. */
async function thumbnail(img: ImageBitmap): Promise<Uint8Array | null> {
  for (const [px, q] of [[THUMB_PX, 0.6], [64, 0.5], [48, 0.4]] as const) {
    const b = await canvasBlob(scaled(img, px), "image/jpeg", q);
    if (b && b.size <= THUMB_MAX_BYTES) return new Uint8Array(await b.arrayBuffer());
  }
  return null;
}

/** Prepares a picked file: photos are re-encoded without metadata, other files go as they are. */
export async function prepareFile(file: File): Promise<Prepared> {
  if (INLINE_IMAGE.includes(file.type) && file.type !== "image/gif") {
    const img = await loadImage(file);
    try {
      // WebP keeps transparency; the re-encode drops every metadata block of the original.
      const out = await canvasBlob(scaled(img, PHOTO_PX), "image/webp", 0.85);
      if (!out) throw new Error("encode");
      const data = new Uint8Array(await out.arrayBuffer());
      if (data.byteLength > MAX_SEND_BYTES) throw new TooLarge();
      return { kind: "image", mime: "image/webp", name: null, data, thumbnail: await thumbnail(img), durationMs: null, waveform: null };
    } finally {
      img.close();
    }
  }
  if (file.size > MAX_SEND_BYTES) throw new TooLarge();
  const data = new Uint8Array(await file.arrayBuffer());
  return { kind: "file", mime: file.type || "application/octet-stream", name: file.name || "file", data, thumbnail: null, durationMs: null, waveform: null };
}

export class TooLarge extends Error {}

/** Records a voice note. `stop()` resolves with the recording; `cancel()` discards it. */
export interface Recording {
  stop: () => Promise<Prepared>;
  cancel: () => void;
  /** Milliseconds recorded so far. */
  elapsed: () => number;
  /** Current input level, 0 to 1, for a live meter. */
  level: () => number;
}

function pickVoiceType(): string {
  for (const t of ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4", "audio/webm"]) {
    if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported(t)) return t;
  }
  return "";
}

export async function startRecording(): Promise<Recording> {
  if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") throw new Error("unsupported");
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  const type = pickVoiceType();
  const rec = new MediaRecorder(stream, type ? { mimeType: type, audioBitsPerSecond: 32_000 } : undefined);
  const parts: Blob[] = [];
  const levels: number[] = [];
  const audio = new AudioContext();
  const analyser = audio.createAnalyser();
  analyser.fftSize = 512;
  audio.createMediaStreamSource(stream).connect(analyser);
  const buf = new Uint8Array(analyser.fftSize);
  let current = 0;
  const sample = window.setInterval(() => {
    analyser.getByteTimeDomainData(buf);
    let peak = 0;
    for (const v of buf) peak = Math.max(peak, Math.abs(v - 128));
    current = peak / 128;
    levels.push(current);
  }, 100);
  const started = performance.now();
  rec.ondataavailable = (e) => {
    if (e.data.size) parts.push(e.data);
  };
  rec.start(1000);
  let finished = false;
  const release = () => {
    finished = true;
    window.clearInterval(sample);
    for (const t of stream.getTracks()) t.stop();
    void audio.close().catch(() => undefined);
  };
  const autoStop = window.setTimeout(() => {
    if (rec.state === "recording") rec.stop();
  }, MAX_VOICE_MS);

  return {
    elapsed: () => (finished ? 0 : performance.now() - started),
    level: () => current,
    cancel: () => {
      window.clearTimeout(autoStop);
      if (rec.state !== "inactive") rec.stop();
      release();
      parts.length = 0;
    },
    stop: () =>
      new Promise<Prepared>((resolve, reject) => {
        window.clearTimeout(autoStop);
        const durationMs = Math.min(MAX_VOICE_MS, Math.round(performance.now() - started));
        const done = async () => {
          release();
          const blob = new Blob(parts, { type: rec.mimeType || type || "audio/webm" });
          parts.length = 0;
          if (blob.size === 0) return reject(new Error("empty"));
          const data = new Uint8Array(await blob.arrayBuffer());
          if (data.byteLength > MAX_SEND_BYTES) return reject(new TooLarge());
          resolve({
            kind: "voice",
            mime: (rec.mimeType || type || "audio/webm").split(";")[0] ?? "audio/webm",
            name: null,
            data,
            thumbnail: null,
            durationMs,
            waveform: waveform(levels),
          });
        };
        if (rec.state === "inactive") void done();
        else {
          rec.onstop = () => void done();
          rec.stop();
        }
      }),
  };
}

/** Peak levels folded into WAVE_BARS bars of 0..255. */
function waveform(levels: number[]): Uint8Array {
  const out = new Uint8Array(WAVE_BARS);
  if (!levels.length) return out;
  for (let i = 0; i < WAVE_BARS; i++) {
    const from = Math.floor((i * levels.length) / WAVE_BARS);
    const to = Math.max(from + 1, Math.floor(((i + 1) * levels.length) / WAVE_BARS));
    let peak = 0;
    for (let j = from; j < to && j < levels.length; j++) peak = Math.max(peak, levels[j] ?? 0);
    out[i] = Math.min(255, Math.round(peak * 255));
  }
  return out;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
