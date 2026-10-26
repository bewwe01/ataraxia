// Photos, files and voice notes in a conversation (DESIGN.md §6 `<ImageAttachment>`,
// `<FileAttachment>`, `<VoiceNote>`, `<Progress>`).
//
// The file comes from Rust only when it is shown, played or saved, as a blob: URL that is
// revoked as soon as it is not needed. Chromium (the Android WebView) moves blob data to files
// in the app's data folder once blobs in memory pass about 1 % of the phone's RAM, which would
// put plaintext outside SQLCipher (review M3-2, INV-ATT-4). So the webview never holds many or
// large ones: a photo in the list is fetched only while on screen and only up to
// `INLINE_MAX`; a larger one shows its thumbnail and opens in the viewer (at most `VIEW_MAX`,
// one at a time); a voice note's blob exists from Play until it ends.
import { useEffect, useRef, useState, type RefObject } from "react";
import { ipc, IpcError, type AttachmentView, type MessageView } from "../ipc";
import { formatBytes, formatDuration } from "../media";
import { Icon, useDialogKeys } from "../ui";

/** Largest photo fetched for the conversation list. */
const INLINE_MAX = 2 * 1024 * 1024;
/** Largest photo shown at all; bigger "photos" are offered as files to save. */
const VIEW_MAX = 8 * 1024 * 1024;

let android: boolean | null = null;
async function isAndroid(): Promise<boolean> {
  if (android === null) android = await ipc.nativeInfo().then((n) => n.android, () => false);
  return android;
}

function hasFile(a: AttachmentView, mine: boolean): boolean {
  return a.state === "ready" || (mine && (a.state === "uploading" || a.state === "sent"));
}

function errorText(err: unknown, fallback: string): string {
  return err instanceof IpcError ? err.message : fallback;
}

/**
 * A blob: URL for the file while `want` is true; revoked afterwards. Depends on primitives
 * only, so a refreshed message list does not fetch the file again (review M3-3).
 */
function useFileUrl(m: MessageView, want: boolean): string | null {
  const [url, setUrl] = useState<string | null>(null);
  const a = m.attachment;
  const ok = want && a !== null && hasFile(a, m.mine);
  const mime = a?.mime ?? "";
  useEffect(() => {
    if (!ok) return;
    let live = true;
    let made: string | null = null;
    ipc.attachmentData(m.id).then(
      (buf) => {
        if (!live) return;
        made = URL.createObjectURL(new Blob([buf], { type: mime }));
        setUrl(made);
      },
      () => undefined,
    );
    return () => {
      live = false;
      if (made) URL.revokeObjectURL(made);
      setUrl(null);
    };
  }, [m.id, ok, mime]);
  return url;
}

/** The thumbnail travels in the message; same bytes, same URL across list refreshes. */
function useThumbUrl(a: AttachmentView | null): string | null {
  const [url, setUrl] = useState<string | null>(null);
  const key = a?.thumbnail?.join(",") ?? "";
  useEffect(() => {
    if (!key) return;
    const bytes = new Uint8Array(key.split(",").map(Number));
    const u = URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }));
    setUrl(u);
    return () => {
      URL.revokeObjectURL(u);
      setUrl(null);
    };
  }, [key]);
  return url;
}

/** True while the element is on (or near) the screen. */
function useOnScreen(el: RefObject<HTMLElement | null>): boolean {
  const [on, setOn] = useState(false);
  useEffect(() => {
    const node = el.current;
    if (!node || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver((entries) => setOn(entries.some((e) => e.isIntersecting)), { rootMargin: "200px 0px" });
    io.observe(node);
    return () => io.disconnect();
  }, [el]);
  return on;
}

let saving = false;

/**
 * Saves the file: Android's "save as" screen, or the webview's download elsewhere. One save
 * at a time, so a second tap cannot redirect the first (review M3-10).
 */
export async function saveFile(m: MessageView): Promise<void> {
  const a = m.attachment;
  if (!a || saving) return;
  saving = true;
  try {
    if (await isAndroid()) {
      await ipc.saveAttachment(m.id).catch((err: unknown) => {
        if (err instanceof IpcError && err.message === "Cancelled") return;
        throw err;
      });
      return;
    }
    const buf = await ipc.attachmentData(m.id);
    const url = URL.createObjectURL(new Blob([buf], { type: a.mime }));
    const link = document.createElement("a");
    link.href = url;
    link.download = a.name ?? (a.kind === "voice" ? "voice-note" : a.kind === "image" ? "photo" : "file");
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
  } finally {
    saving = false;
  }
}

function stateLabel(a: AttachmentView, mine: boolean): string {
  const pct = `${Math.round(a.progress * 100)}%`;
  switch (a.state) {
    case "uploading":
      return `Encrypting and uploading · ${pct}`;
    case "downloading":
      return `Downloading · ${pct}`;
    case "failed":
      return mine ? "Not sent" : "Could not download";
    case "too_large":
      return "Too large for this version of Veil";
    case "available":
      return `Not downloaded · ${formatBytes(a.size)}`;
    default:
      return formatBytes(a.size);
  }
}

function Progress({ a, label }: { a: AttachmentView; label: string }) {
  if (a.state !== "uploading" && a.state !== "downloading") return null;
  const v = Math.round(a.progress * 100);
  return (
    <span className="progress" role="progressbar" aria-label={label} aria-valuenow={v} aria-valuemin={0} aria-valuemax={100}>
      <i style={{ ["--p" as string]: String(a.progress) }}></i>
    </span>
  );
}

/**
 * Try again after a failure, or download a file that was not fetched by itself (a contact
 * past the daily automatic-download allowance).
 */
function Retry({ m, onError }: { m: MessageView; onError: (e: string) => void }) {
  const a = m.attachment;
  if (!a || (a.state !== "failed" && a.state !== "available")) return null;
  const fetch = a.state === "available";
  const label = fetch ? `Download, ${formatBytes(a.size)}` : m.mine ? "Try sending again" : "Try downloading again";
  return (
    <button className="icon-btn" type="button" aria-label={label} onClick={() => void ipc.retryAttachment(m.id).catch((err: unknown) => onError(errorText(err, "Could not retry")))}>
      <Icon name={fetch ? "download" : "refresh"} />
    </button>
  );
}

function ImageAttachment({ m, onOpen }: { m: MessageView; onOpen: () => void }) {
  const a = m.attachment;
  const box = useRef<HTMLButtonElement>(null);
  const onScreen = useOnScreen(box);
  const full = useFileUrl(m, onScreen && a !== null && a.size <= INLINE_MAX);
  const thumb = useThumbUrl(a);
  if (!a) return null;
  const src = full ?? thumb;
  const ready = hasFile(a, m.mine);
  const busy = a.state === "uploading" || a.state === "downloading";
  return (
    <button ref={box} className="att-img att-btn" type="button" aria-label={ready ? "Open photo" : `Photo, ${stateLabel(a, m.mine)}`} disabled={!ready} onClick={onOpen}>
      {src ? <img src={src} alt="" className={full ? "" : "att-thumb"} /> : <span className="art" />}
      {busy || a.state === "failed" || a.state === "too_large" || a.state === "available" ? (
        <span className="att-blur">
          <span className="att-dl">
            <Icon name={a.state === "failed" || a.state === "too_large" ? "alert-circle" : m.mine ? "upload" : "download"} />
            {stateLabel(a, m.mine)}
          </span>
        </span>
      ) : null}
    </button>
  );
}

function Wave({ bars, played }: { bars: number[]; played: number }) {
  const list = bars.length ? bars : new Array<number>(36).fill(40);
  const w = 3;
  const gap = 2;
  const h = 28;
  return (
    <svg className="wave" viewBox={`0 0 ${list.length * (w + gap)} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      {list.map((v, i) => {
        const bh = Math.max(3, Math.round((v / 255) * h));
        return <rect key={i} x={i * (w + gap)} y={(h - bh) / 2} width={w} height={bh} rx={1.5} className={i / list.length < played ? "played" : ""} />;
      })}
    </svg>
  );
}

/** Plays only when tapped; list refreshes do not touch the player (review M3-3). */
function VoiceNote({ m, onError }: { m: MessageView; onError: (e: string) => void }) {
  const a = m.attachment;
  const audio = useRef<HTMLAudioElement | null>(null);
  const url = useRef<string | null>(null);
  const mounted = useRef(true);
  const [playing, setPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const [played, setPlayed] = useState(0);

  function release() {
    audio.current?.pause();
    audio.current = null;
    if (url.current) URL.revokeObjectURL(url.current);
    url.current = null;
  }
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      release();
    };
  }, []);

  if (!a) return null;
  const ready = hasFile(a, m.mine);
  const dur = a.durationMs ?? 0;

  async function toggle() {
    const el = audio.current;
    if (el) {
      if (el.paused) await el.play().then(() => setPlaying(true), () => undefined);
      else {
        el.pause();
        setPlaying(false);
      }
      return;
    }
    if (!a) return;
    setLoading(true);
    try {
      const buf = await ipc.attachmentData(m.id);
      if (!mounted.current) return;
      const u = URL.createObjectURL(new Blob([buf], { type: a.mime }));
      const next = new Audio(u);
      url.current = u;
      audio.current = next;
      next.ontimeupdate = () => setPlayed(next.duration ? next.currentTime / next.duration : 0);
      next.onended = () => {
        setPlaying(false);
        setPlayed(0);
        release();
      };
      await next.play();
      setPlaying(true);
    } catch (err) {
      release();
      setPlaying(false);
      onError(errorText(err, "Could not play this voice note"));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }

  return (
    <div className="voice">
      <button className="play" type="button" disabled={!ready || loading} aria-label={`${playing ? "Pause" : "Play"} voice note, ${formatDuration(dur)}`} onClick={() => void toggle()}>
        <Icon name={playing ? "pause" : "play"} />
      </button>
      <Wave bars={a.waveform} played={played} />
      <span className="vdur">{ready ? formatDuration(dur) : stateLabel(a, m.mine)}</span>
    </div>
  );
}

function FileAttachment({ m, onError }: { m: MessageView; onError: (e: string) => void }) {
  const a = m.attachment;
  const [busy, setBusy] = useState(false);
  if (!a) return null;
  const label = stateLabel(a, m.mine);
  const name = a.name ?? (a.kind === "image" ? "Photo" : "File");
  async function save() {
    setBusy(true);
    try {
      await saveFile(m);
    } catch (err) {
      onError(errorText(err, "Could not save"));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="att-file">
      <span className="ficon"><Icon name="file" /></span>
      <span className="fmeta">
        <span className="fname">{name}</span>
        <span className="fsub">{a.state === "ready" || a.state === "sent" ? `${formatBytes(a.size)} · ${a.mime}` : label}</span>
        <Progress a={a} label={label} />
      </span>
      <Retry m={m} onError={onError} />
      {hasFile(a, m.mine) ? (
        <button className="icon-btn" type="button" disabled={busy} aria-label={`Save ${name}`} onClick={() => void save()}>
          <Icon name="download" />
        </button>
      ) : null}
    </div>
  );
}

/** The attachment part of a message bubble. */
export function AttachmentBody({ m, onOpenImage, onError }: { m: MessageView; onOpenImage: () => void; onError: (e: string) => void }) {
  const a = m.attachment;
  if (!a) return null;
  if (a.kind === "image" && a.size <= VIEW_MAX) {
    return (
      <>
        <ImageAttachment m={m} onOpen={onOpenImage} />
        <Retry m={m} onError={onError} />
      </>
    );
  }
  if (a.kind === "voice") {
    return (
      <>
        <VoiceNote m={m} onError={onError} />
        <Progress a={a} label={stateLabel(a, m.mine)} />
        <Retry m={m} onError={onError} />
      </>
    );
  }
  return <FileAttachment m={m} onError={onError} />;
}

/** Full-screen photo with Save and Close; Escape closes, Tab stays inside, focus returns. */
export function PhotoViewer({ m, onClose, onError }: { m: MessageView; onClose: () => void; onError: (e: string) => void }) {
  const url = useFileUrl(m, true);
  const box = useRef<HTMLDivElement>(null);
  const close = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);
  useDialogKeys(box, onClose);
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    close.current?.focus();
    return () => opener?.focus();
  }, []);
  async function save() {
    setBusy(true);
    try {
      await saveFile(m);
    } catch (err) {
      onError(errorText(err, "Could not save"));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div ref={box} className="scrim viewer" role="dialog" aria-modal="true" aria-label="Photo">
      <div className="viewer-bar">
        <button className="icon-btn" type="button" disabled={busy} aria-label="Save photo" onClick={() => void save()}><Icon name="download" /></button>
        <button ref={close} className="icon-btn" type="button" aria-label="Close photo" onClick={onClose}><Icon name="x" /></button>
      </div>
      {url ? <img className="viewer-img" src={url} alt="Photo" /> : null}
    </div>
  );
}
