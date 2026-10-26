// Photos, files and voice notes in a conversation (DESIGN.md §6 `<ImageAttachment>`,
// `<FileAttachment>`, `<VoiceNote>`, `<Progress>`). The file comes from Rust only when it is
// shown, played or saved, as a blob: URL that is revoked when it is no longer needed.
import { useEffect, useRef, useState } from "react";
import { ipc, IpcError, type AttachmentView, type MessageView } from "../ipc";
import { formatBytes, formatDuration } from "../media";
import { Icon } from "../ui";

let android: boolean | null = null;
async function isAndroid(): Promise<boolean> {
  if (android === null) android = await ipc.nativeInfo().then((n) => n.android, () => false);
  return android;
}

function hasFile(a: AttachmentView, mine: boolean): boolean {
  return a.state === "ready" || (mine && (a.state === "uploading" || a.state === "sent"));
}

/** A blob: URL for the file while `want` is true; revoked afterwards. */
function useFileUrl(m: MessageView, want: boolean): string | null {
  const [url, setUrl] = useState<string | null>(null);
  const a = m.attachment;
  const ok = want && a !== null && hasFile(a, m.mine);
  useEffect(() => {
    if (!ok || !a) return;
    let live = true;
    let made: string | null = null;
    ipc.attachmentData(m.id).then(
      (buf) => {
        if (!live) return;
        made = URL.createObjectURL(new Blob([buf], { type: a.mime }));
        setUrl(made);
      },
      () => undefined,
    );
    return () => {
      live = false;
      if (made) URL.revokeObjectURL(made);
      setUrl(null);
    };
  }, [m.id, ok, a]);
  return url;
}

function useThumbUrl(a: AttachmentView | null): string | null {
  const [url, setUrl] = useState<string | null>(null);
  const bytes = a?.thumbnail ?? null;
  useEffect(() => {
    if (!bytes || bytes.length === 0) return;
    const u = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: "image/jpeg" }));
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [bytes]);
  return url;
}

/** Saves the file: Android's "save as" screen, or the webview's download elsewhere. */
export async function saveFile(m: MessageView): Promise<void> {
  const a = m.attachment;
  if (!a) return;
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

function Retry({ m, onError }: { m: MessageView; onError: (e: string) => void }) {
  return (
    <button className="icon-btn" type="button" aria-label={m.mine ? "Try sending again" : "Try downloading again"} onClick={() => void ipc.retryAttachment(m.id).catch((err: unknown) => onError(err instanceof IpcError ? err.message : "Could not retry"))}>
      <Icon name="refresh" />
    </button>
  );
}

function ImageAttachment({ m, onOpen }: { m: MessageView; onOpen: () => void }) {
  const a = m.attachment;
  const full = useFileUrl(m, true);
  const thumb = useThumbUrl(a);
  if (!a) return null;
  const src = full ?? thumb;
  const busy = a.state === "uploading" || a.state === "downloading";
  return (
    <button className="att-img att-btn" type="button" aria-label={full ? "Open photo" : `Photo, ${stateLabel(a, m.mine)}`} disabled={!full} onClick={onOpen}>
      {src ? <img src={src} alt="" className={full ? "" : "att-thumb"} /> : <span className="art" />}
      {busy || a.state === "failed" || a.state === "too_large" ? (
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

function VoiceNote({ m }: { m: MessageView }) {
  const a = m.attachment;
  const [want, setWant] = useState(false);
  const url = useFileUrl(m, want);
  const audio = useRef<HTMLAudioElement | null>(null);
  const [playing, setPlaying] = useState(false);
  const [played, setPlayed] = useState(0);

  useEffect(() => {
    if (!url) return;
    const el = new Audio(url);
    audio.current = el;
    el.ontimeupdate = () => setPlayed(el.duration ? el.currentTime / el.duration : 0);
    el.onended = () => {
      setPlaying(false);
      setPlayed(0);
    };
    void el.play().then(() => setPlaying(true), () => setPlaying(false));
    return () => {
      el.pause();
      audio.current = null;
    };
  }, [url]);

  if (!a) return null;
  const ready = hasFile(a, m.mine);
  const dur = a.durationMs ?? 0;
  function toggle() {
    const el = audio.current;
    if (!el) {
      setWant(true);
      return;
    }
    if (el.paused) void el.play().then(() => setPlaying(true), () => undefined);
    else {
      el.pause();
      setPlaying(false);
    }
  }
  return (
    <div className="voice">
      <button className="play" type="button" disabled={!ready} aria-label={`${playing ? "Pause" : "Play"} voice note, ${formatDuration(dur)}`} onClick={toggle}>
        <Icon name={playing ? "pause" : "play"} />
      </button>
      <Wave bars={a.waveform} played={played} />
      <span className="vdur">{ready ? formatDuration(dur) : stateLabel(a, m.mine)}</span>
    </div>
  );
}

function FileAttachment({ m, onError }: { m: MessageView; onError: (e: string) => void }) {
  const a = m.attachment;
  if (!a) return null;
  const label = stateLabel(a, m.mine);
  return (
    <div className="att-file">
      <span className="ficon"><Icon name="file" /></span>
      <span className="fmeta">
        <span className="fname">{a.name ?? "File"}</span>
        <span className="fsub">{a.state === "ready" || a.state === "sent" ? `${formatBytes(a.size)} · ${a.mime}` : label}</span>
        <Progress a={a} label={label} />
      </span>
      {a.state === "failed" ? <Retry m={m} onError={onError} /> : null}
      {hasFile(a, m.mine) ? (
        <button className="icon-btn" type="button" aria-label={`Save ${a.name ?? "file"}`} onClick={() => void saveFile(m).catch((err: unknown) => onError(err instanceof IpcError ? err.message : "Could not save"))}>
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
  if (a.kind === "image") {
    return (
      <>
        <ImageAttachment m={m} onOpen={onOpenImage} />
        {a.state === "failed" ? <Retry m={m} onError={onError} /> : null}
      </>
    );
  }
  if (a.kind === "voice") {
    return (
      <>
        <VoiceNote m={m} />
        <Progress a={a} label={stateLabel(a, m.mine)} />
        {a.state === "failed" ? <Retry m={m} onError={onError} /> : null}
      </>
    );
  }
  return <FileAttachment m={m} onError={onError} />;
}

/** Full-screen photo with Save and Close (Escape closes). */
export function PhotoViewer({ m, onClose, onError }: { m: MessageView; onClose: () => void; onError: (e: string) => void }) {
  const url = useFileUrl(m, true);
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    close.current?.focus();
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="scrim viewer" role="dialog" aria-modal="true" aria-label="Photo">
      <div className="viewer-bar">
        <button className="icon-btn" type="button" aria-label="Save photo" onClick={() => void saveFile(m).catch((err: unknown) => onError(err instanceof IpcError ? err.message : "Could not save"))}><Icon name="download" /></button>
        <button ref={close} className="icon-btn" type="button" aria-label="Close photo" onClick={onClose}><Icon name="x" /></button>
      </div>
      {url ? <img className="viewer-img" src={url} alt="Photo" /> : null}
    </div>
  );
}
