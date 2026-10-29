// The user's profile in Settings, and the picture cropper it and the contact profile share
// (milestone 4.5, ADR-0020). Pictures go to Rust as small JPEGs (`preparePicture`).
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type PointerEvent } from "react";
import { IpcError, ipc, type PictureVisibility, type ProfileView } from "../ipc";
import { centreCrop, preparePicture, type Crop } from "../pictures";
import { Avatar, Icon, Segmented } from "../ui";

const VIEW = 240;

function errText(e: unknown, fallback: string): string {
  return e instanceof IpcError || e instanceof Error ? e.message : fallback;
}

/** Choose the square part of a picture to keep: drag (or arrow keys) to move, slider to zoom. */
export function PictureCropper({ file, onDone, onCancel }: { file: File; onDone: (crop: Crop) => void; onCancel: () => void }) {
  const [url, setUrl] = useState<string | null>(null);
  const [nat, setNat] = useState<{ w: number; h: number } | null>(null);
  const [zoom, setZoom] = useState(1);
  const [centre, setCentre] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const drag = useRef<{ id: number; x: number; y: number } | null>(null);
  useEffect(() => {
    const u = URL.createObjectURL(file);
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [file]);

  const side = nat ? Math.min(nat.w, nat.h) / zoom : 1;
  const scale = VIEW / side;
  const clamp = (c: { x: number; y: number }, s = side) =>
    nat ? { x: Math.min(Math.max(c.x, s / 2), nat.w - s / 2), y: Math.min(Math.max(c.y, s / 2), nat.h - s / 2) } : c;
  function move(dx: number, dy: number) {
    setCentre((c) => clamp({ x: c.x - dx / scale, y: c.y - dy / scale }));
  }
  function onDown(e: PointerEvent<HTMLDivElement>) {
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY };
  }
  function onMove(e: PointerEvent<HTMLDivElement>) {
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    move(e.clientX - d.x, e.clientY - d.y);
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY };
  }
  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    const step = 12;
    const d = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[e.key];
    if (!d) return;
    e.preventDefault();
    move(d[0] ?? 0, d[1] ?? 0);
  }
  function setZoomTo(z: number) {
    if (!nat) return;
    setZoom(z);
    setCentre((c) => clamp(c, Math.min(nat.w, nat.h) / z));
  }

  return (
    <div className="cropper stack-sm" role="group" aria-label="Crop your picture">
      <p id="crop-hint" className="hint">Drag, or use the arrow keys, to move the picture; the circle is what contacts see.</p>
      <div
        className="crop-view"
        role="group"
        tabIndex={0}
        aria-label="Picture position"
        aria-describedby="crop-hint"
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={() => { drag.current = null; }}
        onPointerCancel={() => { drag.current = null; }}
        onKeyDown={onKey}
      >
        {url ? (
          <img
            src={url}
            alt=""
            draggable={false}
            onLoad={(e) => {
              const w = e.currentTarget.naturalWidth;
              const h = e.currentTarget.naturalHeight;
              setNat({ w, h });
              const c = centreCrop(w, h);
              setCentre({ x: c.x + c.size / 2, y: c.y + c.size / 2 });
            }}
            style={nat ? { transform: `translate(${VIEW / 2 - centre.x * scale}px, ${VIEW / 2 - centre.y * scale}px) scale(${scale})` } : { opacity: 0 }}
          />
        ) : null}
      </div>
      <div className="range">
        <span className="range-label" id="crop-zoom">Zoom</span>
        <input type="range" min={1} max={4} step={0.05} value={zoom} aria-labelledby="crop-zoom" aria-valuetext={`${zoom.toFixed(1)} times`} onChange={(e) => setZoomTo(Number(e.target.value))} />
      </div>
      <div className="banner-actions">
        <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
        <button className="btn btn-primary" type="button" disabled={!nat} onClick={() => onDone({ x: centre.x - side / 2, y: centre.y - side / 2, size: side })}>Use picture</button>
      </div>
    </div>
  );
}

function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return parts.slice(0, 2).map((p) => [...p][0] ?? "").join("").toUpperCase() || "?";
}

const VISIBILITY_HINT: Record<PictureVisibility, string> = {
  all: "Every contact sees your picture.",
  verified: "Only contacts whose safety number you verified see your picture.",
  nobody: "Nobody sees your picture; it stays on this device.",
};

/** Settings → Profile: picture, name, status and who sees the picture. */
export function ProfileCard({ onChanged }: { onChanged: () => void }) {
  const [p, setP] = useState<ProfileView | null>(null);
  const [name, setName] = useState("");
  const [status, setStatus] = useState("");
  const [picked, setPicked] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);

  async function load() {
    try {
      const v = await ipc.profile();
      setP(v);
      setName(v.name);
      setStatus(v.status);
    } catch {
      setP(null);
    }
  }
  useEffect(() => {
    void load();
  }, []);

  async function act(f: () => Promise<void>, fallback: string) {
    setError(null);
    setSaved(false);
    setBusy(true);
    try {
      await f();
      await load();
      onChanged();
      return true;
    } catch (e) {
      setError(errText(e, fallback));
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function save(e: FormEvent) {
    e.preventDefault();
    if (await act(() => ipc.setProfile(name, status), "Could not save your profile")) setSaved(true);
  }
  async function crop(c: Crop) {
    const f = picked;
    setPicked(null);
    if (!f) return;
    await act(async () => ipc.setMyPicture(await preparePicture(f, c)), "Could not set the picture");
  }

  if (!p) return null;
  return (
    <section className="card stack">
      <div className="profile-head">
        <Avatar initials={initialsOf(p.name)} hue={5} size="xl" owner={null} picture={p.picture} />
        <div className="stack-sm">
          <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => file.current?.click()}>
            <Icon name="image" />{p.picture ? "Change picture" : "Add a picture"}
          </button>
          {p.picture ? (
            <button className="btn btn-danger-ghost" type="button" disabled={busy} onClick={() => void act(() => ipc.setMyPicture(null), "Could not remove the picture")}>
              <Icon name="trash" />Remove picture
            </button>
          ) : null}
        </div>
        <input ref={file} type="file" accept="image/*" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) setPicked(f); }} />
      </div>
      {picked ? <PictureCropper file={picked} onDone={(c) => void crop(c)} onCancel={() => setPicked(null)} /> : null}
      <form className="stack-sm" onSubmit={(e) => void save(e)}>
        <div className="field">
          <label htmlFor="my-name">Your name</label>
          <div className="input"><input id="my-name" maxLength={64} value={name} autoComplete="off" onChange={(e) => setName(e.target.value)} /></div>
        </div>
        <div className="field">
          <label htmlFor="my-status">Status</label>
          <div className="input"><input id="my-status" maxLength={140} value={status} placeholder="Optional, one line" autoComplete="off" onChange={(e) => setStatus(e.target.value)} /></div>
        </div>
        <button className="btn btn-secondary btn-block" type="submit" disabled={busy}>Save</button>
        {saved ? <p className="hint" role="status">Saved. Your contacts get it end-to-end encrypted.</p> : null}
      </form>
      <div className="field">
        <span className="label">Who sees your picture</span>
        <Segmented<PictureVisibility>
          name="picture-visibility"
          label="Who sees your picture"
          value={p.visibility}
          options={[["all", "All contacts"], ["verified", "Verified"], ["nobody", "Nobody"]]}
          onChange={(v) => void act(() => ipc.setPictureVisibility(v), "Could not change who sees your picture")}
        />
        <p className="hint">{VISIBILITY_HINT[p.visibility]} You can also hide it from one contact in their profile. A contact who saw it may have kept a copy.</p>
      </div>
      {error ? <p className="field-error" role="alert">{error}</p> : null}
    </section>
  );
}
