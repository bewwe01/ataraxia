// Pickers for the look (milestone 4.5, ADR-0019): a colour from one hue, and a wallpaper.
// Settings uses them for the app's defaults, a contact's profile for that chat alone.
import { useEffect, useRef, useState, type ChangeEvent, type CSSProperties } from "react";
import { HUES, swatch } from "../color";
import { IpcError, WALLPAPER_PRESETS, type WallpaperPreset, type WallpaperView } from "../ipc";
import { preparePhoto, saveWallpaper, WallpaperLayer } from "../wallpaper";
import { Icon } from "../ui";

const HUE_NAMES: Record<number, string> = {
  0: "Red", 25: "Orange", 45: "Amber", 140: "Green", 170: "Teal", 195: "Cyan",
  215: "Blue", 245: "Indigo", 270: "Violet", 295: "Purple", 320: "Magenta", 340: "Pink",
};

/** Hue swatches and a slider for any other hue. `none` adds a first choice for "no colour of its own". */
export function HuePicker({ name, label, value, none, onChange }: {
  name: string;
  label: string;
  value: number | null;
  none?: string;
  onChange: (h: number | null) => void;
}) {
  // The slider moves freely; the choice is saved when it is let go (or by keyboard, at once).
  const [draft, setDraft] = useState(value ?? 245);
  useEffect(() => setDraft(value ?? 245), [value]);
  return (
    <div className="stack-sm">
      <div className="swatches" role="radiogroup" aria-label={label}>
        {none ? (
          <label className="swatch none" title={none}>
            <input type="radio" name={name} checked={value === null} onChange={() => onChange(null)} aria-label={none} />
            <span aria-hidden="true"><Icon name="x" className="icon-sm" /></span>
          </label>
        ) : null}
        {HUES.map((h) => (
          <label key={h} className="swatch" title={HUE_NAMES[h]}>
            <input type="radio" name={name} checked={value === h} onChange={() => onChange(h)} aria-label={HUE_NAMES[h]} />
            <span aria-hidden="true" style={{ background: swatch(h) }} />
          </label>
        ))}
      </div>
      <div className="range">
        <span className="hue-dot" aria-hidden="true" style={{ background: swatch(draft) }} />
        <input
          type="range"
          min={0}
          max={359}
          step={1}
          value={draft}
          aria-label={`${label}, hue`}
          aria-valuetext={`Hue ${draft}`}
          onChange={(e) => setDraft(Number(e.target.value))}
          onPointerUp={() => onChange(draft)}
          onKeyUp={() => onChange(draft)}
        />
      </div>
    </div>
  );
}

const PRESET_NAMES: Record<WallpaperPreset, string> = {
  dusk: "Dusk", aurora: "Aurora", grid: "Grid", dots: "Dots", waves: "Waves", paper: "Paper",
};

/** Choose a wallpaper (none, a built-in one or a photo) with its dim and blur. `contact` null is
 *  the default for every chat; otherwise one chat's own, where "none" means "use the default". */
export function WallpaperPicker({ contact, value, photoUrl }: { contact: number | null; value: WallpaperView | null; photoUrl: string | null }) {
  const [dim, setDim] = useState(value?.dim ?? 0);
  const [blur, setBlur] = useState(value?.blur ?? 0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  useEffect(() => {
    setDim(value?.dim ?? 0);
    setBlur(value?.blur ?? 0);
  }, [value?.dim, value?.blur]);
  const name = contact === null ? "wp-default" : `wp-${contact}`;

  async function save(f: () => Promise<void>) {
    setError(null);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setError(e instanceof IpcError || e instanceof Error ? e.message : "The wallpaper could not be set");
    } finally {
      setBusy(false);
    }
  }
  const choose = (preset: WallpaperPreset | null) =>
    save(() => saveWallpaper(contact, preset ? { preset, photo: null, keepPhoto: false, dim, blur } : null));
  const commitLevels = () => {
    if (!value) return;
    void save(() => saveWallpaper(contact, { preset: value.preset, photo: null, keepPhoto: value.photo, dim, blur }));
  };
  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    await save(async () => saveWallpaper(contact, { preset: null, photo: await preparePhoto(f), keepPhoto: false, dim, blur }));
  }

  const levels = { dim, blur };
  return (
    <div className="stack-sm">
      <div className="wp-tiles" role="radiogroup" aria-label="Wallpaper" aria-busy={busy}>
        <label className="wp-tile">
          <input type="radio" name={name} checked={value === null} disabled={busy} onChange={() => void choose(null)} />
          <span className="wp-thumb" aria-hidden="true" />
          <span className="wp-name">{contact === null ? "None" : "Default"}</span>
        </label>
        {WALLPAPER_PRESETS.map((p) => (
          <label key={p} className="wp-tile">
            <input type="radio" name={name} checked={value?.preset === p} disabled={busy} onChange={() => void choose(p)} />
            <span className="wp-thumb" aria-hidden="true"><WallpaperLayer w={{ preset: p, photo: false, ...levels }} photoUrl={null} /></span>
            <span className="wp-name">{PRESET_NAMES[p]}</span>
          </label>
        ))}
        <label className="wp-tile">
          <input type="radio" name={name} checked={value?.photo === true} disabled={busy} onChange={() => file.current?.click()} onClick={() => { if (value?.photo) file.current?.click(); }} />
          <span className="wp-thumb" aria-hidden="true">
            {value?.photo && photoUrl ? <WallpaperLayer w={{ preset: null, photo: true, ...levels }} photoUrl={photoUrl} /> : <Icon name="image" />}
          </span>
          <span className="wp-name">{value?.photo ? "Change photo" : "Photo"}</span>
        </label>
        <input ref={file} type="file" accept="image/jpeg,image/png,image/webp" hidden onChange={(e) => void pick(e)} />
      </div>
      {value ? (
        <>
          <div className="range">
            <span className="range-label" id={`${name}-dim`}>Dim</span>
            <input type="range" min={0} max={80} step={5} value={dim} aria-labelledby={`${name}-dim`} aria-valuetext={`${dim}%`}
              onChange={(e) => setDim(Number(e.target.value))} onPointerUp={commitLevels} onKeyUp={commitLevels} />
          </div>
          <div className="range">
            <span className="range-label" id={`${name}-blur`}>Blur</span>
            <input type="range" min={0} max={24} step={2} value={blur} aria-labelledby={`${name}-blur`} aria-valuetext={`${blur} pixels`}
              onChange={(e) => setBlur(Number(e.target.value))} onPointerUp={commitLevels} onKeyUp={commitLevels} />
          </div>
        </>
      ) : null}
      {error ? <p className="field-error" role="alert">{error}</p> : null}
      <p className="hint">Kept encrypted on this device only; nobody else sees your wallpaper.</p>
    </div>
  );
}

/** A tiny live preview of a chat with the current look. */
export function LookPreview({ w, photoUrl, style }: { w: WallpaperView | null; photoUrl: string | null; style?: CSSProperties }) {
  return (
    <div className="look-preview" aria-hidden="true" style={style}>
      <WallpaperLayer w={w} photoUrl={photoUrl} />
      <div className="msg in"><div className="bubble">Hey, are we still on for tonight?</div></div>
      <div className="msg out"><div className="bubble">Yes! See you at eight.</div></div>
    </div>
  );
}
