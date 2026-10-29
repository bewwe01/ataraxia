// Pickers for the look (milestone 4.5, ADR-0019): a colour from one hue, and a wallpaper.
// Settings uses them for the app's defaults, a contact's profile for that chat alone.
import { useEffect, useRef, useState, type ChangeEvent, type CSSProperties, type RefObject } from "react";
import { HUES, swatch } from "../color";
import { IpcError, WALLPAPER_PRESETS, type WallpaperPreset, type WallpaperView } from "../ipc";
import { preparePhoto, saveWallpaper, WallpaperLayer } from "../wallpaper";
import { Banner, Icon } from "../ui";

const HUE_NAMES: Record<number, string> = {
  0: "Red", 25: "Orange", 45: "Amber", 140: "Green", 170: "Teal", 195: "Cyan",
  215: "Blue", 245: "Indigo", 270: "Violet", 295: "Purple", 320: "Magenta", 340: "Pink",
};

/** Calls `commit` on a slider's native `change` event: once, when a drag or a key step ends
 *  (React's `onChange` fires on every move, and key-up also fires for Tab). */
function useSliderCommit(ref: RefObject<HTMLInputElement | null>, commit: (v: number) => void, shown = true) {
  const latest = useRef(commit);
  latest.current = commit;
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const on = () => latest.current(Number(el.value));
    el.addEventListener("change", on);
    return () => el.removeEventListener("change", on);
  }, [ref, shown]);
}

/** Hue swatches and a slider for any other hue. `none` adds a first choice for "no colour of its own". */
export function HuePicker({ name, label, value, none, onChange }: {
  name: string;
  label: string;
  value: number | null;
  none?: string;
  onChange: (h: number | null) => void;
}) {
  // The slider moves freely; the hue is saved when it is let go, if it changed.
  const [draft, setDraft] = useState(value ?? 245);
  useEffect(() => setDraft(value ?? 245), [value]);
  const slider = useRef<HTMLInputElement>(null);
  useSliderCommit(slider, (h) => {
    if (h !== value) onChange(h);
  });
  return (
    <div className="stack-sm">
      <div className="hue-swatches" role="radiogroup" aria-label={label}>
        {none ? (
          <label className="hue-swatch none" title={none}>
            <input type="radio" name={name} checked={value === null} onChange={() => onChange(null)} aria-label={none} />
            <span aria-hidden="true"><Icon name="x" className="icon-sm" /></span>
          </label>
        ) : null}
        {HUES.map((h) => (
          <label key={h} className="hue-swatch" title={HUE_NAMES[h]}>
            <input type="radio" name={name} checked={value === h} onChange={() => onChange(h)} aria-label={HUE_NAMES[h]} />
            <span aria-hidden="true" style={{ background: swatch(h) }} />
          </label>
        ))}
      </div>
      <div className="range">
        <span className="hue-dot" aria-hidden="true" style={{ background: swatch(draft) }} />
        <input
          ref={slider}
          type="range"
          min={0}
          max={359}
          step={1}
          value={draft}
          aria-label={`${label}, hue`}
          aria-valuetext={`Hue ${draft}`}
          onChange={(e) => setDraft(Number(e.target.value))}
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
  /** A choice that would delete the photo, waiting for the user to confirm. */
  const [replacing, setReplacing] = useState<WallpaperPreset | "none" | null>(null);
  // Radios stay enabled while saving (disabling the focused one would drop keyboard focus);
  // a ref keeps one save at a time.
  const saving = useRef(false);
  const file = useRef<HTMLInputElement>(null);
  const dimRef = useRef<HTMLInputElement>(null);
  const blurRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    setDim(value?.dim ?? 0);
    setBlur(value?.blur ?? 0);
  }, [value?.dim, value?.blur]);
  const name = contact === null ? "wp-default" : `wp-${contact}`;

  async function save(f: () => Promise<void>) {
    if (saving.current) return;
    saving.current = true;
    setError(null);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setError(e instanceof IpcError || e instanceof Error ? e.message : "The wallpaper could not be set");
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  const apply = (preset: WallpaperPreset | "none") =>
    save(() => saveWallpaper(contact, preset === "none" ? null : { preset, photo: null, keepPhoto: false, dim, blur }));
  function choose(preset: WallpaperPreset | "none") {
    // Leaving a photo deletes it: ask first (an arrow key in the group is enough to get here).
    if (value?.photo) setReplacing(preset);
    else void apply(preset);
  }
  const levels = (d: number, b: number) => {
    if (!value || (d === value.dim && b === value.blur)) return;
    void save(() => saveWallpaper(contact, { preset: value.preset, photo: null, keepPhoto: value.photo, dim: d, blur: b }));
  };
  useSliderCommit(dimRef, (d) => levels(d, blur), value !== null);
  useSliderCommit(blurRef, (b) => levels(dim, b), value !== null);
  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    await save(async () => saveWallpaper(contact, { preset: null, photo: await preparePhoto(f), keepPhoto: false, dim, blur }));
  }

  const shown = { dim, blur };
  return (
    <div className="stack-sm">
      <div className="wp-tiles" role="radiogroup" aria-label="Wallpaper" aria-busy={busy}>
        <label className="wp-tile">
          <input type="radio" name={name} checked={value === null} onChange={() => choose("none")} />
          <span className="wp-thumb" aria-hidden="true" />
          <span className="wp-name">{contact === null ? "None" : "Default"}</span>
        </label>
        {WALLPAPER_PRESETS.map((p) => (
          <label key={p} className="wp-tile">
            <input type="radio" name={name} checked={value?.preset === p} onChange={() => choose(p)} />
            <span className="wp-thumb" aria-hidden="true"><WallpaperLayer w={{ preset: p, photo: false, ...shown }} photoUrl={null} /></span>
            <span className="wp-name">{PRESET_NAMES[p]}</span>
          </label>
        ))}
        <label className="wp-tile">
          {/* The file chooser opens on a click or Space only, never as arrow keys pass by. */}
          <input type="radio" name={name} checked={value?.photo === true} onChange={() => undefined} onClick={() => file.current?.click()} />
          <span className="wp-thumb" aria-hidden="true">
            {value?.photo && photoUrl ? <WallpaperLayer w={{ preset: null, photo: true, ...shown }} photoUrl={photoUrl} /> : <Icon name="image" />}
          </span>
          <span className="wp-name">{value?.photo ? "Change photo" : "Photo"}</span>
        </label>
        <input ref={file} type="file" accept="image/jpeg,image/png,image/webp" hidden onChange={(e) => void pick(e)} />
      </div>
      {replacing ? (
        <div role="alertdialog" aria-labelledby={`${name}-rt`} aria-describedby={`${name}-rd`}>
          <Banner tone="warning" icon="image">
            <strong id={`${name}-rt`}>Remove your photo wallpaper?</strong>
            <p id={`${name}-rd`}>The photo is deleted from Veil. You can pick it again from your files.</p>
            <div className="banner-actions">
              <button className="btn btn-secondary" type="button" autoFocus onClick={() => setReplacing(null)}>Keep photo</button>
              <button className="btn btn-danger" type="button" onClick={() => { const p = replacing; setReplacing(null); void apply(p); }}>Remove</button>
            </div>
          </Banner>
        </div>
      ) : null}
      {value ? (
        <>
          <div className="range">
            <span className="range-label" id={`${name}-dim`}>Dim</span>
            <input ref={dimRef} type="range" min={0} max={80} step={5} value={dim} aria-labelledby={`${name}-dim`} aria-valuetext={`${dim}%`}
              onChange={(e) => setDim(Number(e.target.value))} />
          </div>
          <div className="range">
            <span className="range-label" id={`${name}-blur`}>Blur</span>
            <input ref={blurRef} type="range" min={0} max={24} step={2} value={blur} aria-labelledby={`${name}-blur`} aria-valuetext={`${blur} pixels`}
              onChange={(e) => setBlur(Number(e.target.value))} />
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
