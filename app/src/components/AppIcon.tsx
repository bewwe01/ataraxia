// Settings → Security → App icon (Android, ADR-0022): Veil's own launcher icon, or a disguise
// (Calculator, Notes, Weather, Clock) with that name on the home screen, in the app drawer,
// in recent apps and in notifications. The glyphs match the launcher icons that
// app/android/harden.py draws, here in design tokens.
import { useEffect, useState } from "react";
import { IpcError, ipc, type AppIcon } from "../ipc";
import { Logo } from "../ui";

const NAMES: Record<AppIcon, string> = {
  veil: "Veil",
  calculator: "Calculator",
  notes: "Notes",
  weather: "Weather",
  clock: "Clock",
};
const ORDER: AppIcon[] = ["veil", "calculator", "notes", "weather", "clock"];

/** The same paths as the Android icons (108-unit canvas, shown from 24 to 84). */
function Glyph({ icon }: { icon: Exclude<AppIcon, "veil"> }) {
  const body = "M40,28h28a4,4 0 0 1 4,4v44a4,4 0 0 1 -4,4h-28a4,4 0 0 1 -4,-4v-44a4,4 0 0 1 4,-4z";
  return (
    <svg className="appicon-glyph" viewBox="24 24 60 60" aria-hidden="true">
      {icon === "calculator" ? (
        <path fillRule="evenodd" d={`${body} M41,33h26v9h-26z M41,47h7v7h-7z M50.5,47h7v7h-7z M60,47h7v7h-7z M41,57h7v7h-7z M50.5,57h7v7h-7z M60,57h7v7h-7z M41,67h7v7h-7z M50.5,67h7v7h-7z M60,67h7v7h-7z`} />
      ) : icon === "notes" ? (
        <path fillRule="evenodd" d={`${body} M43,38h22v3h-22z M43,47h22v3h-22z M43,56h22v3h-22z M43,65h14v3h-14z`} />
      ) : icon === "weather" ? (
        <>
          <path className="appicon-sun" d="M34,46a10,10 0 1 0 20,0a10,10 0 1 0 -20,0z" />
          <path d="M37,64a9,9 0 1 0 18,0a9,9 0 1 0 -18,0z M49,60a11,11 0 1 0 22,0a11,11 0 1 0 -22,0z M61,68a7,7 0 1 0 14,0a7,7 0 1 0 -14,0z M42,66v9h26v-9z" />
        </>
      ) : (
        <>
          <path fillRule="evenodd" d="M30,54a24,24 0 1 0 48,0a24,24 0 1 0 -48,0z M34,54a20,20 0 1 0 40,0a20,20 0 1 0 -40,0z" />
          <path d="M52,40h4v16h-4z M54,52h11v4h-11z" />
        </>
      )}
    </svg>
  );
}

export function AppIconPicker() {
  const [icon, setIcon] = useState<AppIcon | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void ipc.appIcon().then(setIcon, () => setIcon(null));
  }, []);
  // Only where the launcher icon can change (Android).
  if (!icon) return null;

  async function choose(next: AppIcon) {
    if (next === icon || busy) return;
    setError(null);
    setNote(null);
    setBusy(true);
    try {
      await ipc.setAppIcon(next);
      setIcon(next);
      setNote(
        next === "veil"
          ? "Veil shows as Veil again."
          : `Veil now shows as “${NAMES[next]}”. Your home screen may take a moment to update; if Veil's icon was on it, add the new one there.`,
      );
    } catch (e) {
      setError(e instanceof IpcError ? e.message : "Could not change the icon");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card stack-sm">
      <div className="appicon-tiles" role="radiogroup" aria-label="App icon" aria-busy={busy}>
        {ORDER.map((i) => (
          <label key={i} className="appicon-tile">
            <input type="radio" name="app-icon" value={i} checked={icon === i} disabled={busy} onChange={() => void choose(i)} />
            <span className="appicon-thumb" aria-hidden="true">{i === "veil" ? <Logo /> : <Glyph icon={i} />}</span>
            <span className="appicon-name">{NAMES[i]}{icon === i ? <span className="sr-only"> (in use)</span> : null}</span>
          </label>
        ))}
      </div>
      <p className="hint">A disguise changes Veil's name and icon on the home screen, in the app list and in recent apps. Notifications then show only that name and “Tap to open”; calls still say “Incoming call”. Android's own Settings → Apps still lists Veil, so this hides Veil from a glance, not from a search of the phone.</p>
      {note ? <p className="hint" role="status">{note}</p> : null}
      {error ? <p className="field-error" role="alert">{error}</p> : null}
    </section>
  );
}
