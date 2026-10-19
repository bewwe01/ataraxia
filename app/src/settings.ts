// Appearance preferences (Settings → Appearance). Conveniences only, kept in localStorage and
// wrapped in try/catch; nothing security-relevant lives here (DESIGN.md §8).
export type Style = "aurora" | "ink";
export type Mode = "system" | "dark" | "light";
export type Accent = "aurora" | "lagoon" | "ember";

export interface Appearance {
  style: Style;
  mode: Mode;
  accent: Accent;
  reduceMotion: boolean;
}

const KEY = "veil.appearance";
const DEFAULTS: Appearance = { style: "aurora", mode: "system", accent: "aurora", reduceMotion: false };

export function loadAppearance(): Appearance {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;
    const v = JSON.parse(raw) as Partial<Appearance>;
    return {
      style: v.style === "ink" ? "ink" : "aurora",
      mode: v.mode === "dark" || v.mode === "light" ? v.mode : "system",
      accent: v.accent === "lagoon" || v.accent === "ember" ? v.accent : "aurora",
      reduceMotion: v.reduceMotion === true,
    };
  } catch {
    return DEFAULTS;
  }
}

export function applyAppearance(a: Appearance): void {
  const root = document.documentElement;
  const dark = a.mode === "dark" || (a.mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  root.dataset["style"] = a.style;
  root.dataset["theme"] = dark ? "dark" : "light";
  root.dataset["accent"] = a.accent;
  const reduce = a.reduceMotion || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  root.dataset["motion"] = reduce ? "reduced" : "full";
  try {
    window.localStorage.setItem(KEY, JSON.stringify(a));
  } catch {
    /* private mode or blocked storage: appearance still applies for this session */
  }
}
