// Appearance preferences (Settings → Appearance). Conveniences only, kept in localStorage and
// wrapped in try/catch; nothing security-relevant lives here (DESIGN.md §8). Wallpapers are kept
// in the encrypted database instead (they can be the user's own photo, ADR-0019).
import { ipc } from "./ipc";
import { ACCENT_VARS, accentVars } from "./color";
export type Style = "aurora" | "ink";
export type Mode = "system" | "dark" | "light";
export type Accent = "aurora" | "lagoon" | "ember" | "custom";
export type Bubble = "gradient" | "soft" | "minimal";
export type TextSize = "sm" | "md" | "lg" | "xl";
export type Density = "regular" | "compact";

export interface Appearance {
  style: Style;
  mode: Mode;
  accent: Accent;
  /** The custom accent's hue (0–359), used when `accent` is "custom". */
  hue: number;
  /** Pure black backgrounds in dark mode (OLED screens). */
  black: boolean;
  bubble: Bubble;
  textSize: TextSize;
  density: Density;
  reduceMotion: boolean;
}

const KEY = "veil.appearance";
const DEFAULTS: Appearance = {
  style: "aurora",
  mode: "system",
  accent: "aurora",
  hue: 245,
  black: false,
  bubble: "gradient",
  textSize: "md",
  density: "regular",
  reduceMotion: false,
};

function pick<T extends string>(v: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(v as T) ? (v as T) : fallback;
}

export function loadAppearance(): Appearance {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;
    const v = JSON.parse(raw) as Partial<Record<keyof Appearance, unknown>>;
    const hue = typeof v.hue === "number" && Number.isFinite(v.hue) ? Math.round(v.hue) : DEFAULTS.hue;
    return {
      style: pick(v.style, ["aurora", "ink"], "aurora"),
      mode: pick(v.mode, ["system", "dark", "light"], "system"),
      accent: pick(v.accent, ["aurora", "lagoon", "ember", "custom"], "aurora"),
      hue: ((hue % 360) + 360) % 360,
      black: v.black === true,
      bubble: pick(v.bubble, ["gradient", "soft", "minimal"], "gradient"),
      textSize: pick(v.textSize, ["sm", "md", "lg", "xl"], "md"),
      density: pick(v.density, ["regular", "compact"], "regular"),
      reduceMotion: v.reduceMotion === true,
    };
  } catch {
    return DEFAULTS;
  }
}

export function isDark(a: Appearance): boolean {
  return a.mode === "dark" || (a.mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
}

export function applyAppearance(a: Appearance): void {
  const root = document.documentElement;
  const dark = isDark(a);
  root.dataset["style"] = a.style;
  root.dataset["theme"] = dark ? "dark" : "light";
  root.dataset["accent"] = a.accent;
  root.dataset["black"] = dark && a.black ? "true" : "false";
  root.dataset["bubble"] = a.bubble;
  root.dataset["textSize"] = a.textSize;
  root.dataset["density"] = a.density;
  // A custom accent is computed (contrast-checked) for this theme; presets come from tokens.
  for (const name of ACCENT_VARS) root.style.removeProperty(name);
  if (a.accent === "custom") {
    for (const [name, value] of Object.entries(accentVars(a.hue, dark))) root.style.setProperty(name, value);
  }
  const reduce = a.reduceMotion || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  root.dataset["motion"] = reduce ? "reduced" : "full";
  // Android: the status and navigation bar area follows the theme.
  void ipc.setDarkBars(dark).catch(() => undefined);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(a));
  } catch {
    /* private mode or blocked storage: appearance still applies for this session */
  }
}
