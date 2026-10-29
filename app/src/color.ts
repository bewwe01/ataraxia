// Colours from one hue (milestone 4.5, custom accent and per-chat colour). Every colour is
// checked, not hoped for: white text and the dimmer meta text (times, quotes, sizes) on the
// sent bubble keep at least 4.5:1 at every gradient stop and between them, and the accent keeps
// 4.5:1 against every panel it sits on (WCAG AA, DESIGN.md). Lightness steps down (or up) until
// the contrast holds. `scripts/contrast-check.mjs` checks all 360 hues (run by `pnpm lint`).

export type Rgb = [number, number, number];

function hsl(h: number, s: number, l: number): Rgb {
  const hue = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = l - c / 2;
  const [r, g, b] =
    hue < 60 ? [c, x, 0] : hue < 120 ? [x, c, 0] : hue < 180 ? [0, c, x] : hue < 240 ? [0, x, c] : hue < 300 ? [x, 0, c] : [c, 0, x];
  return [Math.round((r + m) * 255), Math.round((g + m) * 255), Math.round((b + m) * 255)];
}

function luminance([r, g, b]: Rgb): number {
  const lin = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

export function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

export const WHITE: Rgb = [255, 255, 255];
/** Meta text in sent bubbles is white at this opacity (`--text-on-accent-2`, the dimmer of the
 *  two themes). */
export const META_ALPHA = 0.86;
/** Every panel accent text can sit on (`--bg-0..2`, `--surface-1..2` of each theme in
 *  tokens.css); `scripts/contrast-check.mjs` reads tokens.css and fails if one is missing. */
export const DARK_BGS: Rgb[] = [
  [6, 7, 26], [11, 13, 34], [16, 19, 49], [23, 26, 61], [30, 34, 80], // Aurora dark
  [10, 10, 12], [14, 14, 17], [17, 17, 20], [26, 26, 31], [31, 31, 37], // Ink dark
  [5, 5, 6], [12, 12, 15], [19, 19, 23], // pure black
];
export const LIGHT_BGS: Rgb[] = [
  [231, 233, 245], [246, 247, 252], [238, 240, 249], [255, 255, 255], [233, 235, 246], // Aurora light
  [233, 233, 236], [247, 247, 248], [242, 242, 244], [235, 235, 239], // Ink light
];

const hex = ([r, g, b]: Rgb) => `#${[r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("")}`;
const rgba = ([r, g, b]: Rgb, a: number) => `rgb(${r} ${g} ${b} / ${a})`;
export const mix = (a: Rgb, b: Rgb, t: number): Rgb => [0, 1, 2].map((i) => Math.round(a[i]! + (b[i]! - a[i]!) * t)) as Rgb;

/** Meta text as it shows on bubble colour `c`. */
export const meta = (c: Rgb): Rgb => mix(c, WHITE, META_ALPHA);
/** Both text colours on a bubble colour keep 4.5:1. */
export const readable = (c: Rgb): boolean => contrast(WHITE, c) >= 4.5 && contrast(meta(c), c) >= 4.5;

/** The lightest lightness (from `start` down) at which white and meta text on every colour,
 *  and on the colours between neighbours, keep 4.5:1. */
function bubbleLightness(stops: { h: number; s: number }[], start: number): number {
  for (let l = start; l > 0.1; l -= 0.01) {
    const cols = stops.map((p) => hsl(p.h, p.s, l));
    const between = cols.slice(1).flatMap((c, i) => [0.25, 0.5, 0.75].map((t) => mix(cols[i]!, c, t)));
    if ([...cols, ...between].every(readable)) return l;
  }
  return 0.1;
}

/** An accent text colour readable on all of `bgs`: lighter on dark backgrounds, darker on
 *  light ones. */
function readableOn(h: number, s: number, bgs: Rgb[], dark: boolean): Rgb {
  const ok = (c: Rgb) => bgs.every((bg) => contrast(c, bg) >= 4.5);
  if (dark) {
    for (let l = 0.62; l < 0.96; l += 0.01) {
      const c = hsl(h, s, l);
      if (ok(c)) return c;
    }
    return hsl(h, s, 0.96);
  }
  for (let l = 0.45; l > 0.05; l -= 0.01) {
    const c = hsl(h, s, l);
    if (ok(c)) return c;
  }
  return hsl(h, s, 0.05);
}

/** The sent-bubble colours for a hue: what a per-chat colour changes. */
export function bubbleVars(h: number): Record<string, string> {
  const stops = [
    { h, s: 0.72 },
    { h: h + 18, s: 0.62 },
    { h: h - 28, s: 0.66 },
  ];
  const l = bubbleLightness(stops, 0.5);
  const [a, b, c] = stops.map((p) => hsl(p.h, p.s, l)) as [Rgb, Rgb, Rgb];
  const solid = hsl(h, 0.68, Math.min(l, bubbleLightness([{ h, s: 0.68 }], 0.5)));
  return {
    "--sent-a": hex(a),
    "--sent-b": hex(b),
    "--sent-c": hex(c),
    "--sent-solid": hex(solid),
    "--sent-ink": hex(solid),
  };
}

/** Everything a custom app accent sets, for the dark or light theme. */
export function accentVars(h: number, dark: boolean): Record<string, string> {
  const bubbles = bubbleVars(h);
  const accent = readableOn(h, 0.85, dark ? DARK_BGS : LIGHT_BGS, dark);
  const solid = hsl(h, 0.68, bubbleLightness([{ h, s: 0.68 }], 0.5));
  return {
    ...bubbles,
    "--accent": hex(accent),
    "--accent-strong": dark ? hex(solid) : hex(accent),
    "--accent-soft": rgba(dark ? solid : accent, dark ? 0.18 : 0.1),
    "--focus": hex(accent),
    "--glow-accent": `0 8px 28px -6px ${rgba(solid, 0.5)}`,
    "--accent-swatch": `linear-gradient(135deg, ${bubbles["--sent-a"]}, ${bubbles["--sent-b"]} 55%, ${bubbles["--sent-c"]})`,
  };
}

/** The variables `accentVars` may set, so they can all be removed again. */
export const ACCENT_VARS = Object.keys(accentVars(0, true));

/** Hues offered as swatches; any other comes from the slider. */
export const HUES = [0, 25, 45, 140, 170, 195, 215, 245, 270, 295, 320, 340];

/** A swatch's own colour (the solid bubble), for drawing it. */
export function swatch(h: number): string {
  return bubbleVars(h)["--sent-solid"]!;
}
