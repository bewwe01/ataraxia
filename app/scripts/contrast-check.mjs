// Checks the colours `src/color.ts` makes from a hue, for every hue 0–359 in both themes
// (milestone 4.5, ADR-0019): white and meta text on every sent-bubble colour and between the
// gradient stops, and the accent on every panel it sits on, all at least 4.5:1. Run by `pnpm lint`.
import { readFileSync } from "node:fs";
import { accentVars, bubbleVars, contrast, DARK_BGS, LIGHT_BGS, meta, mix, WHITE } from "../src/color.ts";

const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));

// Every panel in tokens.css that accent text can sit on must be in color.ts's list for its own
// theme, and must be written as hex so this can tell (reviews LK2-1, LK3-2).
const css = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
const hexRgb = (v) => {
  const m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!m) return null;
  const h = m[1].length === 3 ? [...m[1]].map((c) => c + c).join("") : m[1];
  return rgb(`#${h}`);
};
const has = (list, c) => list.some((x) => x.join(",") === c.join(","));
const uncovered = [];
let panels = 0;
for (const [, sel, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
  const dark = !/data-theme="light"/.test(sel);
  for (const [, tok, val] of body.matchAll(/--(bg-\d+|surface-[12]):\s*([^;]+);/g)) {
    panels += 1;
    const c = hexRgb(val.trim());
    if (!c || !has(dark ? DARK_BGS : LIGHT_BGS, c)) uncovered.push(`${sel.trim()} --${tok}: ${val.trim()}`);
  }
}
if (!panels || uncovered.length) {
  console.error(`contrast: panels not covered by color.ts:\n${uncovered.join("\n") || "(none found: tokens.css not parsed)"}`);
  process.exit(1);
}

const worst = { white: 99, meta: 99, accentDark: 99, accentLight: 99 };
const bubble = (c) => {
  worst.white = Math.min(worst.white, contrast(WHITE, c));
  worst.meta = Math.min(worst.meta, contrast(meta(c), c));
};
for (let h = 0; h < 360; h++) {
  const b = bubbleVars(h);
  const stops = ["--sent-a", "--sent-b", "--sent-c"].map((k) => rgb(b[k]));
  stops.forEach(bubble);
  bubble(rgb(b["--sent-solid"]));
  for (let i = 1; i < stops.length; i++) for (const t of [0.25, 0.5, 0.75]) bubble(mix(stops[i - 1], stops[i], t));
  for (const dark of [true, false]) {
    const accent = rgb(accentVars(h, dark)["--accent"]);
    for (const bg of dark ? DARK_BGS : LIGHT_BGS) {
      const k = dark ? "accentDark" : "accentLight";
      worst[k] = Math.min(worst[k], contrast(accent, bg));
    }
  }
}
const fails = Object.entries(worst).filter(([, v]) => v < 4.5);
console.log(`contrast: ${panels} panels; worst ${Object.entries(worst).map(([k, v]) => `${k} ${v.toFixed(4)}`).join(", ")}`);
if (fails.length) {
  console.error(`contrast: below 4.5:1: ${fails.map(([k]) => k).join(", ")}`);
  process.exit(1);
}
