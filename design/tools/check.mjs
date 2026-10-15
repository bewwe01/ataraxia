// Automated design checks for the Veil prototype. Writes design/CHECKS.md.
// Exit code 1 if any hard check fails. Usage: node check.mjs [--quick]
import { chromium } from "playwright";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import vm from "node:vm";

const here = path.dirname(fileURLToPath(import.meta.url));
const design = path.resolve(here, "..");
const quick = process.argv.includes("--quick");
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(path.join(design, "proto/screens.js"), "utf8"), sandbox);
const SCREENS = sandbox.window.VeilScreens;
const axeSource = readFileSync(path.join(here, "node_modules/axe-core/axe.min.js"), "utf8");
const url = (file, route, q = "") => pathToFileURL(path.join(design, file)).href + `?capture=1${q}#${route}`;

const report = [];
const failures = [];
const log = (s) => { report.push(s); };
const fail = (s) => { failures.push(s); };

const browser = await chromium.launch();

// ---------------------------------------------------------------- 1. Contrast
// Resolve tokens in the real page for every theme × mode × accent × bubble.
const pairsFn = () => {
  const probe = document.createElement("div");
  document.body.appendChild(probe);
  const color = (v) => { probe.style.color = ""; probe.style.color = `var(${v})`; return getComputedStyle(probe).color; };
  const bg = (v) => { probe.style.background = ""; probe.style.background = `var(${v})`; const cs = getComputedStyle(probe); return { image: cs.backgroundImage, color: cs.backgroundColor }; };
  const parse = (s) => { const m = s.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const all = (s) => (s.match(/rgba?\([^)]+\)/g) || []).map(parse);
  const over = (fg, bgc) => { const a = fg[3]; return [fg[0] * a + bgc[0] * (1 - a), fg[1] * a + bgc[1] * (1 - a), fg[2] * a + bgc[2] * (1 - a), 1]; };
  const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
  const L = (c) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
  const ratio = (a, b) => { const x = L(a), y = L(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const solid = (v) => parse(color(v));
  const bg1 = solid("--bg-1");
  const layer = (v, base) => over(solid(v), base || bg1);
  // Worst-case backdrop under glass: brightest ambient blob composited on bg-1.
  const ambient = ["--ambient-a", "--ambient-b", "--ambient-c", "--ambient-d"].map((v) => over(solid(v), bg1));
  const surfaces = {
    "bg-1": bg1, "bg-2": layer("--bg-2"), "surface-1": layer("--surface-1"), "surface-2": layer("--surface-2"), "surface-3": layer("--surface-3"),
  };
  const glassUnder = ambient.concat([bg1]);
  const out = [];
  const add = (name, fgVar, bgs, min = 4.5) => {
    for (const [bn, b] of Object.entries(bgs)) {
      const f = over(solid(fgVar), b);
      out.push({ pair: `${name} on ${bn}`, ratio: ratio(f, b), min });
    }
  };
  for (const t of ["--text-1", "--text-2", "--text-3"]) add(t, t, surfaces);
  add("--accent", "--accent", { "bg-1": surfaces["bg-1"], "surface-1": surfaces["surface-1"], "surface-2": surfaces["surface-2"], "accent-soft/surface-1": layer("--accent-soft", surfaces["surface-1"]), "accent-soft/bg-2": layer("--accent-soft", surfaces["bg-2"]) });
  add("--success", "--success", { "surface-1": surfaces["surface-1"], "success-soft/surface-1": layer("--success-soft", surfaces["surface-1"]), "success-soft/bg-1": layer("--success-soft", bg1) });
  add("--warning", "--warning", { "surface-1": surfaces["surface-1"], "warning-soft/surface-1": layer("--warning-soft", surfaces["surface-1"]), "warning-soft/bg-1": layer("--warning-soft", bg1) });
  add("--danger", "--danger", { "surface-1": surfaces["surface-1"], "danger-soft/surface-1": layer("--danger-soft", surfaces["surface-1"]), "danger-soft/bg-1": layer("--danger-soft", bg1) });
  add("--text-1 (banner body)", "--text-1", { "warning-soft/bg-1": layer("--warning-soft", bg1) });
  add("--text-on-warm (unread badge)", "--text-on-warm", { "aurora-warm": solid("--aurora-warm") });
  for (const [i, g] of glassUnder.entries()) {
    const gl = over(solid("--surface-glass"), g);
    for (const t of ["--text-1", "--text-2", "--text-3"]) out.push({ pair: `${t} on surface-glass over backdrop#${i}`, ratio: ratio(over(solid(t), gl), gl), min: 4.5 });
    const gs = over(solid("--surface-glass-strong"), g);
    for (const t of ["--text-1", "--text-2", "--text-3"]) out.push({ pair: `${t} on surface-glass-strong over backdrop#${i}`, ratio: ratio(over(solid(t), gs), gs), min: 4.5 });
  }
  // Gradient-backed text: sample 21 points along every gradient.
  const gradientCheck = (name, fgVars, bgVar) => {
    const b = bg(bgVar);
    let stops = all(b.image);
    if (!stops.length) stops = [parse(b.color)];
    const samples = [];
    if (stops.length === 1) samples.push(stops[0]);
    for (let s = 0; s < stops.length - 1; s++) for (let k = 0; k <= 20; k++) { const t = k / 20; samples.push(stops[s].map((v, i) => (i === 3 ? 1 : v + (stops[s + 1][i] - v) * t))); }
    for (const fv of fgVars) {
      let worst = 99;
      for (const sm of samples) { const base = over(sm, bg1); worst = Math.min(worst, ratio(over(solid(fv), base), base)); }
      out.push({ pair: `${fv} on ${name} (${stops.length > 1 ? stops.length + " stops, " + samples.length + " samples" : "solid"})`, ratio: worst, min: 4.5 });
    }
  };
  gradientCheck("sent bubble", ["--sent-text", "--sent-meta"], "--sent-bg");
  gradientCheck("primary button", ["--btn-primary-fg"], "--btn-primary-bg");
  probe.remove();
  return out;
};

const STYLES = ["aurora", "ink"], MODES = ["dark", "light"], ACCENTS = ["aurora", "lagoon", "ember"], BUBBLES = ["gradient", "soft", "minimal"];
{
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  log("## 1. Text contrast (WCAG AA, 4.5:1 for all text)\n");
  log("Resolved from the live tokens in the browser. Translucent layers are composited over their real backdrop; glass is checked over each ambient-blob colour; gradients are sampled at 21 points per segment.\n");
  log("| Theme | Mode | Accent | Bubble | Pairs | Worst pair | Worst ratio | Result |\n|---|---|---|---|---:|---|---:|---|");
  let total = 0;
  for (const style of STYLES) for (const mode of MODES) for (const accent of ACCENTS) for (const bubble of BUBBLES) {
    await page.goto(url("mobile.html", "chats", `&style=${style}&theme=${mode}&accent=${accent}&bubble=${bubble}`));
    await page.waitForSelector("html[data-ready=true]");
    const res = await page.evaluate(pairsFn);
    total += res.length;
    const bad = res.filter((r) => r.ratio < r.min);
    const worst = res.reduce((a, b) => (b.ratio < a.ratio ? b : a));
    log(`| ${style} | ${mode} | ${accent} | ${bubble} | ${res.length} | ${worst.pair} | ${worst.ratio.toFixed(2)} | ${bad.length ? "**FAIL**" : "pass"} |`);
    for (const b of bad) fail(`contrast ${style}/${mode}/${accent}/${bubble}: ${b.pair} = ${b.ratio.toFixed(2)}`);
  }
  log(`\n${total} pair checks in total.\n`);
  await ctx.close();
}

// -------------------------------------- 2-5. Per-screen checks (axe, targets, network, CSP)
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const layouts = [
  { key: "mobile", file: "mobile.html", viewport: { width: 390, height: 844 }, filter: (s) => !s.desktopOnly },
  { key: "desktop", file: "desktop.html", viewport: { width: 1440, height: 900 }, filter: () => true },
];
const axeRows = [], targetIssues = new Map(), netIssues = [], consoleIssues = [];
let screensChecked = 0;
for (const L of layouts) for (const style of STYLES) for (const mode of (quick ? ["dark"] : MODES)) {
  // CSP stays ON for the network/console pass; a separate CSP-bypassing page injects axe.
  const ctxCsp = await browser.newContext({ viewport: L.viewport });
  const pCsp = await ctxCsp.newPage();
  pCsp.on("request", (r) => { const u = r.url(); if (!u.startsWith("file:") && !u.startsWith("data:")) netIssues.push(`${L.key}: ${u}`); });
  pCsp.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") consoleIssues.push(`${L.key}/${style}/${mode}: ${m.text()}`); });
  const ctxAxe = await browser.newContext({ viewport: L.viewport, bypassCSP: true });
  const pAxe = await ctxAxe.newPage();
  for (const s of SCREENS.filter(L.filter)) {
    const q = `&style=${style}&theme=${mode}`;
    await pCsp.goto("about:blank");
    await pCsp.goto(url(L.file, s.route, q));
    await pCsp.waitForSelector("html[data-ready=true]");
    await pAxe.goto("about:blank");
    await pAxe.goto(url(L.file, s.route, q));
    await pAxe.waitForSelector("html[data-ready=true]");
    await pAxe.waitForTimeout(150);
    await pAxe.addScriptTag({ content: axeSource });
    const axe = await pAxe.evaluate(async (tags) => {
      // Let entry animations settle so axe sees final colours.
      document.getAnimations().forEach((a) => { try { a.finish(); } catch (e) { /* infinite */ } });
      const r = await window.axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations"] });
      return r.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, sample: v.nodes[0] && v.nodes[0].target.join(" ") }));
    }, AXE_TAGS);
    for (const v of axe) axeRows.push({ layout: L.key, style, mode, route: s.route, ...v });
    if (style === "aurora" && mode === "dark") {
      const small = await pAxe.evaluate(() => {
        const out = [];
        const sel = "a[href], button, input:not([type=hidden]), textarea, select, [role=switch], [role=separator][tabindex], [tabindex]:not([tabindex='-1'])";
        document.querySelectorAll(sel).forEach((el) => {
          if (el.closest("[aria-hidden=true], .sr-only, .proto-panel, .proto-fab")) return;
          // Visually-hidden native inputs are targeted through their visible wrapper.
          const target = el.matches("input[type=radio], input[type=checkbox], input[type=range]") ? (el.closest(".switch, .segmented label, .swatch, .radio-card, .theme-card, .range") || el) : el;
          const r = target.getBoundingClientRect();
          if (r.width === 0 || r.height === 0) return;
          const cs = getComputedStyle(target);
          if (cs.visibility === "hidden" || cs.display === "none") return;
          // Count an invisible ::after hit-area extension (used by .reaction).
          const after = getComputedStyle(target, "::after");
          const ext = after.content !== "none" && after.position === "absolute";
          const hitH = ext ? Math.max(r.height, parseFloat(after.height) || 0) : r.height;
          const hitW = ext ? Math.max(r.width, parseFloat(after.width) || 0) : r.width;
          if (Math.round(hitW) < 44 || Math.round(hitH) < 44) out.push(`${target.tagName.toLowerCase()}.${String(target.className).split(" ")[0] || ""} "${(target.getAttribute("aria-label") || target.textContent || target.getAttribute("placeholder") || "").trim().slice(0, 30)}" ${Math.round(hitW)}×${Math.round(hitH)}`);
        });
        return out;
      });
      for (const t of small) { const k = `${L.key}: ${t}`; targetIssues.set(k, (targetIssues.get(k) || []).concat(s.route)); }
    }
    screensChecked++;
  }
  await ctxCsp.close();
  await ctxAxe.close();
}
{
  log("## 2. Accessibility (axe-core 4.10.3, WCAG 2.0/2.1/2.2 A+AA rules)\n");
  log(`${screensChecked} screen renders checked (mobile + desktop × ${STYLES.length} themes × ${quick ? 1 : 2} modes).\n`);
  const byRule = {};
  for (const r of axeRows) { const k = `${r.id} (${r.impact})`; (byRule[k] = byRule[k] || { help: r.help, where: new Set(), nodes: 0, sample: r.sample }); byRule[k].where.add(`${r.layout}/${r.style}/${r.mode}:${r.route}`); byRule[k].nodes += r.nodes; }
  if (!axeRows.length) log("**0 violations.**\n");
  else {
    log("| Rule | Help | Renders | Nodes | Example |\n|---|---|---:|---:|---|");
    for (const [k, v] of Object.entries(byRule)) log(`| ${k} | ${v.help} | ${v.where.size} | ${v.nodes} | \`${v.sample}\` |`);
    log("");
  }
  for (const r of axeRows) if (r.impact === "serious" || r.impact === "critical") fail(`axe ${r.id} (${r.impact}) ${r.layout}/${r.style}/${r.mode}:${r.route} ${r.sample}`);

  log("## 3. Touch / click targets (≥ 44×44 px)\n");
  if (!targetIssues.size) log("**All interactive elements are at least 44×44 px** (visible box, or an invisible hit-area extension where noted in DESIGN.md).\n");
  else { log("| Element | Screens |\n|---|---|"); for (const [k, v] of targetIssues) log(`| ${k} | ${[...new Set(v)].slice(0, 4).join(", ")}${v.length > 4 ? "…" : ""} |`); log(""); }

  log("## 4. Privacy: network requests & CSP\n");
  log(`Every screen loaded with CSP \`default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'\`.\n`);
  log(`- Requests to any origin other than local files: **${netIssues.length}**`);
  log(`- Console errors / warnings / CSP violations: **${consoleIssues.length}**\n`);
  for (const n of netIssues) fail("network: " + n);
  for (const c of consoleIssues) fail("console: " + c);
}

// -------------------------------------------------- 6. Motion audit
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(url("desktop.html", "chat:ada"));
  await page.waitForSelector("html[data-ready=true]");
  // Static audit of every stylesheet (file:// sheets are opaque to CSSOM).
  const audit = (() => {
    const files = ["tokens.css", "proto/base.css", "proto/content.css", "proto/mobile.css", "proto/desktop.css"];
    const allowed = new Set(["transform", "opacity", "offset", "animation-timing-function"]);
    const bad = [], frames = [], trans = new Set();
    for (const f of files) {
      const css = readFileSync(path.join(design, f), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
      const re = /@keyframes\s+([\w-]+)\s*\{/g;
      let m;
      while ((m = re.exec(css))) {
        let depth = 1, i = re.lastIndex;
        while (depth && i < css.length) { if (css[i] === "{") depth++; else if (css[i] === "}") depth--; i++; }
        const body = css.slice(re.lastIndex, i - 1);
        frames.push(m[1]);
        for (const d of body.matchAll(/([a-z-]+)\s*:/g)) if (!allowed.has(d[1])) bad.push(`@keyframes ${m[1]} animates "${d[1]}" (${f})`);
      }
      for (const t of css.matchAll(/(?:^|[;{\s])transition(?:-property)?\s*:\s*([^;}]+)/g)) {
        for (const part of t[1].split(",")) {
          const prop = part.trim().split(/\s+/)[0];
          trans.add(prop);
          if (!["transform", "opacity", "none"].includes(prop)) bad.push(`transition on "${prop}" (${f})`);
        }
      }
    }
    return { bad, frames: [...new Set(frames)], trans: [...trans] };
  })();
  log("## 5. Motion\n");
  log(`- Keyframes found: ${audit.frames.length} (${audit.frames.join(", ")}).`);
  log(`- Transition properties found: ${audit.trans.filter(Boolean).join(", ")}.`);
  log(`- Rules animating anything other than \`transform\`/\`opacity\`: **${audit.bad.length}**${audit.bad.length ? "\n  - " + audit.bad.join("\n  - ") : ""}`);
  for (const b of audit.bad) fail("motion: " + b);

  // Hidden tab pauses ambient + looping motion
  const paused = await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    document.dispatchEvent(new Event("visibilitychange"));
    const blob = document.querySelector(".ambient .blob");
    return { cls: document.documentElement.classList.contains("tab-hidden"), state: getComputedStyle(blob).animationPlayState };
  });
  log(`- Tab hidden → \`tab-hidden\` class: ${paused.cls}; ambient animation-play-state: \`${paused.state}\`.`);
  if (!paused.cls || paused.state !== "paused") fail("ambient motion not paused when tab hidden");
  await ctx.close();

  for (const how of ["system", "setting"]) {
    const c2 = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: how === "system" ? "reduce" : "no-preference" });
    const p2 = await c2.newPage();
    const routes = ["welcome", "keygen", "chat:ada", "chats-loading", "call-audio:ada", "scan", "verified", "chats-offline"];
    let running = [];
    for (const r of routes) {
      await p2.goto(url("mobile.html", r, how === "setting" ? "&motion=reduced" : ""));
      await p2.waitForSelector("html[data-ready=true]");
      await p2.waitForTimeout(200);
      const left = await p2.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").map((a) => `${a.animationName || a.constructor.name}`));
      running = running.concat(left.map((n) => `${r}:${n}`));
    }
    log(`- Reduced motion via ${how === "system" ? "OS preference (prefers-reduced-motion)" : "in-app setting"}: animations still running 200 ms after load across ${routes.length} motion-heavy screens: **${running.length}**${running.length ? " (" + running.join(", ") + ")" : ""}.`);
    for (const r of running) fail(`reduced motion (${how}): still running ${r}`);
    await c2.close();
  }
  log("");
}

// -------------------------------------------------- 7. Keyboard (desktop)
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(url("desktop.html", "chat:ada").replace("?capture=1", "?"));
  await page.waitForSelector("html[data-ready=true]");
  const steps = [];
  await page.keyboard.press("Control+k");
  steps.push(["Ctrl+K focuses search", await page.evaluate(() => document.activeElement && document.activeElement.matches("[data-search]"))]);
  await page.locator(".conv").first().focus();
  await page.keyboard.press("ArrowDown");
  steps.push(["ArrowDown moves focus in conversation list", await page.evaluate(() => document.activeElement.getAttribute("data-conv") === "mira")]);
  await page.locator("body").click({ position: { x: 900, y: 450 } });
  await page.keyboard.press("Alt+ArrowDown");
  await page.waitForTimeout(400);
  steps.push(["Alt+↓ opens next conversation", await page.evaluate(() => location.hash === "#chat:mira")]);
  await page.keyboard.press("Control+i");
  await page.waitForTimeout(400);
  steps.push(["Ctrl+I opens info panel", await page.evaluate(() => !!document.querySelector(".pane-info"))]);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  steps.push(["Esc closes info panel", await page.evaluate(() => !document.querySelector(".pane-info"))]);
  await page.locator(".resizer").focus();
  await page.keyboard.press("ArrowRight");
  steps.push(["Resizer: ArrowRight widens list by 16px", await page.evaluate(() => document.querySelector(".resizer").getAttribute("aria-valuenow") === "356")]);
  await page.keyboard.press("Shift+?");
  await page.waitForTimeout(400);
  steps.push(["? opens shortcuts dialog", await page.evaluate(() => !!document.querySelector("[role=dialog]"))]);
  log("## 6. Keyboard navigation (desktop)\n");
  log("| Interaction | Result |\n|---|---|");
  for (const [k, v] of steps) { log(`| ${k} | ${v ? "pass" : "**FAIL**"} |`); if (!v) fail("keyboard: " + k); }
  log("");
  await ctx.close();
}

await browser.close();

const header = `# Design checks: automated evidence\n\nGenerated by \`design/tools/check.mjs\` on ${new Date().toISOString().slice(0, 10)}. Re-run with \`cd design/tools && pnpm install && node check.mjs\`.\n\n**Result: ${failures.length ? `FAIL (${failures.length} hard failures)` : "PASS"}**\n\n`;
const tail = failures.length ? `\n## Hard failures\n\n${failures.map((f) => "- " + f).join("\n")}\n` : "";
writeFileSync(path.join(design, "CHECKS.md"), header + report.join("\n") + "\n" + tail);
console.log(failures.length ? `FAIL: ${failures.length}\n` + failures.slice(0, 60).join("\n") : "PASS");
process.exit(failures.length ? 1 : 0);
