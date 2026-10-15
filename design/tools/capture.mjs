// Capture Veil prototype screenshots across theme × mode × layout.
// Usage: node capture.mjs [--style=aurora|ink] [--layout=mobile|tablet|desktop] [--mode=dark|light] [--route=chat:ada]
// Fails (exit 1) on any console error, CSP violation, or non-file:// request.
import { chromium } from "playwright";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const here = path.dirname(fileURLToPath(import.meta.url));
const design = path.resolve(here, "..");
const outRoot = path.join(design, "screenshots");
const arg = (k) => (process.argv.find((a) => a.startsWith(`--${k}=`)) || "").split("=")[1];

// Load the canonical screen list from the prototype itself.
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(path.join(design, "proto/screens.js"), "utf8"), sandbox);
const SCREENS = sandbox.window.VeilScreens;

const LAYOUTS = {
  mobile: { file: "mobile.html", viewport: { width: 390, height: 844 }, filter: (s) => !s.desktopOnly },
  tablet: { file: "desktop.html", viewport: { width: 768, height: 1024 }, filter: (s) => s.tablet },
  desktop: { file: "desktop.html", viewport: { width: 1440, height: 900 }, filter: () => true },
};
const STYLES = arg("style") ? [arg("style")] : ["aurora", "ink"];
const MODES = arg("mode") ? [arg("mode")] : ["dark", "light"];
const LAYOUT_KEYS = arg("layout") ? [arg("layout")] : Object.keys(LAYOUTS);
const onlyRoute = arg("route");

const slug = (r) => r.replace(/[^a-z0-9]+/gi, "-");
const problems = [];
const manifest = [];
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });

if (!arg("route") && !arg("style") && !arg("layout") && !arg("mode")) rmSync(outRoot, { recursive: true, force: true });

for (const layoutKey of LAYOUT_KEYS) {
  const L = LAYOUTS[layoutKey];
  for (const style of STYLES) {
    for (const mode of MODES) {
      const ctx = await browser.newContext({ viewport: L.viewport, deviceScaleFactor: 1, colorScheme: mode, reducedMotion: "no-preference" });
      const page = await ctx.newPage();
      page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") problems.push(`[${layoutKey}/${style}/${mode}] console ${m.type()}: ${m.text()}`); });
      page.on("pageerror", (e) => problems.push(`[${layoutKey}/${style}/${mode}] pageerror: ${e.message}`));
      page.on("request", (r) => { const u = r.url(); if (!u.startsWith("file:") && !u.startsWith("data:")) problems.push(`[${layoutKey}] NETWORK REQUEST: ${u}`); });
      const all = SCREENS.filter(L.filter);
      const screens = all.filter((s) => !onlyRoute || s.route === onlyRoute);
      const dir = path.join(outRoot, style, layoutKey, mode);
      mkdirSync(dir, { recursive: true });
      for (const s of screens) {
        const n = all.indexOf(s) + 1;
        const url = pathToFileURL(path.join(design, L.file)).href + `?capture=1&style=${style}&theme=${mode}#${s.route}`;
        await page.goto("about:blank");
        await page.goto(url);
        await page.waitForSelector("html[data-ready=true]");
        await page.waitForTimeout(120);
        const file = path.join(dir, `${String(n).padStart(2, "0")}-${slug(s.route)}.png`);
        await page.screenshot({ path: file, animations: "disabled" });
        manifest.push({ style, layout: layoutKey, mode, route: s.route, title: s.title, file: path.relative(design, file) });
      }
      await ctx.close();
      console.log(`captured ${layoutKey}/${style}/${mode}: ${screens.length}`);
    }
  }
}

// Moodboards (direction exploration)
if (!onlyRoute && !arg("style") && !arg("layout") && !arg("mode")) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  page.on("request", (r) => { const u = r.url(); if (!u.startsWith("file:") && !u.startsWith("data:")) problems.push(`[moodboard] NETWORK REQUEST: ${u}`); });
  page.on("console", (m) => { if (m.type() === "error") problems.push(`[moodboard] console: ${m.text()}`); });
  mkdirSync(path.join(outRoot, "moodboards"), { recursive: true });
  for (const f of ["a-aurora-glass", "b-ink-signal"]) {
    await page.goto(pathToFileURL(path.join(design, "moodboards", f + ".html")).href);
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: path.join(outRoot, "moodboards", f + ".png"), animations: "disabled" });
  }
  await ctx.close();
  writeFileSync(path.join(outRoot, "manifest.json"), JSON.stringify(manifest, null, 1) + "\n");
}

await browser.close();
if (problems.length) {
  console.error("PROBLEMS:\n" + [...new Set(problems)].join("\n"));
  process.exit(1);
}
console.log(`OK: ${manifest.length} screenshots, 0 console errors, 0 CSP violations, 0 network requests`);
