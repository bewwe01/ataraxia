// Bans the patterns CLAUDE.md forbids in the webview code. Small on purpose: no plugins, no
// network. Fails on: dangerouslySetInnerHTML, innerHTML/outerHTML, insertAdjacentHTML,
// document.write, eval, new Function, string setTimeout/setInterval, `any`, direct `invoke`
// outside src/ipc.ts, and http(s) URLs (no remote resources).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const RULES = [
  [/dangerouslySetInnerHTML/, "dangerouslySetInnerHTML"],
  [/\.(inner|outer)HTML\b/, "innerHTML/outerHTML"],
  [/insertAdjacentHTML/, "insertAdjacentHTML"],
  [/document\.write/, "document.write"],
  [/\beval\s*\(/, "eval"],
  [/new\s+Function\b/, "new Function"],
  [/set(Timeout|Interval)\s*\(\s*["'`]/, "string setTimeout/setInterval"],
  [/:\s*any\b|<any>|as\s+any\b/, "any"],
  [/https?:\/\//, "remote URL"],
];
const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(ts|tsx)$/.test(f)) files.push(p);
  }
})("src");
let bad = 0;
for (const f of files) {
  const lines = readFileSync(f, "utf8").split("\n");
  lines.forEach((line, i) => {
    for (const [re, what] of RULES) {
      if (re.test(line)) { console.error(`${f}:${i + 1}: banned: ${what}`); bad++; }
    }
    if (!f.endsWith("ipc.ts") && /\binvoke\s*\(|@tauri-apps\/api\/core/.test(line)) {
      console.error(`${f}:${i + 1}: banned: invoke outside src/ipc.ts`); bad++;
    }
  });
}
if (bad) { console.error(`${bad} lint error(s)`); process.exit(1); }
console.log(`lint: ${files.length} files clean`);
