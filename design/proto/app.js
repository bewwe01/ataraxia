/* Veil prototype runtime: prefs, routing, motion, interactions.
 * Shell scripts (mobile.js / desktop.js) register window.VeilShell.render(route). */
(function () {
  "use strict";
  var root = document.documentElement;
  var params = new URLSearchParams(location.search);
  var capture = params.has("capture");
  if (capture) root.classList.add("capture");

  // Per-viewer convenience only; prototype works fully without storage.
  var store = {
    get: function (k) { if (capture) return null; try { return localStorage.getItem("veil-proto:" + k); } catch (e) { return null; } },
    set: function (k, v) { if (capture) return; try { localStorage.setItem("veil-proto:" + k, v); } catch (e) { /* ignore */ } },
  };
  var prefs = {
    style: params.get("style") || store.get("style") || "aurora",
    themePref: params.get("theme") || store.get("theme") || "dark",
    accent: params.get("accent") || store.get("accent") || "aurora",
    bubble: params.get("bubble") || store.get("bubble") || "gradient",
    textSize: params.get("text") || store.get("textSize") || "md",
    motion: params.get("motion") || store.get("motion") || "full",
  };
  var mqLight = window.matchMedia("(prefers-color-scheme: light)");
  var mqReduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  function apply() {
    root.dataset.style = prefs.style;
    root.dataset.theme = prefs.themePref === "system" ? (mqLight.matches ? "light" : "dark") : prefs.themePref;
    root.dataset.accent = prefs.accent;
    root.dataset.bubble = prefs.bubble;
    root.dataset.textSize = prefs.textSize;
    root.dataset.motion = prefs.motion;
  }
  apply();
  mqLight.addEventListener("change", apply);
  function reduced() { return prefs.motion === "reduced" || mqReduce.matches; }

  // Pause all ambient/looping motion while the tab/window is hidden.
  function onVis() { root.classList.toggle("tab-hidden", document.hidden); }
  document.addEventListener("visibilitychange", onVis);
  onVis();

  // ------------------------------------------------------------ routing
  function parse(hash) {
    var h = (hash || "").replace(/^#/, "");
    var parts = h.split(":");
    return { id: parts[0] || "", param: parts[1] || "" };
  }
  var lastClicked = null;
  document.addEventListener("click", function (e) { lastClicked = e.target.closest("a,button"); }, true);

  function render(animate) {
    var shell = window.VeilShell;
    if (!shell) return;
    var r = parse(location.hash);
    if (!r.id) r = parse(shell.defaultRoute);
    var heroOld = lastClicked && lastClicked.querySelector && lastClicked.querySelector("[data-vt]");
    var doRender = function () {
      shell.render(r);
      if (heroOld) {
        var target = document.querySelector(".profile-hero [data-vt], .call-id [data-vt], .chat-hdr [data-vt]");
        if (target) target.style.viewTransitionName = "hero-avatar";
      }
      hydrate(document);
    };
    if (animate && document.startViewTransition && !reduced() && !capture) {
      if (heroOld) heroOld.style.viewTransitionName = "hero-avatar";
      document.startViewTransition(doRender);
    } else {
      doRender();
    }
    lastClicked = null;
  }
  window.addEventListener("hashchange", function () { render(true); });

  // ------------------------------------------------------------ hydrate
  function hydrate(scope) {
    scope.querySelectorAll("[data-p]").forEach(function (el) { el.style.setProperty("--p", el.getAttribute("data-p")); });
    scope.querySelectorAll("[data-a]").forEach(function (el) { el.style.setProperty("--a", el.getAttribute("data-a") + "deg"); el.style.animationDelay = (Number(el.getAttribute("data-a")) / 360) * 1.6 + "s"; });
    var off = 0; // continuous stagger index across consecutive lists
    scope.querySelectorAll(".stagger").forEach(function (ul) {
      Array.prototype.forEach.call(ul.children, function (li) { li.style.setProperty("--i", String(off++)); });
    });
    scope.querySelectorAll(".scanner").forEach(function (s) {
      requestAnimationFrame(function () { s.style.setProperty("--scan-h", Math.round(s.clientHeight * 0.62) + "px"); });
    });
    var toBottom = function () { scope.querySelectorAll(".msgs").forEach(function (m) { m.scrollTo({ top: m.scrollHeight, behavior: "instant" }); }); };
    toBottom();
    requestAnimationFrame(toBottom);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(toBottom);
    scope.querySelectorAll("[data-composer]").forEach(wireComposer);
    scope.querySelectorAll("[data-keygen]").forEach(runKeygen);
    scope.querySelectorAll("[data-pp]").forEach(wirePassphrase);
    scope.querySelectorAll("[data-reveal]").forEach(wireReveal);
    scope.querySelectorAll("[data-setting]").forEach(wireSetting);
    scope.querySelectorAll("[data-hold]").forEach(wireHold);
    scope.querySelectorAll("form").forEach(function (f) { if (!f.hasAttribute("data-composer")) f.addEventListener("submit", function (e) { e.preventDefault(); }); });
    var focusTarget = scope.querySelector("[data-autofocus]");
    if (focusTarget && !capture) focusTarget.focus();
  }

  function nowTime() { var d = new Date(); return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0"); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function metaEl(time, out) {
    var m = el("span", "meta");
    m.appendChild(el("time", null, time));
    if (out) { m.insertAdjacentHTML("beforeend", String(window.VeilUI.icon("check"))); m.appendChild(el("span", "sr-only", "Sent")); }
    return m;
  }
  function wireComposer(form) {
    var ta = form.querySelector("textarea");
    var log = form.parentElement.querySelector(".msgs");
    if (!ta || !log) return;
    ta.addEventListener("input", function () { form.classList.toggle("has-text", ta.value.trim().length > 0); });
    ta.addEventListener("keydown", function (e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var text = ta.value.trim();
      if (!text) return;
      var typing = log.querySelector(".typing-bubble");
      var m = el("div", "msg out enter-out");
      var b = el("div", "bubble");
      b.appendChild(document.createTextNode(text)); // plain text, never HTML
      b.appendChild(metaEl(nowTime(), true));
      m.appendChild(b);
      log.insertBefore(m, typing || null);
      ta.value = "";
      form.classList.remove("has-text");
      log.scrollTop = log.scrollHeight;
      setTimeout(function () {
        var r = el("div", "msg in enter-in");
        var rb = el("div", "bubble");
        rb.appendChild(document.createTextNode("Got it 👍"));
        rb.appendChild(metaEl(nowTime(), false));
        r.appendChild(rb);
        log.insertBefore(r, log.querySelector(".typing-bubble") || null);
        log.scrollTop = log.scrollHeight;
      }, reduced() ? 300 : 1400);
    });
  }
  function runKeygen(wrap) {
    var steps = wrap.querySelectorAll(".step");
    var next = wrap.querySelector("[data-kg-next]");
    var title = wrap.querySelector("[data-kg-title]");
    var fp = wrap.querySelector("[data-kg-fp]");
    var finalFp = fp.textContent;
    var finish = function () {
      steps.forEach(function (s) { s.classList.remove("active"); s.classList.add("done"); });
      wrap.classList.add("done");
      title.textContent = "Your identity is ready";
      fp.innerHTML = "";
      var f = window.VeilData.me.fingerprint;
      fp.appendChild(document.createTextNode(f.slice(0, 4).join(" ")));
      fp.appendChild(document.createElement("br"));
      fp.appendChild(document.createTextNode(f.slice(4).join(" ")));
      next.removeAttribute("aria-disabled");
    };
    if (capture || reduced()) { finish(); return; }
    var hex = "0123456789ABCDEF", t0 = performance.now(), dur = 2600;
    (function tick(t) {
      if (!document.body.contains(wrap)) return;
      var k = Math.min(1, (t - t0) / dur);
      steps.forEach(function (s, i) { var a = k * 3; s.classList.toggle("done", a > i + 1); s.classList.toggle("active", a > i && a <= i + 1); });
      if (k < 1) {
        var s = "";
        for (var i = 0; i < finalFp.length; i++) { var ch = finalFp[i]; s += /[0-9A-F]/.test(ch) && Math.random() > k ? hex[(Math.random() * 16) | 0] : ch; }
        fp.textContent = s;
        requestAnimationFrame(tick);
      } else finish();
    })(t0);
  }
  function wirePassphrase(input) {
    var form = input.closest("form");
    var meter = form.querySelector(".meter");
    var label = form.querySelector("[data-pp-label]");
    var hint = form.querySelector("#pp-h");
    input.addEventListener("input", function () {
      var words = input.value.trim().split(/\s+/).filter(Boolean).length;
      var len = input.value.length;
      var level = len === 0 ? 0 : words >= 4 || len >= 20 ? 4 : words >= 3 || len >= 14 ? 3 : len >= 8 ? 2 : 1;
      meter.dataset.level = String(level);
      label.lastChild.textContent = ["", "Too weak", "Weak", "Good", "Strong"][level];
      hint.textContent = words + (words === 1 ? " word" : " words") + " · " + len + " characters";
    });
  }
  function wireReveal(btn) {
    var input = btn.parentElement.querySelector("input");
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", String(show));
      btn.setAttribute("aria-label", show ? "Hide passphrase" : "Show passphrase");
    });
  }
  var SIZES = ["sm", "md", "lg", "xl"], SIZE_NAMES = ["Small", "Default", "Large", "Extra large"];
  function wireSetting(input) {
    var key = input.getAttribute("data-setting");
    input.addEventListener("change", function () {
      if (key === "style") { prefs.style = input.value; store.set("style", input.value); }
      else if (key === "theme") { prefs.themePref = input.value; store.set("theme", input.value); }
      else if (key === "accent") { prefs.accent = input.value; store.set("accent", input.value); }
      else if (key === "bubble") { prefs.bubble = input.value; store.set("bubble", input.value); }
      else if (key === "textSize") { prefs.textSize = SIZES[input.value]; input.setAttribute("aria-valuetext", SIZE_NAMES[input.value]); store.set("textSize", prefs.textSize); }
      else if (key === "reduce-motion") { prefs.motion = input.checked ? "reduced" : "full"; store.set("motion", prefs.motion); }
      else if (key === "pair-tab") { location.hash = input.value === "scan" ? "#scan" : "#add"; return; }
      else return;
      apply();
    });
    if (key === "textSize") input.addEventListener("input", function () { input.dispatchEvent(new Event("change")); });
  }
  function wireHold(btn) {
    var timer = null;
    function start(e) { if (e.type === "keydown" && e.key !== " " && e.key !== "Enter") return; if (timer) return; e.preventDefault(); btn.classList.add("holding"); timer = setTimeout(function () { location.hash = "#welcome"; }, reduced() ? 1200 : 2000); }
    function stop() { btn.classList.remove("holding"); clearTimeout(timer); timer = null; }
    btn.addEventListener("pointerdown", start);
    btn.addEventListener("keydown", start);
    ["pointerup", "pointerleave", "pointercancel", "keyup", "blur"].forEach(function (ev) { btn.addEventListener(ev, stop); });
  }

  // ----------------------------------------------- prototype screen index
  function buildIndex(screens) {
    if (capture) return;
    var U = window.VeilUI, h = U.html;
    var fab = document.createElement("button");
    fab.className = "proto-fab";
    fab.type = "button";
    fab.setAttribute("aria-expanded", "false");
    fab.setAttribute("aria-controls", "proto-panel");
    fab.innerHTML = String(h`${U.icon("grip")}Screens <span class="kbd">\\</span>`);
    var panel = document.createElement("nav");
    panel.id = "proto-panel";
    panel.className = "proto-panel glass-strong";
    panel.hidden = true;
    panel.setAttribute("aria-label", "Prototype screens");
    var groups = {};
    screens.forEach(function (s) { (groups[s.group] = groups[s.group] || []).push(s); });
    panel.innerHTML = String(h`<h2>Theme</h2><div class="seg-row">${[["aurora", "Aurora Glass"], ["ink", "Ink & Signal"]].map(function (t) { return h`<button type="button" data-pt="style" data-v="${t[0]}">${t[1]}</button>`; })}</div>
      <h2>Mode</h2><div class="seg-row">${["dark", "light"].map(function (t) { return h`<button type="button" data-pt="theme" data-v="${t}">${t}</button>`; })}</div>
      <h2>Accent</h2><div class="seg-row">${["aurora", "lagoon", "ember"].map(function (t) { return h`<button type="button" data-pt="accent" data-v="${t}">${t}</button>`; })}</div>
      ${Object.keys(groups).map(function (g) { return h`<h2>${g}</h2>${groups[g].map(function (s) { return h`<a href="#${s.route}">${s.title}</a>`; })}`; })}`);
    document.body.appendChild(fab);
    document.body.appendChild(panel);
    function sync() {
      panel.querySelectorAll("[data-pt]").forEach(function (b) { b.setAttribute("aria-pressed", String(({ theme: prefs.themePref, style: prefs.style, accent: prefs.accent })[b.dataset.pt] === b.dataset.v)); });
      panel.querySelectorAll("a").forEach(function (a) { a.setAttribute("aria-current", String(a.getAttribute("href") === (location.hash || "#" + window.VeilShell.defaultRoute))); });
    }
    function toggle(open) { panel.hidden = !open; fab.setAttribute("aria-expanded", String(open)); sync(); }
    fab.addEventListener("click", function () { toggle(panel.hidden); });
    panel.addEventListener("click", function (e) {
      var b = e.target.closest("[data-pt]");
      if (b) {
        var k = b.dataset.pt, v = b.dataset.v;
        if (k === "theme") prefs.themePref = v; else if (k === "style") prefs.style = v; else prefs.accent = v;
        store.set(k, v); apply(); sync();
        if (location.hash === "#settings-appearance") render(false); // keep the picker in sync
      }
    });
    window.addEventListener("hashchange", sync);
    document.addEventListener("keydown", function (e) {
      var t = e.target;
      if (e.key === "\\" && !(t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA"))) { e.preventDefault(); toggle(panel.hidden); if (!panel.hidden) { var a = panel.querySelector("a"); if (a) a.focus(); } }
      if (e.key === "Escape" && !panel.hidden) { toggle(false); fab.focus(); }
    });
  }

  window.VeilApp = { prefs: prefs, apply: apply, render: render, hydrate: hydrate, reduced: reduced, capture: capture, buildIndex: buildIndex, store: store, parse: parse };

  function boot() {
    window.VeilIcons.inject();
    render(false);
    if (window.VeilShell && window.VeilShell.screens) buildIndex(window.VeilShell.screens);
    var fontsReady = document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve();
    fontsReady.then(function () { requestAnimationFrame(function () { root.setAttribute("data-ready", "true"); }); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
