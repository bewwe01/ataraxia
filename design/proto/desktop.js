/* Desktop shell: rail + resizable conversation list + chat + optional info
 * panel, modals, full keyboard navigation. Collapses gracefully to tablet. */
(function () {
  "use strict";
  var U = window.VeilUI, h = U.html, raw = U.raw, icon = U.icon, D = window.VeilData;
  var App = function () { return window.VeilApp; };

  function rail(active) {
    var items = [["chats", "Chats", "chats", "#chat:ada"], ["contacts", "Contacts", "users", "#contacts"], ["settings", "Settings", "settings", "#settings-privacy"]];
    return h`<nav class="rail glass" aria-label="Main">
      <span class="rail-logo">${U.logo()}<span class="sr-only">Veil</span></span>
      <ul>${items.map(function (it) {
        return h`<li><a class="rail-btn" href="${it[3]}" aria-label="${it[1]}" ${raw(active === it[0] ? 'aria-current="page"' : "")} data-tip="${it[1]}">${icon(it[2], "icon-lg")}${it[0] === "chats" ? h`<span class="badge rail-badge" aria-hidden="true">16</span>` : ""}</a></li>`;
      })}</ul>
      <span class="spacer"></span>
      <span class="rail-status" role="status" aria-label="Connected to relay, IP hidden" data-tip="Connected · relay-only"><span class="pulse-dot"></span>${icon("shield", "icon-sm")}</span>
      <a class="rail-btn" href="#lock" aria-label="Lock Veil now (Ctrl+L)" data-tip="Lock">${icon("lock", "icon-lg")}</a>
      <a class="rail-btn me" href="#add" aria-label="My code" data-tip="My code">${U.avatar("me", "sm")}</a></nav>`;
  }
  function listHead(title, extra) {
    return h`<header class="list-head"><div class="hstack"><h1>${title}</h1><span class="spacer"></span>${extra || ""}</div>
      <div class="input slim"><span class="lead-icon">${icon("search")}</span><label class="sr-only" for="d-q">Search</label><input id="d-q" type="search" placeholder="Search" data-search><span class="kbd">Ctrl K</span></div></header>`;
  }
  var addBtn = h`<a class="icon-btn solid" href="#add" aria-label="Add contact">${icon("user-plus")}</a>`;
  function chatsList(sel, o) {
    o = o || {};
    return h`${o.top || ""}${listHead("Chats", addBtn)}<div class="list-scroll" ${raw(o.busy ? 'aria-busy="true"' : "")}>${o.body || U.convList(sel)}</div>`;
  }
  function settingsList(active) {
    return h`${listHead("Settings")}<div class="list-scroll pad">${U.settingsMeCard()}<h3 class="group-title">Preferences</h3>${U.settingsNav(active)}<p class="hint center app-ver">Veil 0.1.0 · design prototype</p></div>`;
  }
  function settingsMain(title, body) {
    return h`<div class="settings-main"><header class="settings-head"><h2>${title}</h2></header><div class="settings-scroll"><div class="settings-col">${body}</div></div></div>`;
  }
  function emptyMain() {
    return h`<div class="state main-empty"><div class="state-art"><span class="core">${icon("chats", "icon-xl")}</span></div><h2>Select a conversation</h2>
      <p>Or press <span class="kbd">Ctrl</span> <span class="kbd">K</span> to search. Everything here is end-to-end encrypted.</p></div>`;
  }
  function infoPanel(title, back, body) {
    return h`<aside class="pane-info glass-strong" aria-label="${title}"><header class="info-head"><h2>${title}</h2><span class="spacer"></span>${back ? h`<a class="icon-btn" href="${back}" aria-label="Close panel (Esc)">${icon("x")}</a>` : ""}</header><div class="info-scroll">${body}</div></aside>`;
  }
  function modal(title, body, close) {
    return h`<div class="scrim"><div class="dialog glass-strong wide-dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t"><div class="hstack dlg-head"><h2 id="dlg-t">${title}</h2><span class="spacer"></span><a class="icon-btn" href="${close}" aria-label="Close (Esc)">${icon("x")}</a></div>${body}</div></div>`;
  }
  function fullCard(body, cls) { return { full: h`<div class="d-full"><div class="d-card glass-strong ${cls || ""}">${body}</div></div>` }; }

  var R = {
    welcome: function () { return fullCard(U.welcomeContent()); },
    keygen: function () { return fullCard(U.keygenContent()); },
    passphrase: function () { return fullCard(U.passphraseContent()); },
    protection: function () { return fullCard(U.protectionContent(), "wide"); },
    lock: function () { return fullCard(U.lockContent()); },
    chats: function () { return { section: "chats", list: chatsList(""), main: emptyMain() }; },
    chat: function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, "", { info: "#profile:" + p }) }; },
    "chat-empty": function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, "empty", { info: "#profile:" + p }) }; },
    "chat-keychange": function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, "keychange", { info: "#profile:" + p }) }; },
    "chat-offline": function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, "offline", { info: "#profile:" + p }) }; },
    "chats-offline": function () {
      return { section: "chats", list: chatsList("ada", { top: h`<div class="conn-bar reconnecting" role="status">${icon("refresh", "icon-sm spin")}Reconnecting… attempt 3</div>` }), main: U.chatPane("ada", "", { info: "#profile:ada" }) };
    },
    "chats-empty": function () { return { section: "chats", list: chatsList("", { body: h`<p class="hint list-empty">No conversations yet.</p>` }), main: U.chatsEmpty() }; },
    "chats-loading": function () { return { section: "chats", list: chatsList("", { body: U.skeletonList(9), busy: true }), main: U.chatSkeleton() }; },
    contacts: function () { return { section: "contacts", list: h`${listHead("Contacts", addBtn)}<div class="list-scroll">${U.contactsList()}</div>`, main: h`<div class="contact-main"><div class="settings-col">${U.profileContent("ada")}</div></div>` }; },
    profile: function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, "", { info: "#chat:" + p, infoOpen: true }), info: infoPanel("Contact info", "#chat:" + p, U.profileContent(p)) }; },
    safety: function (p) { return { section: "chats", list: chatsList(p), main: U.chatPane(p, p === "lena" ? "keychange" : "", { info: "#chat:" + p, infoOpen: true }), info: infoPanel("Safety number", "#profile:" + p, U.safetyContent(p, true)) }; },
    add: function () { return { section: "chats", list: chatsList("ada"), main: U.chatPane("ada", "", { info: "#profile:ada" }), modal: modal("Add contact", U.addContent(), "#chat:ada") }; },
    scan: function () { return { section: "chats", list: chatsList("ada"), main: U.chatPane("ada", "", { info: "#profile:ada" }), modal: modal("Add contact", U.scanContent(), "#chat:ada") }; },
    verified: function () { return { section: "chats", list: chatsList("ada"), main: U.chatPane("ada", "", { info: "#profile:ada" }), modal: h`<div class="scrim"><div class="dialog glass-strong" role="dialog" aria-modal="true" aria-label="Contact verified">${U.verifiedContent()}</div></div>` }; },
    "call-audio": function (p) { return { section: "chats", list: chatsList(p), main: U.callContent("audio", p) }; },
    "call-video": function (p) { return { section: "chats", list: chatsList(p), main: U.callContent("video", p) }; },
    settings: function () { return R["settings-privacy"](); },
    "settings-privacy": function () { return { section: "settings", list: settingsList("privacy"), main: settingsMain("Privacy", U.settingsPrivacy()) }; },
    "settings-appearance": function () { return { section: "settings", list: settingsList("appearance"), main: settingsMain("Appearance", U.settingsAppearance()) }; },
    "settings-relays": function () { return { section: "settings", list: settingsList("relays"), main: settingsMain("Relay servers", U.settingsRelays()) }; },
    "settings-security": function () { return { section: "settings", list: settingsList("security"), main: settingsMain("Security", U.settingsSecurity()) }; },
    panic: function () { var s = R["settings-security"](); s.modal = U.panicDialog(); return s; },
    error: function () { return { section: "chats", list: chatsList("", { top: h`<div class="conn-bar offline" role="status">${icon("wifi-off", "icon-sm")}Relay unreachable · messages queued</div>` }), main: U.errorContent() }; },
    shortcuts: function () { var s = R.chat("ada"); s.modal = U.shortcutsDialog(); return s; },
  };

  var LIST_W_KEY = "listWidth";
  function listWidth() { var v = Number(App().store.get(LIST_W_KEY)); return v >= 280 && v <= 480 ? v : 340; }

  function renderLayout(v) {
    if (v.full) return String(v.full);
    var w = listWidth();
    return String(h`<div class="d-app ${v.info ? "has-info" : ""}">${rail(v.section)}
      <section class="pane-list" aria-label="${v.section === "settings" ? "Settings sections" : v.section === "contacts" ? "Contacts" : "Conversations"}">${v.list}</section>
      <div class="resizer" role="separator" tabindex="0" aria-orientation="vertical" aria-label="Resize list" aria-valuemin="280" aria-valuemax="480" aria-valuenow="${w}" aria-controls="pane-list"></div>
      <main class="pane-main" id="main">${v.main}</main>${v.info || ""}${v.modal || ""}</div>`);
  }

  function wireResizer(win) {
    var r = win.querySelector(".resizer");
    if (!r) return;
    var set = function (w) {
      w = Math.max(280, Math.min(480, Math.round(w)));
      win.style.setProperty("--list-w", w + "px");
      r.setAttribute("aria-valuenow", String(w));
      App().store.set(LIST_W_KEY, String(w));
    };
    set(listWidth());
    r.addEventListener("pointerdown", function (e) {
      r.setPointerCapture(e.pointerId);
      var startX = e.clientX, startW = Number(r.getAttribute("aria-valuenow"));
      r.classList.add("dragging");
      var move = function (ev) { set(startW + ev.clientX - startX); };
      var up = function () { r.classList.remove("dragging"); r.removeEventListener("pointermove", move); r.removeEventListener("pointerup", up); };
      r.addEventListener("pointermove", move);
      r.addEventListener("pointerup", up);
    });
    r.addEventListener("keydown", function (e) {
      var w = Number(r.getAttribute("aria-valuenow"));
      if (e.key === "ArrowLeft") { set(w - 16); e.preventDefault(); }
      if (e.key === "ArrowRight") { set(w + 16); e.preventDefault(); }
      if (e.key === "Home") { set(280); e.preventDefault(); }
      if (e.key === "End") { set(480); e.preventDefault(); }
    });
  }

  // Roving focus within the conversation list (Up/Down/Home/End).
  function wireListKeys(win) {
    var list = win.querySelector(".pane-list");
    if (!list) return;
    list.addEventListener("keydown", function (e) {
      var items = Array.prototype.slice.call(list.querySelectorAll(".conv, a.row"));
      var i = items.indexOf(document.activeElement);
      if (i < 0) return;
      var n = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: items.length - 1 }[e.key];
      if (n == null) return;
      e.preventDefault();
      items[Math.max(0, Math.min(items.length - 1, n))].focus();
    });
  }

  var current = null;
  document.addEventListener("keydown", function (e) {
    var mod = e.ctrlKey || e.metaKey;
    var t = e.target, typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA");
    var r = current || { id: "chat", param: "ada" };
    var cid = r.param || "ada";
    if (mod && e.key.toLowerCase() === "k") { var s = document.querySelector("[data-search]"); if (s) { e.preventDefault(); s.focus(); } }
    else if (mod && e.key === ",") { e.preventDefault(); location.hash = "#settings-privacy"; }
    else if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); location.hash = "#lock"; }
    else if (mod && e.key.toLowerCase() === "i") { e.preventDefault(); location.hash = r.id === "profile" ? "#chat:" + cid : "#profile:" + cid; }
    else if (e.altKey && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      var order = D.order, idx = order.indexOf(cid);
      var next = order[(idx + (e.key === "ArrowDown" ? 1 : -1) + order.length) % order.length];
      location.hash = "#chat:" + next;
    } else if (e.key === "Escape") {
      var close = document.querySelector(".scrim a[aria-label^='Close'], .scrim a.btn-secondary, .pane-info a[aria-label^='Close']");
      var pp = document.getElementById("proto-panel");
      if (close && (!pp || pp.hidden)) { e.preventDefault(); location.hash = close.getAttribute("href"); }
    } else if (e.key === "?" && !typing) { e.preventDefault(); location.hash = "#shortcuts"; }
  });

  window.VeilShell = {
    defaultRoute: "welcome",
    screens: window.VeilScreens,
    render: function (r) {
      current = r;
      var fn = R[r.id] || R.chats;
      var v = fn(r.param || "ada");
      var win = document.getElementById("app");
      win.innerHTML = renderLayout(v);
      document.title = "Veil · " + ((window.VeilScreens.find(function (s) { return s.route === r.id || s.route === r.id + ":" + r.param; }) || {}).title || "Prototype") + " (desktop)";
      var app = win.querySelector(".d-app");
      if (app) { wireResizer(app); wireListKeys(app); var pl = app.querySelector(".pane-list"); if (pl) pl.id = "pane-list"; }
      if (!App().capture) {
        var dlg = win.querySelector("[role=dialog] a, [role=alertdialog] button");
        if (dlg) dlg.focus();
      }
    },
  };
})();
