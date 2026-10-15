/* Mobile shell: single pane, bottom navigation, push screens. */
(function () {
  "use strict";
  var U = window.VeilUI, h = U.html, raw = U.raw, icon = U.icon;
  var TABS = [["chats", "Chats", "chats"], ["contacts", "Contacts", "users"], ["settings", "Settings", "settings"]];

  function nav(active) {
    return h`<nav class="m-nav glass-strong" aria-label="Main"><ul>${TABS.map(function (t) {
      return h`<li><a href="#${t[0]}" ${raw(active === t[0] ? 'aria-current="page"' : "")}><span class="nav-ic">${icon(t[2])}${t[0] === "chats" ? h`<span class="badge nav-badge"><span aria-hidden="true">16</span><span class="sr-only">, 16 unread</span></span>` : ""}</span><span>${t[1]}</span></a></li>`;
    })}</ul></nav>`;
  }
  function tab(active, title, actions, body, o) {
    o = o || {};
    return h`<div class="m-screen tab">${o.top || ""}<header class="m-appbar"><h1>${title}</h1><span class="spacer"></span>${actions || ""}</header>
      <div class="m-body" ${raw(o.busy ? 'aria-busy="true"' : "")}>${body}</div>${o.fab || ""}${nav(active)}</div>`;
  }
  function push(title, back, body, o) {
    o = o || {};
    return h`<div class="m-screen push ${o.cls || ""}"><header class="m-topbar glass"><a class="icon-btn" href="${back}" aria-label="Back">${icon("back")}</a><h1>${title}</h1><span class="spacer"></span>${o.actions || ""}</header>
      <div class="m-body">${body}</div>${o.after || ""}</div>`;
  }
  function full(body, cls) { return h`<div class="m-screen full ${cls || ""}">${body}</div>`; }
  var chatActions = h`<a class="icon-btn" href="#add" aria-label="Add contact">${icon("user-plus")}</a>`;
  var search = h`<div class="m-search"><div class="input slim"><span class="lead-icon">${icon("search")}</span><label class="sr-only" for="m-q">Search conversations</label><input id="m-q" type="search" placeholder="Search"></div></div>`;
  var fab = h`<a class="m-fab icon-btn accent" href="#add" aria-label="New conversation: add a contact">${icon("qr")}</a>`;

  var R = {
    welcome: function () { return full(U.welcomeContent(), "onb-screen"); },
    keygen: function () { return full(U.keygenContent(), "onb-screen"); },
    passphrase: function () { return full(U.passphraseContent(), "onb-screen"); },
    protection: function () { return full(U.protectionContent(), "onb-screen"); },
    lock: function () { return full(U.lockContent(), "onb-screen"); },
    chats: function () { return tab("chats", "Chats", chatActions, h`${search}${U.convList()}`, { fab: fab }); },
    "chats-offline": function () {
      return tab("chats", "Chats", chatActions, h`${search}${U.convList()}`, { fab: fab, top: h`<div class="conn-bar reconnecting" role="status">${icon("refresh", "icon-sm spin")}Reconnecting to relay… attempt 3</div>` });
    },
    "chats-empty": function () { return tab("chats", "Chats", chatActions, U.chatsEmpty()); },
    "chats-loading": function () { return tab("chats", "Chats", "", h`<p class="m-loading-note" role="status">${icon("lock", "icon-xs")} Unlocking your vault…</p>${U.skeletonList(8)}`, { busy: true }); },
    contacts: function () { return tab("contacts", "Contacts", chatActions, h`${search}${U.contactsList()}`); },
    chat: function (p) { return h`<div class="m-screen chat-screen">${U.chatPane(p, "", { back: "#chats" })}</div>`; },
    "chat-empty": function (p) { return h`<div class="m-screen chat-screen">${U.chatPane(p, "empty", { back: "#chats" })}</div>`; },
    "chat-keychange": function (p) { return h`<div class="m-screen chat-screen">${U.chatPane(p, "keychange", { back: "#chats" })}</div>`; },
    "chat-offline": function (p) { return h`<div class="m-screen chat-screen">${U.chatPane(p, "offline", { back: "#chats" })}</div>`; },
    profile: function (p) { return push("Contact", "#chat:" + p, U.profileContent(p), { actions: h`<button class="icon-btn" type="button" aria-label="Edit contact name">${icon("edit")}</button>` }); },
    safety: function (p) { return push("Safety number", "#profile:" + p, U.safetyContent(p)); },
    add: function () { return push("Add contact", "#chats", U.addContent()); },
    scan: function () { return push("Add contact", "#chats", U.scanContent()); },
    verified: function () { return full(U.verifiedContent(), "onb-screen"); },
    "call-audio": function (p) { return full(U.callContent("audio", p), "call-screen"); },
    "call-video": function (p) { return full(U.callContent("video", p), "call-screen"); },
    settings: function () { return tab("settings", "Settings", "", h`<div class="m-pad">${U.settingsMeCard()}<h3 class="group-title">Preferences</h3>${U.settingsNav()}<p class="hint center app-ver">Veil 0.1.0 · design prototype</p></div>`); },
    "settings-privacy": function () { return push("Privacy", "#settings", h`<div class="m-pad">${U.settingsPrivacy()}</div>`); },
    "settings-appearance": function () { return push("Appearance", "#settings", h`<div class="m-pad">${U.settingsAppearance()}</div>`); },
    "settings-relays": function () { return push("Relay servers", "#settings", h`<div class="m-pad">${U.settingsRelays()}</div>`); },
    "settings-security": function () { return push("Security", "#settings", h`<div class="m-pad">${U.settingsSecurity()}</div>`); },
    panic: function () { return push("Security", "#settings", h`<div class="m-pad">${U.settingsSecurity()}</div>`, { after: U.panicDialog() }); },
    error: function () { return tab("chats", "Chats", chatActions, U.errorContent(), { top: h`<div class="conn-bar offline" role="status">${icon("wifi-off", "icon-sm")}Relay unreachable · messages queued</div>` }); },
    shortcuts: function () { return R.chats(); },
  };

  window.VeilShell = {
    defaultRoute: "welcome",
    screens: window.VeilScreens.filter(function (s) { return !s.desktopOnly; }),
    render: function (r) {
      var fn = R[r.id] || R.chats;
      var app = document.getElementById("app");
      app.innerHTML = String(fn(r.param || "ada"));
      document.title = "Veil · " + ((window.VeilScreens.find(function (s) { return s.route === r.id || s.route === r.id + ":" + r.param; }) || {}).title || "Prototype") + " (mobile)";
      var h1 = app.querySelector("h1, h2");
      if (h1 && !window.VeilApp.capture) { h1.setAttribute("tabindex", "-1"); h1.focus({ preventScroll: true }); }
    },
  };
})();
