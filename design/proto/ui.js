/* Veil prototype: components + shared screen content.
 * html`` escapes every interpolated value unless wrapped in raw() — the
 * same "render as plain text" rule the React app will follow. */
(function () {
  "use strict";
  var D = window.VeilData;

  // ---------------------------------------------------------------- core
  function Safe(s) { this.s = s; }
  Safe.prototype.toString = function () { return this.s; };
  function raw(s) { return new Safe(String(s)); }
  var ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  function esc(v) { return String(v).replace(/[&<>"']/g, function (c) { return ESC[c]; }); }
  function val(v) {
    if (v == null || v === false || v === true) return "";
    if (v instanceof Safe) return v.s;
    if (Array.isArray(v)) return v.map(val).join("");
    return esc(v);
  }
  function html(strings) {
    var out = strings[0];
    for (var i = 1; i < arguments.length; i++) out += val(arguments[i]) + strings[i];
    return new Safe(out);
  }
  function icon(name, cls) {
    return raw('<svg class="icon ' + (cls || "") + (window.VeilIcons.filled(name) ? " icon-fill" : "") +
      '" aria-hidden="true" focusable="false"><use href="#i-' + name + '"/></svg>');
  }
  var uid = 0;
  function logo(cls) {
    var id = "lg" + (++uid);
    return raw('<svg class="logo ' + (cls || "") + '" viewBox="0 0 48 48" aria-hidden="true"><defs>' +
      '<linearGradient id="' + id + '" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#4338ff"/><stop offset=".55" stop-color="#8b3dff"/><stop offset="1" stop-color="#00b8d9"/></linearGradient></defs>' +
      '<rect width="48" height="48" rx="15" fill="url(#' + id + ')"/>' +
      '<path d="M13 15c5 0 8.5 7 11 19 2.5-12 6-19 11-19" fill="none" stroke="#fff" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<path d="M13 15c4 3 7 3 11 3s7 0 11-3" fill="none" stroke="#fff" stroke-opacity=".55" stroke-width="2.4" stroke-linecap="round"/></svg>');
  }
  function c(id) { return D.contacts[id] || D.contacts.ada; }

  // ---------------------------------------------------------- primitives
  var CONN_LABEL = { online: "Connected", connecting: "Connecting", offline: "Offline, messages go to their mailbox" };
  function avatar(p, size, opts) {
    opts = opts || {};
    var hue = p === "me" ? "hue-me" : "hue-" + p.hue;
    var initials = p === "me" ? D.me.initials : p.initials;
    var vt = opts.hero ? raw(' data-vt="hero-avatar"') : "";
    return html`<span class="avatar ${size || ""} ${hue} ${opts.ring ? "ring-verified" : ""}"${vt} aria-hidden="true"><span class="face">${initials}</span>${
      opts.conn && p !== "me" ? html`<span class="conn" data-state="${p.conn}"></span>` : ""}</span>`;
  }
  function verifiedMark(p) {
    return p.verified ? html`<span class="verified-mark" title="Verified">${icon("shield-check")}<span class="sr-only">Verified</span></span>` : "";
  }
  function transportSub(p) {
    if (p.conn === "offline") return html`<span>Offline · delivering to mailbox</span>`;
    if (p.conn === "connecting") return html`<span class="hstack">${icon("refresh", "spin")} Connecting…</span>`;
    return p.transport === "direct"
      ? html`<span class="transport direct">${icon("eye")}Direct · IP visible</span>`
      : html`<span class="transport relay">${icon("shield")}Relayed · IP hidden</span>`;
  }
  function chip(text, kind, ic) { return html`<span class="chip ${kind || ""}">${ic ? icon(ic) : ""}${text}</span>`; }
  function toggleRow(o) {
    var id = "t-" + o.id;
    return html`<div class="row"><div class="row-icon ${o.tone || ""}">${icon(o.icon)}</div>
      <div class="row-main"><label class="row-title" for="${id}">${o.title}</label>${o.sub ? html`<div class="row-sub" id="${id}-d">${o.sub}</div>` : ""}</div>
      <span class="switch"><input type="checkbox" role="switch" id="${id}" ${raw(o.on ? "checked" : "")} ${raw(o.sub ? 'aria-describedby="' + id + '-d"' : "")} data-setting="${o.id}"><span class="track"><span class="thumb"></span></span></span></div>`;
  }
  function linkRow(o) {
    var tag = o.href ? "a" : "button";
    var attrs = o.href ? raw('href="' + esc(o.href) + '"') : raw('type="button"');
    return html`${raw("<" + tag + " ")}class="row ${o.danger ? "danger" : ""}" ${attrs}${raw(">")}
      <div class="row-icon ${o.tone || ""}">${icon(o.icon)}</div>
      <div class="row-main"><div class="row-title">${o.title}</div>${o.sub ? html`<div class="row-sub">${o.sub}</div>` : ""}</div>
      ${o.value ? html`<span class="row-value">${o.value}</span>` : ""}${o.chev === false ? "" : icon("chevron-right", "chev")}${raw("</" + tag + ">")}`;
  }
  function segmented(name, opts, current, label) {
    return html`<div class="segmented" role="radiogroup" aria-label="${label}">${opts.map(function (o) {
      return html`<label><input type="radio" name="${name}" value="${o.v}" ${raw(o.v === current ? "checked" : "")} data-setting="${name}"><span>${o.icon ? icon(o.icon) : ""}${o.t}</span></label>`;
    })}</div>`;
  }
  function qr(text) {
    var q = window.qrcode(0, "M");
    q.addData(text);
    q.make();
    var n = q.getModuleCount(), d = "", m = 2;
    for (var r = 0; r < n; r++) for (var col = 0; col < n; col++) if (q.isDark(r, col)) d += "M" + (col + m) + " " + (r + m) + "h1v1h-1z";
    return raw('<svg class="qr" viewBox="0 0 ' + (n + 2 * m) + " " + (n + 2 * m) + '" shape-rendering="crispEdges" role="img" aria-label="QR code"><path d="' + d + '"/></svg>');
  }
  function waveSvg(id, playedFrac) {
    var bars = D.wave(id, 36), w = 3, gap = 2, H = 28, out = "";
    bars.forEach(function (b, i) {
      var h = Math.round(b * H * 10) / 10;
      out += '<rect x="' + i * (w + gap) + '" y="' + (H - h) / 2 + '" width="' + w + '" height="' + h + '" rx="1.5"' + (i / bars.length < playedFrac ? ' class="played"' : "") + "/>";
    });
    return raw('<svg class="wave" viewBox="0 0 ' + bars.length * (w + gap) + " " + H + '" preserveAspectRatio="none" aria-hidden="true">' + out + "</svg>");
  }
  function dots() { return raw('<span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>'); }

  // ------------------------------------------------------- conversations
  function convRow(p, opts) {
    opts = opts || {};
    var preview;
    if (p.typing) preview = html`<span class="conv-preview typing">${dots()}typing…</span>`;
    else if (p.keyChanged) preview = html`<span class="conv-preview warn">${icon("alert-triangle", "icon-xs")}Safety number changed</span>`;
    else preview = html`<span class="conv-preview">${p.lastMine ? "You: " : ""}${p.lastIcon ? icon(p.lastIcon, "icon-xs") : ""} ${p.last}</span>`;
    var sr = [p.name, p.verified ? "verified" : "not verified", CONN_LABEL[p.conn], p.unread ? p.unread + " unread" : "", p.timer ? "disappearing messages " + p.timer : "", p.pinned ? "pinned" : "", p.muted ? "muted" : ""].filter(Boolean).join(", ");
    return html`<li><a class="conv" href="#chat:${p.id}" data-conv="${p.id}" ${raw(opts.selected ? 'aria-current="page"' : "")} aria-label="${sr}">
      ${avatar(p, "", { conn: true, hero: opts.hero })}
      <div class="conv-main">
        <div class="conv-top"><span class="conv-name">${p.name}</span>${verifiedMark(p)}<time class="${p.unread ? "unread" : ""}">${p.time}</time></div>
        <div class="conv-bottom">${preview}<span class="conv-flags">${p.timer ? html`<span class="timer-chip" title="Disappearing: ${p.timer}">${icon("timer")}${p.timerShort}</span>` : ""}${p.muted ? icon("bell-off") : ""}${p.pinned ? icon("pin") : ""}${p.unread ? html`<span class="badge ${p.muted ? "muted" : ""}">${p.unread}</span>` : ""}</span></div>
      </div></a></li>`;
  }
  function convList(selected) {
    var pinned = D.order.filter(function (id) { return D.contacts[id].pinned; });
    var rest = D.order.filter(function (id) { return !D.contacts[id].pinned; });
    var i = 0;
    function rows(ids) { return ids.map(function (id) { return raw(String(convRow(D.contacts[id], { selected: id === selected })).replace("<li>", '<li data-i="' + i++ + '">')); }); }
    return html`<h2 class="list-section-title" id="pinned-h">Pinned</h2><ul class="stagger" aria-labelledby="pinned-h">${rows(pinned)}</ul>
      <h2 class="list-section-title" id="all-h">All chats</h2><ul class="stagger" aria-labelledby="all-h">${rows(rest)}</ul>`;
  }
  function skeletonList(n) {
    var out = [];
    for (var k = 0; k < n; k++) out.push(html`<div class="skel-row"><span class="skel av"></span><span class="lines"><span class="skel l1"></span><span class="skel l2"></span></span></div>`);
    return html`<div aria-hidden="true">${out}</div>`;
  }
  function contactsList() {
    var ver = D.order.filter(function (id) { return D.contacts[id].verified; });
    var un = D.order.filter(function (id) { return !D.contacts[id].verified; });
    function row(id) {
      var p = D.contacts[id];
      var status = p.keyChanged ? html`<span class="row-sub hstack">${chip("Safety number changed", "warning", "alert-triangle")}</span>`
        : p.verified ? html`<div class="row-sub">Verified · ${p.verifiedHow.toLowerCase()} · ${p.verifiedOn}</div>`
        : html`<div class="row-sub">Not verified · added by ${p.verifiedHow.toLowerCase()}</div>`;
      return html`<li><a class="row" href="#profile:${p.id}">${avatar(p, "", { conn: true })}<div class="row-main"><div class="row-title hstack">${p.name}${verifiedMark(p)}</div>${status}</div>${icon("chevron-right", "chev")}</a></li>`;
    }
    return html`<h2 class="list-section-title">Verified · ${ver.length}</h2><ul class="list-pad">${ver.map(row)}</ul>
      <h2 class="list-section-title">Not verified · ${un.length}</h2><ul class="list-pad">${un.map(row)}</ul>`;
  }

  // ---------------------------------------------------------------- chat
  function meta(time, status, extra) {
    var st = { sending: ["clock", "Sending"], sent: ["check", "Sent"], delivered: ["check-double", "Delivered"], read: ["check-double", "Read"], queued: ["clock", "Queued"] }[status];
    return html`<span class="meta">${extra || ""}<time>${time}</time>${st ? html`${icon(st[0])}<span class="sr-only">${st[1]}</span>${status === "read" ? html`<span aria-hidden="true">Read</span>` : ""}` : ""}</span>`;
  }
  function msg(dir, body, o) {
    o = o || {};
    return html`<div class="msg ${dir} ${o.cont ? "cont" : ""} ${o.cls || ""}">${body}${o.after || ""}</div>`;
  }
  function bubble(text, m, extra) {
    return html`<div class="bubble">${extra || ""}${text}${m}</div>`;
  }
  function reactions(list) {
    return html`<div class="reactions">${list.map(function (r) {
      return html`<button class="reaction ${r.mine ? "mine" : ""}" type="button" aria-label="${r.label}${r.n > 1 ? ", " + r.n : ""}${r.mine ? ", including you" : ""}" aria-pressed="${r.mine ? "true" : "false"}"><span aria-hidden="true">${r.e}</span>${r.n > 1 ? html`<b>${r.n}</b>` : ""}</button>`;
    })}</div>`;
  }
  function chatMessages(id) {
    var p = c(id);
    if (id === "ada") {
      return html`
      <div class="day-sep" role="separator">Yesterday</div>
      <div class="sys-msg success">${icon("shield-check")}You verified ${p.first} in person · safety numbers match</div>
      ${msg("in", bubble("Landed! The keynote got moved to 4pm. Can you still make it?", meta("18:02")))}
      ${msg("out", bubble("Yes! Grabbing a coffee first. Sending the slides now.", meta("18:03", "read")), { after: reactions([{ e: "❤️", label: "Heart", n: 1 }]) })}
      ${msg("out", html`<div class="bubble"><div class="att-file"><span class="ficon">${icon("file")}</span><span class="fmeta"><span class="fname">keynote-final.pdf</span><span class="fsub">3.1 of 4.8 MB · encrypting &amp; uploading</span><span class="progress" role="progressbar" aria-label="Upload progress" aria-valuenow="64" aria-valuemin="0" aria-valuemax="100"><i data-p="0.64"></i></span></span><button class="icon-btn" type="button" aria-label="Cancel upload">${icon("x")}</button></div>${meta("18:04", "sending")}</div>`, { cont: true })}
      ${msg("in", html`<div class="bubble media"><span class="att-img"><span class="art art-pier"></span></span><span class="cap">The pier on Sunday, no filter${meta("18:10")}</span></div>`, { after: reactions([{ e: "😍", label: "Heart eyes", n: 2, mine: true }, { e: "🔥", label: "Fire", n: 1 }]) })}
      ${msg("in", html`<div class="bubble"><div class="voice"><button class="play" type="button" aria-label="Play voice note, 42 seconds">${icon("play")}</button>${waveSvg("ada", 0.3)}<span class="vdur">0:42</span></div>${meta("18:12")}</div>`, { cont: true })}
      <div class="day-sep" role="separator">Today</div>
      <div class="sys-msg">${icon("timer")}You set disappearing messages to 1 day</div>
      ${msg("in", bubble("Did the slides arrive OK? My upload was super slow at the airport", meta("14:02")))}
      ${msg("out", bubble(html`Yes, all good, file arrived intact${meta("14:05", "read", html`<span class="edited">edited · </span>`)}`, "", html`<span class="reply"><b>${p.first}</b><span>Did the slides arrive OK? My upload was super slow…</span></span>`))}
      ${msg("out", bubble("Told you the light at the pier would be worth it ✨", meta("14:06", "delivered")), { cont: true })}
      <div class="typing-bubble" role="status" aria-label="${p.first} is typing">${dots()}</div>`;
    }
    if (id === "mira") {
      return html`<div class="day-sep" role="separator">Today</div>
      <div class="sys-msg">${icon("eye")}You allowed a direct connection with ${p.first}. Your IP is visible to ${p.first}.</div>
      ${msg("in", bubble("Call in 5? Easier to explain the floor plan on video", meta("13:30")))}
      ${msg("out", bubble("Sure, ringing you now", meta("13:31", "read")))}
      <div class="sys-msg">${icon("video")}Video call · 18 min · direct</div>
      ${msg("in", html`<div class="bubble"><div class="voice"><button class="play" type="button" aria-label="Play voice note, 42 seconds">${icon("play")}</button>${waveSvg("mira", 0)}<span class="vdur">0:42</span></div>${meta("13:48")}</div>`)}`;
    }
    if (id === "lena") {
      return html`<div class="day-sep" role="separator">Last week</div>
      ${msg("in", bubble("Here's the address for Saturday: the green door next to the bakery", meta("Thu")))}
      ${msg("out", bubble("Perfect, see you there", meta("Thu", "read")))}
      <div class="day-sep" role="separator">Today</div>
      <div class="sys-msg warning" role="alert">${icon("alert-triangle")}${p.first}'s safety number changed · ${p.keyChangedOn}</div>
      ${msg("in", html`<div class="bubble"><span class="muted">${icon("lock", "icon-xs")} Held until you review the new safety number</span>${meta("12:16")}</div>`)}`;
    }
    if (id === "theo") {
      return html`<div class="day-sep" role="separator">Sunday</div>
      ${msg("in", bubble("Dinner at 8 still works?", meta("19:40")))}
      ${msg("out", bubble("See you then", meta("19:41", "read")))}
      <div class="day-sep" role="separator">Today</div>
      ${msg("out", bubble("Running 10 min late, sorry!", meta("19:52", "queued")), { cls: "pending" })}
      ${msg("out", bubble("Can you grab us a table by the window?", ""), { cls: "failed", cont: true, after: html`<button class="fail-row" type="button">${icon("alert-circle")}Not delivered · Retry</button>` })}`;
    }
    return "";
  }
  function chatHeader(p, o) {
    o = o || {};
    var sub = transportSub(p);
    return html`<header class="chat-hdr glass">
      ${o.back ? html`<a class="icon-btn" href="${o.back}" aria-label="Back to chats">${icon("back")}</a>` : ""}
      <a class="who" href="#profile:${p.id}" aria-label="${p.name}, view profile">${avatar(p, "", { conn: true, hero: true })}
        <span class="who-text"><span class="who-name">${p.name}${verifiedMark(p)}${p.timer ? html`<span class="timer-chip" title="Disappearing messages ${p.timer}">${icon("timer")}${p.timerShort}<span class="sr-only">disappearing messages ${p.timer}</span></span>` : ""}</span>
        <span class="who-sub">${p.verified ? "" : html`<span>Not verified ·</span>`}${sub}</span></span></a>
      <a class="icon-btn" href="#call-audio:${p.id}" aria-label="Start encrypted voice call">${icon("phone")}</a>
      <a class="icon-btn" href="#call-video:${p.id}" aria-label="Start encrypted video call">${icon("video")}</a>
      ${o.info ? html`<a class="icon-btn" href="${o.info}" aria-label="Conversation info" ${raw(o.infoOpen ? 'aria-expanded="true"' : 'aria-expanded="false"')}>${icon("info")}</a>` : ""}
    </header>`;
  }
  function composer(p) {
    return html`<form class="composer" data-composer="${p.id}" autocomplete="off">
      <button class="icon-btn solid" type="button" aria-label="Attach file or photo">${icon("plus")}</button>
      <div class="box"><label class="sr-only" for="msg-${p.id}">Message ${p.first}</label><textarea id="msg-${p.id}" rows="1" placeholder="Message" spellcheck="true"></textarea>
        <button class="icon-btn" type="button" aria-label="Emoji">${icon("smile")}</button></div>
      <button class="icon-btn accent send-btn" type="submit" aria-label="Send or hold to record voice note">${icon("mic", "i-mic")}${icon("send", "i-send")}</button>
    </form>`;
  }
  function chatPane(id, variant, o) {
    o = o || {};
    var p = c(id);
    var top = "", body, foot = composer(p);
    if (variant === "keychange") {
      top = html`<div class="banner warning chat-banner" role="alert">${icon("shield-alert", "icon-lg")}<div><strong>${p.first}'s safety number changed</strong>
        <p>${p.first} may have reinstalled Veil or switched phones, or someone may be intercepting. New messages are held until you review the change.</p>
        <div class="banner-actions"><a class="btn btn-sm btn-warning" href="#safety:${p.id}">Review safety number</a><button class="btn btn-sm btn-secondary" type="button">Learn more</button></div></div></div>`;
      foot = html`<div class="composer-locked">${icon("lock")}<p>Sending to ${p.first} is paused until you review the new safety number.</p></div>`;
    }
    if (variant === "offline") top = html`<div class="conn-bar offline" role="status">${icon("wifi-off", "icon-sm")}You're offline. Messages will send when you reconnect.</div>`;
    if (variant === "empty") {
      body = html`<div class="msgs" role="log" aria-label="Messages with ${p.name}"><div class="state">
        <div class="pair">${avatar("me", "lg")}<span class="link-line"></span>${avatar(p, "lg")}</div>
        <h2>Say hi to ${p.first}</h2>
        <p>Messages and calls with ${p.first} are end-to-end encrypted. Only the two of you can read them, not the relay and not us.</p>
        <div class="banner info" role="note">${icon("shield-alert")}<div class="center-left"><strong>Not verified yet</strong><p>You added ${p.first} with an invite link. Compare safety numbers in person or on a call to make sure no one is in the middle.</p>
        <div class="banner-actions"><a class="btn btn-sm btn-secondary" href="#safety:${p.id}">Compare safety numbers</a></div></div></div>
      </div><div class="typing-bubble" role="status" aria-label="${p.first} is typing">${dots()}</div></div>`;
    } else {
      body = html`<div class="msgs" role="log" aria-live="polite" aria-relevant="additions" aria-label="Messages with ${p.name}" tabindex="0">${chatMessages(id)}</div>`;
    }
    return html`<section class="chat" aria-label="Conversation with ${p.name}">${chatHeader(p, o)}${top}${body}${foot}</section>`;
  }
  function chatSkeleton() {
    return html`<div class="chat" aria-busy="true" aria-label="Loading conversation"><div class="chat-hdr"><span class="skel av-skel"></span><span class="lines"><span class="skel l1"></span></span></div>
      <div class="msgs skel-msgs" aria-hidden="true"><span class="skel b w60"></span><span class="skel b w40 r"></span><span class="skel b w70"></span><span class="skel b w50 r"></span><span class="skel b w30"></span></div></div>`;
  }

  // ------------------------------------------------------------- profile
  function profileContent(id) {
    var p = c(id);
    return html`<div class="profile">
      <div class="profile-hero">${avatar(p, "xl", { hero: true, ring: p.verified })}
        <h2 class="profile-name">${p.name}</h2>
        ${p.keyChanged ? chip("Safety number changed", "warning", "alert-triangle")
          : p.verified ? chip("Verified " + p.verifiedHow.toLowerCase() + " · " + p.verifiedOn, "success", "shield-check")
          : chip("Not verified", "outline", "shield")}
        <div class="profile-actions">
          <a class="act" href="#chat:${p.id}"><span class="icon-btn solid">${icon("chats")}</span>Message</a>
          <a class="act" href="#call-audio:${p.id}"><span class="icon-btn solid">${icon("phone")}</span>Voice</a>
          <a class="act" href="#call-video:${p.id}"><span class="icon-btn solid">${icon("video")}</span>Video</a>
          <button class="act" type="button" aria-pressed="false"><span class="icon-btn solid">${icon("bell-off")}</span>Mute</button>
        </div></div>
      <h3 class="group-title">Security</h3>
      <div class="group card">
        ${linkRow({ href: "#safety:" + p.id, icon: "key", tone: p.verified ? "success" : "warning", title: "Safety number", sub: p.verified ? "Matches · checked " + p.verifiedOn : "Compare to verify " + p.first, value: p.verified ? "Verified" : "Verify" })}
        <div class="row"><div class="row-icon accent">${icon("route")}</div><div class="row-main"><div class="row-title">Connection</div><div class="row-sub">${p.transport === "direct" ? "Direct: faster calls, but " + p.first + " can see your IP address" : "Relay only: " + p.first + " never sees your IP address"}</div></div></div>
        <div class="row conn-choice">${segmented("conn-" + p.id, [{ v: "relay", t: "Relay only", icon: "shield" }, { v: "direct", t: "Allow direct", icon: "eye" }], p.transport, "Connection mode for " + p.first)}</div>
        ${p.transport === "direct" ? html`<div class="row"><div class="banner warning slim">${icon("eye")}<p>Direct mode reveals your IP address to ${p.first}. Use it only with people you trust.</p></div></div>` : ""}
        ${linkRow({ icon: "timer", title: "Disappearing messages", value: p.timer || "Off" })}
      </div>
      <h3 class="group-title">Media &amp; files</h3>
      <div class="group card media-strip"><span class="att-thumb"><span class="art art-pier"></span></span><span class="att-thumb"><span class="art art-video"></span></span><span class="att-thumb file">${icon("file")}</span><a class="att-thumb more" href="#chat:${p.id}" aria-label="All media, 24 items">+21</a></div>
      <h3 class="group-title">Privacy</h3>
      <div class="group card">
        ${linkRow({ icon: "ban", tone: "danger", title: "Block " + p.first, danger: true, chev: false })}
        ${linkRow({ icon: "trash", tone: "danger", title: "Delete conversation", sub: "Removes it from this device only", danger: true, chev: false })}
      </div></div>`;
  }
  function safetyContent(id, compact) {
    var p = c(id);
    var groups = D.safetyNumber(p.id);
    var status = p.verified
      ? html`<div class="banner neutral">${icon("shield-check", "icon-lg ok")}<div><strong>Verified ${p.verifiedHow.toLowerCase()} · ${p.verifiedOn}</strong><p>If this number ever changes, Veil will warn you before sending anything.</p></div></div>`
      : p.keyChanged
      ? html`<div class="banner warning" role="alert">${icon("alert-triangle", "icon-lg")}<div><strong>New safety number · ${p.keyChangedOn}</strong><p>${p.first}'s key changed. Compare this new number with ${p.first} before you trust it again.</p></div></div>`
      : html`<div class="banner info">${icon("shield")}<div><strong>Not verified</strong><p>Compare these numbers with ${p.first} in person or on a call. If they match, no one is in the middle.</p></div></div>`;
    return html`<div class="safety ${compact ? "compact" : ""}">
      ${status}
      <div class="safety-qr"><div class="qr-card">${qr("veil-sn:" + groups.join(""))}</div>
        <p class="hint center">Scan ${p.first}'s code, or have ${p.first} scan yours. Both screens show the same code when the numbers match.</p></div>
      <div class="safety-num card"><div class="safety-grid" aria-label="Safety number">${groups.map(function (g) { return html`<span>${g}</span>`; })}</div></div>
      <div class="safety-actions">
        <a class="btn btn-primary btn-block" href="#scan">${icon("scan")}Scan ${p.first}'s code</a>
        ${p.verified ? html`<button class="btn btn-secondary btn-block" type="button">Clear verification</button>` : html`<a class="btn btn-secondary btn-block" href="#verified">${icon("check")}Numbers match: mark as verified</a>`}
      </div>
      <p class="hint center">Safety numbers are derived from both identity keys. They never leave your devices.</p></div>`;
  }

  // ------------------------------------------------------- add / pairing
  function addContent() {
    return html`<div class="pairing">
      ${segmented("pair-tab", [{ v: "code", t: "My code", icon: "qr" }, { v: "scan", t: "Scan", icon: "scan" }], "code", "Add contact")}
      <div class="qr-wrap"><div class="qr-card">${qr(D.me.invite)}<span class="qr-logo">${logo()}</span></div></div>
      <div class="center stack-sm"><h2 class="pair-title">Let them scan this in person</h2>
        <p class="hint">Scanning each other's codes face to face verifies you both automatically.</p>
        <div class="hstack center-row">${chip("Single use", "outline", "key")}${chip("Expires in 23 h 59 m", "outline", "clock")}</div></div>
      <div class="invite card">
        <div class="field"><span class="label" id="inv-l">Or send an invite link</span>
          <div class="input mono"><input type="text" readonly value="${D.me.invite}" aria-labelledby="inv-l"><button class="icon-btn" type="button" aria-label="Copy invite link">${icon("copy")}</button></div></div>
        <p class="hint hstack-top">${icon("alert-circle", "icon-sm")}<span>Contacts added by link start as <b>not verified</b> until you compare safety numbers.</span></p>
        <button class="btn btn-secondary btn-block" type="button">${icon("share")}Share invite link</button>
      </div></div>`;
  }
  function scanContent() {
    return html`<div class="pairing">
      ${segmented("pair-tab", [{ v: "code", t: "My code", icon: "qr" }, { v: "scan", t: "Scan", icon: "scan" }], "scan", "Add contact")}
      <div class="scanner" role="img" aria-label="Camera viewfinder"><span class="feed-blur"></span><span class="frame"><i></i><i></i><i></i><i></i></span><span class="line"></span><span class="hint-pill">Point at a Veil code</span></div>
      <div class="center stack-sm"><h2 class="pair-title">Scan their code</h2><p class="hint">The camera feed is processed on this device only and never stored.</p></div>
      <div class="stack-sm"><a class="btn btn-primary btn-block" href="#verified">${icon("check")}Simulate a successful scan</a><button class="btn btn-secondary btn-block" type="button">${icon("link")}Paste an invite link instead</button></div></div>`;
  }
  function verifiedContent() {
    var p = c("ada");
    return html`<div class="verified-view" role="status" aria-live="polite">
      <div class="verified-burst"><span class="ring"></span><span class="ring r2"></span><span class="ring r3"></span><span class="badge-check">${icon("check")}</span></div>
      <h2>${p.first} is verified</h2>
      <p class="muted">You scanned each other's codes in person. Your safety numbers match, so no one can be in the middle.</p>
      <div class="pair">${avatar("me", "lg")}<span class="link-line"></span>${avatar(p, "lg", { ring: true })}</div>
      <div class="stack-sm wide"><a class="btn btn-primary btn-block" href="#chat:ada">${icon("chats")}Send ${p.first} a message</a><a class="btn btn-ghost btn-block" href="#chats">Done</a></div></div>`;
  }

  // --------------------------------------------------------------- calls
  function callContent(kind, id) {
    var p = c(id);
    var direct = p.transport === "direct";
    var tchip = direct
      ? html`<button class="transport-chip direct" type="button" aria-describedby="tc-d">${icon("eye")}Direct · IP visible to ${p.first}</button><span class="sr-only" id="tc-d">Direct connection. Your IP address is visible to ${p.first}. Tap to switch to relayed.</span>`
      : html`<button class="transport-chip relay" type="button" aria-describedby="tc-d">${icon("shield")}Relayed · IP hidden</button><span class="sr-only" id="tc-d">Relayed through TURN. ${p.first} cannot see your IP address.</span>`;
    var controls = html`<div class="call-controls">
      <span class="call-ctl"><button class="icon-btn" type="button" aria-pressed="false" aria-label="Mute microphone">${icon("mic")}</button>Mute</span>
      ${kind === "video" ? html`<span class="call-ctl"><button class="icon-btn" type="button" aria-pressed="false" aria-label="Turn camera off">${icon("video")}</button>Camera</span><span class="call-ctl"><button class="icon-btn" type="button" aria-label="Switch camera">${icon("flip")}</button>Flip</span>`
        : html`<span class="call-ctl"><button class="icon-btn" type="button" aria-pressed="true" aria-label="Speaker">${icon("speaker")}</button>Speaker</span><span class="call-ctl"><a class="icon-btn" href="#call-video:${p.id}" aria-label="Switch to video">${icon("video")}</a>Video</span>`}
      <span class="call-ctl"><a class="icon-btn end" href="#chat:${p.id}" aria-label="End call">${icon("phone-off")}</a>End</span></div>`;
    if (kind === "video") {
      return html`<section class="call video" aria-label="Video call with ${p.name}"><span class="call-bg" role="img" aria-label="${p.first}'s video"></span>
        <div class="call-top"><span class="call-name">${p.name}</span><span class="call-time" role="timer">18:42</span>${tchip}<span class="e2e">${icon("lock")}End-to-end encrypted</span></div>
        <div class="self-view" role="img" aria-label="Your camera preview"><span>You</span></div>
        <div class="call-stage"></div>${controls}</section>`;
    }
    return html`<section class="call audio" aria-label="Voice call with ${p.name}"><span class="call-bg"></span>
      <div class="call-top"><span class="e2e">${icon("lock")}End-to-end encrypted</span></div>
      <div class="call-stage"><div class="stack center call-id"><span class="levels"><i></i><i></i><i></i>${avatar(p, "xxl", { hero: true })}</span>
        <span class="call-name">${p.name}</span><span class="call-time" role="timer">04:12</span>${tchip}</div></div>${controls}</section>`;
  }

  // ------------------------------------------------------------- settings
  var SETTINGS_NAV = [
    { id: "privacy", icon: "shield", title: "Privacy", sub: "Connections, receipts, link previews" },
    { id: "appearance", icon: "palette", title: "Appearance", sub: "Theme, mode, accent, bubbles, text size" },
    { id: "relays", icon: "server", title: "Relay servers", sub: "relay.example.org · connected" },
    { id: "security", icon: "lock", title: "Security", sub: "Auto-lock, backup, panic wipe" },
  ];
  function settingsMeCard() {
    return html`<div class="card me-card">${avatar("me", "lg")}<div class="row-main"><div class="row-title">Your identity</div>
      <div class="row-sub mono">${D.me.fingerprint.slice(0, 4).join(" ")}…</div><div class="row-sub">No phone number, email or account. Just this key.</div></div>
      <a class="icon-btn solid" href="#add" aria-label="Show my code">${icon("qr")}</a></div>`;
  }
  function settingsNav(active) {
    return html`<ul class="group card settings-nav">${SETTINGS_NAV.map(function (s) {
      return html`<li>${raw(String(linkRow({ href: "#settings-" + s.id, icon: s.icon, tone: "accent", title: s.title, sub: s.sub })).replace('class="row ', 'class="row ' + (active === s.id ? "is-active " : "")).replace("<a ", active === s.id ? '<a aria-current="page" ' : "<a "))}</li>`;
    })}</ul>`;
  }
  function settingsPrivacy() {
    return html`<div class="settings-body">
      <h3 class="group-title">Connections</h3>
      <fieldset class="radio-set"><legend class="sr-only">Default connection mode</legend>
        <label class="radio-card"><input type="radio" name="mode" value="relay" checked data-setting="mode"><span class="dot"></span><span><span class="rc-title">${icon("shield", "icon-sm")}Relay only ${chip("Recommended", "success")}</span><span class="rc-sub">Calls and messages always go through the relay and TURN. Contacts never see your IP address.</span></span></label>
        <label class="radio-card"><input type="radio" name="mode" value="direct" data-setting="mode"><span class="dot"></span><span><span class="rc-title">${icon("eye", "icon-sm")}Allow direct, per contact</span><span class="rc-sub">You can enable Direct for chosen contacts for faster calls. Direct reveals your IP address to that contact.</span></span></label>
      </fieldset>
      <h3 class="group-title">What others see</h3>
      <div class="group card">
        ${toggleRow({ id: "receipts", icon: "check-double", title: "Read receipts", sub: "Off: contacts won't know when you've read their messages." })}
        ${toggleRow({ id: "typing", icon: "keyboard", title: "Typing indicators", sub: "Off: contacts won't see when you're typing." })}
      </div>
      <h3 class="group-title">Leaks to avoid</h3>
      <div class="group card">
        ${toggleRow({ id: "previews", icon: "link", tone: "warning", title: "Link previews", sub: "Off by default. Fetching a preview contacts the website from your device, revealing your IP address and what you're reading." })}
        ${toggleRow({ id: "lan", icon: "wifi", title: "Find contacts on this network", sub: "Off by default. Announces Veil on the local Wi-Fi (mDNS) for same-room pairing." })}
      </div>
      <h3 class="group-title">Notifications</h3>
      <div class="group card">
        ${toggleRow({ id: "generic", icon: "bell", title: "Hide sender and content", sub: "Notifications only say “New message”. Nothing readable reaches the lock screen or the OS push service.", on: true })}
      </div></div>`;
  }
  function settingsAppearance() {
    var cur = window.VeilApp ? window.VeilApp.prefs : {};
    var p = c("ada");
    return html`<div class="settings-body">
      <div class="preview-chat card" aria-label="Preview">
        ${msg("in", bubble("This is how messages look.", meta("09:41")))}
        ${msg("out", bubble("Looks great, with readable text on every gradient.", meta("09:42", "read")))}
      </div>
      <h3 class="group-title" id="th-l">Theme</h3>
      <div class="theme-cards" role="radiogroup" aria-labelledby="th-l">${[["aurora", "Aurora Glass", "Gradients, glass, ambient glow"], ["ink", "Ink & Signal", "Matte, hairlines, calm"]].map(function (t) {
        return html`<label class="theme-card"><input type="radio" name="style" value="${t[0]}" ${raw((cur.style || "aurora") === t[0] ? "checked" : "")} data-setting="style">
          <span class="tc-preview tc-${t[0]}" aria-hidden="true"><i class="in"></i><i class="out"></i><i class="in"></i></span>
          <span class="tc-label"><span class="tc-check">${icon("check")}</span><span>${t[1]}<small>${t[2]}</small></span></span></label>`;
      })}</div>
      <h3 class="group-title" id="md-l">Mode</h3>
      ${segmented("theme", [{ v: "system", t: "System", icon: "monitor" }, { v: "dark", t: "Dark", icon: "moon" }, { v: "light", t: "Light", icon: "sun" }], cur.themePref || "dark", "Mode")}
      <h3 class="group-title" id="ac-l">Accent</h3>
      <div class="swatches" role="radiogroup" aria-labelledby="ac-l">${[["aurora", "Aurora"], ["lagoon", "Lagoon"], ["ember", "Ember"]].map(function (a) {
        return html`<label class="swatch"><input type="radio" name="accent" value="${a[0]}" ${raw((cur.accent || "aurora") === a[0] ? "checked" : "")} data-setting="accent"><span class="sw sw-${a[0]}">${icon("check")}</span><span class="lbl">${a[1]}</span></label>`;
      })}</div>
      <h3 class="group-title">Bubble style</h3>
      ${segmented("bubble", [{ v: "gradient", t: "Default" }, { v: "soft", t: "Soft" }, { v: "minimal", t: "Minimal" }], cur.bubble || "gradient", "Bubble style")}
      <h3 class="group-title"><label for="ts">Text size</label></h3>
      <div class="range"><span class="a-sm" aria-hidden="true">A</span><input id="ts" type="range" min="0" max="3" step="1" value="${["sm", "md", "lg", "xl"].indexOf(cur.textSize || "md")}" aria-valuetext="${{ sm: "Small", md: "Default", lg: "Large", xl: "Extra large" }[cur.textSize || "md"]}" data-setting="textSize"><span class="a-lg" aria-hidden="true">A</span></div>
      <h3 class="group-title">Motion</h3>
      <div class="group card">${toggleRow({ id: "reduce-motion", icon: "sparkle", title: "Reduce motion", sub: "Turns off ambient drift and springy animations. Follows your system setting by default.", on: cur.motion === "reduced" })}</div>
    </div>`;
  }
  function settingsRelays() {
    return html`<div class="settings-body">
      <div class="banner info">${icon("info")}<div><strong>What a relay can see</strong><p>Rotating mailbox IDs, message timing and padded sizes, and your IP address while you're connected. Never message content, your identity key or your contact list. It keeps no IP logs.</p></div></div>
      <h3 class="group-title">Your relays</h3>
      <div class="card relay-card"><div class="rh"><span class="row-icon success">${icon("server")}</span><div class="row-main"><div class="row-title">relay.example.org</div><div class="row-sub hstack">${chip("Connected", "success", "check")}<span class="tnum">42 ms</span></div></div><button class="icon-btn" type="button" aria-label="Relay options">${icon("more")}</button></div>
        <dl class="kv"><dt>Pinned key</dt><dd>SHA-256 7F3A 91C2 0B5E D44A…</dd><dt>Mailbox</dt><dd>rotates every 7 days</dd><dt>TURN</dt><dd>turn.example.org · 1 h credentials</dd></dl></div>
      <div class="card relay-card"><div class="rh"><span class="row-icon">${icon("server")}</span><div class="row-main"><div class="row-title">pi.home.arpa:8443</div><div class="row-sub hstack">${chip("Standby", "outline", "clock")}<span>Self-hosted</span></div></div><button class="icon-btn" type="button" aria-label="Relay options">${icon("more")}</button></div>
        <dl class="kv"><dt>Pinned key</dt><dd>SHA-256 C81D 44E0 9A2B 07F6…</dd></dl></div>
      <div class="stack-sm top-gap"><button class="btn btn-secondary btn-block" type="button">${icon("plus")}Add a relay</button><p class="hint center">Run your own on a Raspberry Pi or small VPS. See the setup guide.</p></div></div>`;
  }
  function settingsSecurity() {
    return html`<div class="settings-body">
      <h3 class="group-title">Locking</h3>
      <div class="group card">
        <div class="row"><div class="row-icon accent">${icon("clock")}</div><div class="row-main"><div class="row-title" id="al-l">Auto-lock after</div></div></div>
        <div class="row">${segmented("autolock", [{ v: "1", t: "1 min" }, { v: "5", t: "5 min" }, { v: "15", t: "15 min" }, { v: "60", t: "1 h" }], "5", "Auto-lock after")}</div>
        ${toggleRow({ id: "bglock", icon: "lock", tone: "accent", title: "Lock when Veil goes to background", on: true })}
        ${toggleRow({ id: "bio", icon: "fingerprint", tone: "accent", title: "Unlock with fingerprint", sub: "Your passphrase is still required after every restart.", on: true })}
        ${toggleRow({ id: "screens", icon: "eye-off", tone: "accent", title: "Block screenshots", sub: "Hides Veil in the app switcher and blocks screen capture.", on: true })}
        ${linkRow({ icon: "key", tone: "accent", title: "Change passphrase" })}
      </div>
      <h3 class="group-title">Encrypted backup</h3>
      <div class="group card">
        ${linkRow({ icon: "archive", tone: "accent", title: "Create backup", sub: "Last backup: 9 Oct · protected by its own passphrase" })}
        ${linkRow({ icon: "download", tone: "accent", title: "Restore from backup" })}
      </div>
      <h3 class="group-title">Danger zone</h3>
      <div class="card danger-card"><div class="row"><div class="row-icon danger">${icon("flame")}</div><div class="row-main"><div class="row-title">Panic wipe</div><div class="row-sub">Destroys your keys and every message on this device in under a second. This can't be undone.</div></div></div>
        <div class="row"><a class="btn btn-danger-ghost btn-block" href="#panic">${icon("flame")}Wipe this device…</a></div></div></div>`;
  }
  function panicDialog() {
    return html`<div class="scrim"><div class="dialog glass-strong" role="alertdialog" aria-modal="true" aria-labelledby="pw-t" aria-describedby="pw-d">
      <div class="state-art danger small-art"><span class="core">${icon("flame", "icon-xl")}</span></div>
      <h2 id="pw-t">Wipe everything?</h2>
      <p id="pw-d">Your identity keys and every message, file and contact on this device will be destroyed. It can't be undone. Only an encrypted backup can bring them back.</p>
      <div class="dialog-actions"><button class="btn btn-danger hold-btn" type="button" data-hold>${raw('<span class="fill"></span>')}<span>${icon("hand")} Press and hold to wipe</span></button><a class="btn btn-secondary" href="#settings-security">Cancel</a></div></div></div>`;
  }

  // ------------------------------------------------------- onboarding etc.
  function welcomeContent() {
    return html`<div class="onb welcome">
      <div class="onb-hero">${logo("lg")}<p class="wordmark">Veil</p></div>
      <div class="stack"><h1 class="onb-title">Private by design.<br>Yours by default.</h1>
        <ul class="feature-list">
          <li>${icon("users")}<span><b>No phone number, email or account</b><small>Your identity is a key that only exists on your devices.</small></span></li>
          <li>${icon("lock")}<span><b>End-to-end encrypted everything</b><small>Messages, files, voice notes and calls.</small></span></li>
          <li>${icon("shield")}<span><b>The relay sees sealed envelopes</b><small>Not what you say, and not who you're talking to.</small></span></li>
        </ul></div>
      <div class="onb-actions"><a class="btn btn-primary btn-block" href="#keygen">Create my identity</a><button class="btn btn-ghost btn-block" type="button">${icon("archive")}Restore from backup</button>
      <div class="pager" aria-label="Step 1 of 4"><i class="on"></i><i></i><i></i><i></i></div></div></div>`;
  }
  function keygenContent() {
    var parts = [];
    for (var k = 0; k < 10; k++) parts.push(raw('<span class="particle" data-a="' + k * 36 + '"></span>'));
    return html`<div class="onb keygen" data-keygen>
      <div class="onb-top"><a class="icon-btn" href="#welcome" aria-label="Back">${icon("back")}</a></div>
      <div class="keygen-orb" aria-hidden="true"><span class="glow"></span><span class="ring"></span><span class="ring r2"></span><span class="ring r3"></span>${parts}<span class="core">${icon("key", "icon-xl")}</span></div>
      <div class="stack center"><h1 class="onb-title sm" data-kg-title>Creating your identity…</h1>
        <p class="fingerprint" aria-live="polite" data-kg-fp>${D.me.fingerprint.slice(0, 4).join(" ")}<br>${D.me.fingerprint.slice(4).join(" ")}</p></div>
      <ol class="steps" aria-label="Progress">
        <li class="step" data-step="0"><span class="st">${icon("check")}</span>Generating identity key</li>
        <li class="step" data-step="1"><span class="st">${icon("check")}</span>Creating one-time prekeys</li>
        <li class="step" data-step="2"><span class="st">${icon("check")}</span>Sealing the encrypted vault</li></ol>
      <div class="onb-actions"><p class="hint center">${icon("lock", "icon-xs")} Keys are created on this device and never leave it.</p>
        <a class="btn btn-primary btn-block" href="#passphrase" data-kg-next aria-disabled="true">Continue</a><div class="pager" aria-label="Step 2 of 4"><i></i><i class="on"></i><i></i><i></i></div></div></div>`;
  }
  function passphraseContent() {
    return html`<form class="onb passphrase" data-pass autocomplete="off">
      <div class="onb-top"><a class="icon-btn" href="#keygen" aria-label="Back">${icon("back")}</a></div>
      <div class="stack"><h1 class="onb-title sm">Choose a passphrase</h1><p class="muted">It unlocks Veil and encrypts everything stored on this device. Four or more random words beat a short, complex password.</p></div>
      <div class="field"><label for="pp">Passphrase</label><div class="input"><input id="pp" type="password" value="lantern orbit maple quietly" aria-describedby="pp-m pp-h" autocomplete="new-password" data-pp><button class="icon-btn" type="button" aria-label="Show passphrase" aria-pressed="false" data-reveal>${icon("eye")}</button></div>
        <div class="meter" data-level="4" id="pp-m" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
        <div class="meter-label"><span id="pp-h">4 words · about 52 bits</span><strong data-pp-label>${icon("check", "icon-xs")}Strong</strong></div></div>
      <div class="field"><label for="pp2">Repeat passphrase</label><div class="input"><input id="pp2" type="password" value="lantern orbit maple quietly" autocomplete="new-password"></div></div>
      <div class="group card">${toggleRow({ id: "bio-onb", icon: "fingerprint", tone: "accent", title: "Also unlock with fingerprint", sub: "Passphrase still required after every restart.", on: true })}</div>
      <div class="banner warning slim">${icon("alert-triangle")}<p><b>No one can recover it for you.</b> Not us, not the relay. Without it, only an encrypted backup can restore your messages.</p></div>
      <div class="onb-actions"><a class="btn btn-primary btn-block" href="#protection">Continue</a><div class="pager" aria-label="Step 3 of 4"><i></i><i></i><i class="on"></i><i></i></div></div></form>`;
  }
  function protectionContent() {
    return html`<div class="onb protection">
      <div class="onb-top"><a class="icon-btn" href="#passphrase" aria-label="Back">${icon("back")}</a></div>
      <div class="stack"><h1 class="onb-title sm">What Veil protects, honestly</h1></div>
      <section class="card protect-card"><h2 class="protect-h yes">${icon("shield-check", "icon-sm")}Protected</h2><ul class="protect-list yes">
        <li><span class="pi">${icon("lock", "icon-sm")}</span><span>What you say<small>Messages, files, voice notes and calls are end-to-end encrypted.</small></span></li>
        <li><span class="pi">${icon("users", "icon-sm")}</span><span>Who you talk to<small>Hidden from the relay with sealed delivery and rotating mailboxes.</small></span></li>
        <li><span class="pi">${icon("globe", "icon-sm")}</span><span>Your IP address from contacts<small>Relay-only by default. Direct is your choice, per contact.</small></span></li>
        <li><span class="pi">${icon("archive", "icon-sm")}</span><span>Your data at rest<small>Encrypted with your passphrase and this device's secure keystore.</small></span></li></ul></section>
      <section class="card protect-card"><h2 class="protect-h no">${icon("alert-triangle", "icon-sm")}Not protected</h2><ul class="protect-list no">
        <li><span class="pi">${icon("wifi", "icon-sm")}</span><span>That you use Veil, and when<small>Your network and the relay can see you connect, and when.</small></span></li>
        <li><span class="pi">${icon("eye", "icon-sm")}</span><span>An unlocked or compromised device<small>Anyone holding your unlocked phone, or malware on it, can read your chats.</small></span></li>
        <li><span class="pi">${icon("image", "icon-sm")}</span><span>What others do with your messages<small>Recipients can screenshot or photograph them.</small></span></li>
        <li><span class="pi">${icon("globe", "icon-sm")}</span><span>Your IP in Direct mode<small>Contacts you allow Direct with can see your IP address.</small></span></li></ul></section>
      <div class="onb-actions"><a class="btn btn-primary btn-block" href="#chats">I understand · start messaging</a><div class="pager" aria-label="Step 4 of 4"><i></i><i></i><i></i><i class="on"></i></div></div></div>`;
  }
  function lockContent() {
    return html`<form class="onb lock" data-lock autocomplete="off">
      <div class="lock-hero">${logo("lg")}<h1 class="onb-title sm">Veil is locked</h1><p class="muted">Locked after 5 minutes of inactivity</p></div>
      <div class="stack"><div class="field"><label for="unlock-pp" class="sr-only">Passphrase</label><div class="input"><span class="lead-icon">${icon("key")}</span><input id="unlock-pp" type="password" placeholder="Passphrase" autocomplete="current-password"></div></div>
        <a class="btn btn-primary btn-block" href="#chats">Unlock</a>
        <a class="btn btn-secondary btn-block" href="#chats">${icon("fingerprint")}Use fingerprint</a></div>
      <details class="err-details forgot"><summary>Forgot your passphrase?</summary><p class="hint">It can't be reset or recovered, by anyone. You can restore an encrypted backup, or wipe this device and start over with a new identity.</p></details></form>`;
  }
  function chatsEmpty() {
    return html`<div class="state">
      <div class="state-art"><span class="orbit">${avatar(c("ada"), "sm")}</span><span class="core">${icon("chats", "icon-xl")}</span></div>
      <h2>No conversations yet</h2><p>Veil has no directory and no phone numbers. You add people by swapping codes, ideally face to face.</p>
      <div class="actions"><a class="btn btn-primary" href="#add">${icon("qr")}Show my code</a><a class="btn btn-secondary" href="#scan">${icon("scan")}Scan a code</a></div></div>`;
  }
  function errorContent() {
    return html`<div class="state" role="alert">
      <div class="state-art danger"><span class="core">${icon("server", "icon-xl")}</span></div>
      <h2>Can't reach your relay</h2><p>relay.example.org isn't responding. Your messages are safely queued on this device and will send when it's back. Nothing was lost.</p>
      <div class="actions"><button class="btn btn-primary" type="button">${icon("refresh")}Try again</button><a class="btn btn-secondary" href="#settings-relays">Relay settings</a></div>
      <details class="err-details"><summary>Technical details</summary><pre>relay.example.org:443  connect timeout after 10 s (attempt 4)\nPinned key check: not reached\nQueued locally: 3 messages, 1 attachment</pre></details></div>`;
  }
  function shortcutsDialog() {
    var rows = [["Ctrl", "K", "Search conversations"], ["Alt", "↑ / ↓", "Previous / next conversation"], ["Ctrl", "I", "Toggle info panel"], ["Ctrl", ",", "Settings"], ["Ctrl", "L", "Lock Veil now"], ["Esc", "", "Close panel or dialog"], ["?", "", "Show this list"]];
    return html`<div class="scrim"><div class="dialog glass-strong" role="dialog" aria-modal="true" aria-labelledby="ks-t">
      <div class="hstack"><h2 id="ks-t">Keyboard shortcuts</h2><span class="spacer"></span><a class="icon-btn" href="#chat:ada" aria-label="Close">${icon("x")}</a></div>
      <dl class="shortcuts">${rows.map(function (r) { return html`<dt><span class="kbd">${r[0]}</span>${r[1] ? html` <span class="kbd">${r[1]}</span>` : ""}</dt><dd>${r[2]}</dd>`; })}</dl></div></div>`;
  }

  window.VeilUI = {
    html: html, raw: raw, esc: esc, icon: icon, logo: logo, avatar: avatar, chip: chip, c: c,
    convList: convList, contactsList: contactsList, skeletonList: skeletonList,
    chatPane: chatPane, chatSkeleton: chatSkeleton, profileContent: profileContent, safetyContent: safetyContent,
    addContent: addContent, scanContent: scanContent, verifiedContent: verifiedContent, callContent: callContent,
    settingsNav: settingsNav, settingsMeCard: settingsMeCard, settingsPrivacy: settingsPrivacy, settingsAppearance: settingsAppearance,
    settingsRelays: settingsRelays, settingsSecurity: settingsSecurity, panicDialog: panicDialog,
    welcomeContent: welcomeContent, keygenContent: keygenContent, passphraseContent: passphraseContent,
    protectionContent: protectionContent, lockContent: lockContent, chatsEmpty: chatsEmpty, errorContent: errorContent,
    shortcutsDialog: shortcutsDialog, SETTINGS_NAV: SETTINGS_NAV,
  };
})();
