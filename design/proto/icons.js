/* Veil prototype icon set: 24px grid, 1.8 stroke, drawn for this prototype.
 * Injected once as an inline sprite so <use href="#i-…"> works over file://. */
(function () {
  "use strict";
  var P = {
    send: '<path d="M12 19V5"/><path d="M6 11l6-6 6 6"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11a6.5 6.5 0 0 0 13 0"/><path d="M12 17.5V21"/>',
    "mic-off": '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11a6.5 6.5 0 0 0 13 0"/><path d="M12 17.5V21"/><path d="M3 3l18 18"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    paperclip: '<path d="M20 11.5l-8.2 8.2a5 5 0 0 1-7.1-7.1l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7l-8.5 8.5a1.7 1.7 0 0 1-2.4-2.4L15 7"/>',
    image: '<rect x="3" y="4" width="18" height="16" rx="3"/><circle cx="9" cy="10" r="2"/><path d="M21 16l-5-5-9 9"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    play: '<path d="M8 5.5v13a1 1 0 0 0 1.5.9l10.4-6.5a1 1 0 0 0 0-1.8L9.5 4.6A1 1 0 0 0 8 5.5z"/>',
    pause: '<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>',
    phone: '<path d="M5 4h3.5l1.7 4.3-2.2 1.5a11 11 0 0 0 6.2 6.2l1.5-2.2L20 15.5V19a1.5 1.5 0 0 1-1.6 1.5A16.5 16.5 0 0 1 3.5 5.6 1.5 1.5 0 0 1 5 4z"/>',
    "phone-off": '<path d="M3 14.5c5-5 13-5 18 0l-2.2 2.2-3.3-1.6v-2.6a12 12 0 0 0-7 0v2.6l-3.3 1.6z"/>',
    video: '<rect x="3" y="6" width="13" height="12" rx="3"/><path d="M16 10.5l5-3v9l-5-3"/>',
    "video-off": '<rect x="3" y="6" width="13" height="12" rx="3"/><path d="M16 10.5l5-3v9l-5-3"/><path d="M2 2l20 20"/>',
    speaker: '<path d="M4 9.5h3.5L12 5.5v13l-4.5-4H4z"/><path d="M16 9a4 4 0 0 1 0 6"/><path d="M18.5 6.5a7.5 7.5 0 0 1 0 11"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.6v.2"/>',
    back: '<path d="M15 5l-7 7 7 7"/>',
    "chevron-right": '<path d="M9 5l7 7-7 7"/>',
    "chevron-down": '<path d="M5 9l7 7 7-7"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    qr: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><path d="M14 14h2v2h-2zM18 18h2v2h-2zM14 20h2M20 14v2"/>',
    scan: '<path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    share: '<path d="M12 4v11"/><path d="M8 8l4-4 4 4"/><path d="M5 13v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5"/>',
    shield: '<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8-7.5 9.5-4.4-1.5-7.5-4.9-7.5-9.5V6z"/>',
    "shield-check": '<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8-7.5 9.5-4.4-1.5-7.5-4.9-7.5-9.5V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    "shield-alert": '<path d="M12 3l7.5 3v5.5c0 4.6-3.1 8-7.5 9.5-4.4-1.5-7.5-4.9-7.5-9.5V6z"/><path d="M12 8v4.5"/><path d="M12 15.8v.2"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-2.6 3.5M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/><path d="M2 2l20 20"/>',
    lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
    fingerprint: '<path d="M7.5 19.5c1.2-2 1.8-4.4 1.8-7a2.7 2.7 0 0 1 5.4 0c0 1.5-.1 3-.4 4.4"/><path d="M4.5 15.5c.6-1.2.9-2.5.9-3.9a6.6 6.6 0 0 1 11.6-4.3"/><path d="M12 12.5c0 3-.7 5.8-2 8.2"/><path d="M18.5 10.5c.2 1.6.1 4.4-.6 6.8"/><path d="M14.4 20.5c.4-.9.7-1.9.9-2.9"/>',
    timer: '<circle cx="12" cy="13" r="7.5"/><path d="M12 9.5V13l2.5 2"/><path d="M9.5 2.5h5"/>',
    pin: '<path d="M9 4h6l-1 5 3 3v2H7v-2l3-3z"/><path d="M12 14v6"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "check-double": '<path d="M2.5 12.5l4 4L14.5 8.5"/><path d="M11 15.5l1 1 8.5-8.5"/>',
    clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    "alert-triangle": '<path d="M10.3 4.2L2.8 17.5A2 2 0 0 0 4.5 20.5h15a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.5"/><path d="M12 17.2v.2"/>',
    "alert-circle": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5.5"/><path d="M12 16.2v.2"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    chats: '<path d="M20 12a8 8 0 0 1-11.6 7.1L4 20l1-4.2A8 8 0 1 1 20 12z"/>',
    users: '<circle cx="9" cy="8.5" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 5.2a3.5 3.5 0 0 1 0 6.6"/><path d="M18 14.5a6.5 6.5 0 0 1 3.5 5.5"/>',
    "user-plus": '<circle cx="9" cy="8.5" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M19 8v6M16 11h6"/>',
    key: '<circle cx="7.5" cy="15.5" r="4"/><path d="M10.5 12.5L20 3"/><path d="M16 7l3 3"/><path d="M13.5 9.5l2 2"/>',
    "wifi-off": '<path d="M2 8.5a15 15 0 0 1 4.5-2.7"/><path d="M10.5 5.1A15 15 0 0 1 22 8.5"/><path d="M5 12a10 10 0 0 1 4-2.2"/><path d="M15.5 10.3A10 10 0 0 1 19 12"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><path d="M12 19.5v.2"/><path d="M3 3l18 18"/>',
    wifi: '<path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><path d="M12 19.5v.2"/>',
    refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5v.2M7 16.5v.2"/>',
    trash: '<path d="M4 7h16"/><path d="M9 7V4.5h6V7"/><path d="M6 7l1 12.5a2 2 0 0 0 2 1.5h6a2 2 0 0 0 2-1.5L18 7"/>',
    ban: '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
    bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
    "bell-off": '<path d="M6 16V11a6 6 0 0 1 9.4-4.9M18 11v5l1.5 2H8"/><path d="M10 20.5a2 2 0 0 0 4 0"/><path d="M3 3l18 18"/>',
    palette: '<path d="M12 3a9 9 0 1 0 0 18c1.2 0 1.8-.8 1.8-1.7 0-1.1-.9-1.4-.9-2.4 0-1 .8-1.6 1.8-1.6h2A4.3 4.3 0 0 0 21 11c0-4.4-4-8-9-8z"/><circle cx="7.5" cy="11" r="1"/><circle cx="10" cy="7" r="1"/><circle cx="14.5" cy="7" r="1"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6L6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    sparkle: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/>',
    download: '<path d="M12 4v11"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/>',
    upload: '<path d="M12 15V4"/><path d="M7 9l5-5 5 5"/><path d="M5 20h14"/>',
    flip: '<path d="M4 9a8 8 0 0 1 14-3l2 2"/><path d="M20 4v4h-4"/><path d="M20 15a8 8 0 0 1-14 3l-2-2"/><path d="M4 20v-4h4"/>',
    more: '<path d="M5 12h.2M12 12h.2M19 12h.2" stroke-width="3"/>',
    smile: '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 14a4.5 4.5 0 0 0 7 0"/><path d="M9 9.5v.2M15 9.5v.2"/>',
    reply: '<path d="M9 7L4 12l5 5"/><path d="M4 12h10a6 6 0 0 1 6 6v1"/>',
    flame: '<path d="M12 21a7 7 0 0 0 7-7c0-4-3-6.5-4-10-2 2-3 4-3 6-1-.8-1.7-2-2-3.5C7.5 9 5 11 5 14a7 7 0 0 0 7 7z"/>',
    archive: '<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v9a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9"/><path d="M10 13h4"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.5 2.6 3.5 5.5 3.5 8.5s-1 5.9-3.5 8.5c-2.5-2.6-3.5-5.5-3.5-8.5s1-5.9 3.5-8.5z"/>',
    route: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="12" cy="6" r="2"/><path d="M6.5 10.7l4-3.4M13.5 7.3l4 3.4"/>',
    type: '<path d="M4 7V5h10v2M9 5v14M7 19h4"/><path d="M14 12v-1.5h7V12M17.5 10.5V19M16 19h3"/>',
    keyboard: '<rect x="2.5" y="6" width="19" height="12" rx="2.5"/><path d="M6.5 10h.2M10 10h.2M13.5 10h.2M17 10h.2M7 14h10"/>',
    grip: '<path d="M9 6h.2M9 12h.2M9 18h.2M15 6h.2M15 12h.2M15 18h.2" stroke-width="2.6"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
    hand: '<path d="M8 13V5.5a1.5 1.5 0 0 1 3 0V11M11 10.5V4a1.5 1.5 0 0 1 3 0v6.5M14 10.5V6a1.5 1.5 0 0 1 3 0v8a7 7 0 0 1-7 7h-.5a6 6 0 0 1-4.6-2.2L2.8 16a1.6 1.6 0 0 1 2.4-2.1L8 16"/>',
    logout: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M9 8l-4 4 4 4"/><path d="M5 12h11"/>',
  };
  var FILLED = { play: 1, pause: 1 };
  var NS = "http://www.w3.org/2000/svg";
  function inject() {
    if (document.getElementById("veil-sprite")) return;
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("id", "veil-sprite");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("width", "0");
    svg.setAttribute("height", "0");
    svg.setAttribute("class", "sr-only");
    var markup = "";
    Object.keys(P).forEach(function (k) {
      markup += '<symbol id="i-' + k + '" viewBox="0 0 24 24">' + P[k] + "</symbol>";
    });
    svg.innerHTML = markup; // static, author-controlled markup only
    document.body.insertBefore(svg, document.body.firstChild);
  }
  window.VeilIcons = {
    names: Object.keys(P),
    inject: inject,
    filled: function (n) { return !!FILLED[n]; },
  };
})();
