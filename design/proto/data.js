/* Fictional sample data for the prototype. No real people, keys or servers. */
(function () {
  "use strict";
  var contacts = {
    ada: {
      id: "ada", name: "Ada Okafor", first: "Ada", initials: "AO", hue: 0,
      verified: true, verifiedHow: "In person", verifiedOn: "12 Oct",
      conn: "online", transport: "relay", timer: "1 day", timerShort: "1d", pinned: true,
      last: "Told you the light at the pier would be worth it ✨", lastMine: true, time: "14:06", unread: 0,
    },
    mira: {
      id: "mira", name: "Mira Sato", first: "Mira", initials: "MS", hue: 2,
      verified: true, verifiedHow: "In person", verifiedOn: "3 Sep",
      conn: "online", transport: "direct", pinned: true,
      last: "Voice note (0:42)", lastIcon: "mic", time: "13:48", unread: 3,
    },
    jonas: {
      id: "jonas", name: "Jonas Weber", first: "Jonas", initials: "JW", hue: 1,
      verified: false, verifiedHow: "Invite link",
      conn: "online", transport: "relay", typing: true,
      last: "Thanks for the invite!", time: "13:40", unread: 0,
    },
    lena: {
      id: "lena", name: "Lena Park", first: "Lena", initials: "LP", hue: 5,
      verified: false, wasVerified: true, keyChanged: true, keyChangedOn: "Today, 12:15",
      conn: "connecting", transport: "relay",
      last: "Safety number changed", time: "12:15", unread: 1,
    },
    noor: {
      id: "noor", name: "Noor Haddad", first: "Noor", initials: "NH", hue: 3,
      verified: true, verifiedHow: "In person", verifiedOn: "21 Aug",
      conn: "offline", transport: "relay", muted: true,
      last: "Photo", lastIcon: "image", time: "Tue", unread: 12,
    },
    sam: {
      id: "sam", name: "Sam Rivera", first: "Sam", initials: "SR", hue: 6,
      verified: true, verifiedHow: "Safety number", verifiedOn: "2 Oct",
      conn: "offline", transport: "relay", timer: "1 hour", timerShort: "1h",
      last: "Okay, this disappears in an hour", time: "Mon", unread: 0,
    },
    theo: {
      id: "theo", name: "Theo Marchetti", first: "Theo", initials: "TM", hue: 4,
      verified: false, verifiedHow: "Invite link",
      conn: "offline", transport: "relay",
      last: "See you then", lastMine: true, lastStatus: "read", time: "Sun", unread: 0,
    },
  };

  // Deterministic pseudo-random for stable fake safety numbers / waveforms.
  function seeded(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return function () {
      h += 0x6d2b79f5;
      var t = h;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function safetyNumber(id) {
    var r = seeded("safety:" + id), out = [];
    for (var g = 0; g < 12; g++) {
      var s = "";
      for (var d = 0; d < 5; d++) s += Math.floor(r() * 10);
      out.push(s);
    }
    return out;
  }
  function wave(id, n) {
    var r = seeded("wave:" + id), out = [];
    for (var i = 0; i < n; i++) {
      var env = Math.sin((i / n) * Math.PI) * 0.6 + 0.4;
      out.push(Math.max(0.12, Math.min(1, env * (0.35 + r() * 0.75))));
    }
    return out;
  }

  window.VeilData = {
    me: {
      name: "You", initials: "ME",
      fingerprint: ["7F3A", "91C2", "0B5E", "D44A", "18C3", "6E07", "A9F2", "3B10"],
      invite: "veil://i/2Kq9vX7mPZr4tH8bNcL1wQe6YfDu3sJgA5oT0kVnRiE?r=relay.example.org&x=1729000000",
    },
    contacts: contacts,
    order: ["ada", "mira", "jonas", "lena", "noor", "sam", "theo"],
    safetyNumber: safetyNumber,
    wave: wave,
    seeded: seeded,
  };
})();
