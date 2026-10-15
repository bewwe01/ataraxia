/* Canonical screen list. Used by both shells (screen index) and by
 * design/tools/capture.mjs (screenshots + checks). Keep in sync with DESIGN.md. */
(function () {
  "use strict";
  window.VeilScreens = [
    { route: "welcome", title: "Welcome", group: "Onboarding", tablet: true },
    { route: "keygen", title: "Key generation", group: "Onboarding" },
    { route: "passphrase", title: "Set passphrase", group: "Onboarding" },
    { route: "protection", title: "What's protected", group: "Onboarding" },
    { route: "lock", title: "Lock screen", group: "Lock" },
    { route: "chats", title: "Conversation list", group: "Conversations", tablet: true },
    { route: "chat:ada", title: "Chat (verified, rich)", group: "Conversations", tablet: true },
    { route: "chat:mira", title: "Chat (direct mode)", group: "Conversations" },
    { route: "chat-empty:jonas", title: "New chat (unverified)", group: "Conversations" },
    { route: "contacts", title: "Contacts", group: "Conversations" },
    { route: "add", title: "Add contact: my code", group: "Pairing", tablet: true },
    { route: "scan", title: "Add contact: scan", group: "Pairing" },
    { route: "verified", title: "Verified success", group: "Pairing" },
    { route: "profile:ada", title: "Contact profile", group: "Trust", tablet: true },
    { route: "safety:jonas", title: "Safety number (unverified)", group: "Trust" },
    { route: "safety:ada", title: "Safety number (verified)", group: "Trust" },
    { route: "call-audio:ada", title: "Voice call · relayed", group: "Calls", tablet: true },
    { route: "call-video:mira", title: "Video call · direct", group: "Calls" },
    { route: "settings", title: "Settings", group: "Settings" },
    { route: "settings-privacy", title: "Privacy", group: "Settings", tablet: true },
    { route: "settings-appearance", title: "Appearance", group: "Settings" },
    { route: "settings-relays", title: "Relay servers", group: "Settings" },
    { route: "settings-security", title: "Security", group: "Settings" },
    { route: "panic", title: "Panic wipe confirm", group: "Settings" },
    { route: "chats-empty", title: "Empty", group: "States" },
    { route: "chats-loading", title: "Loading skeletons", group: "States", tablet: true },
    { route: "chats-offline", title: "Reconnecting", group: "States" },
    { route: "chat-offline:theo", title: "Offline + message failed", group: "States" },
    { route: "chat-keychange:lena", title: "Key changed warning", group: "States", tablet: true },
    { route: "error", title: "Relay unreachable", group: "States" },
    { route: "shortcuts", title: "Keyboard shortcuts", group: "Desktop", desktopOnly: true },
  ];
})();
