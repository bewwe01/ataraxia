// The only module that talks to the Rust side (CLAUDE.md: "All IPC goes through one typed
// module"). It mirrors `app/src-tauri/src/lib.rs`. Everything that crosses this boundary is
// display data: no key material, no ciphertext, no file paths.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type AppState = "new" | "locked" | "unlocked";
export type Connection = "online" | "connecting" | "offline";

export interface Me {
  name: string;
  fingerprint: string;
  relay: string;
  connection: Connection;
}

export interface ContactView {
  id: number;
  name: string;
  verified: boolean;
  initials: string;
  hue: number;
  lastText: string | null;
  lastMine: boolean;
  lastAtMs: number | null;
  unread: number;
  blocked: boolean;
  /** Disappearing-message timer in seconds; 0 is off. */
  timerSecs: number;
  /** Arrived with the same name as an existing contact, under a different key. */
  keyWarning: boolean;
  /** Unblocked, but they have not received their new address yet. */
  unblockPending: boolean;
  /** With a key warning: the earlier contact "It's them" would merge here (null: unclear). */
  previous: { id: number; name: string; verified: boolean; blocked: boolean; lastAtMs: number | null } | null;
}

export type MessageStatus = "sending" | "sent" | "failed" | "delivered" | "read" | "received";

export interface MessageView {
  id: number;
  mine: boolean;
  /** "timer" is a notice that the disappearing-message timer changed; "call" a call line. */
  kind: "text" | "timer" | "attachment" | "call";
  text: string;
  atMs: number;
  status: MessageStatus;
  timerSecs: number | null;
  expiresAtMs: number | null;
  /** The message this one answers. `text` is empty when that message is gone or deleted. */
  /** `mine` is null when the quoted message is gone from this device (author unknown). */
  reply: { id: number | null; mine: boolean | null; text: string } | null;
  reactions: { emoji: string; mine: boolean }[];
  edited: boolean;
  /** Deleted for everyone: show a placeholder. */
  deleted: boolean;
  /** Can be replied to and reacted to. */
  actionable: boolean;
  attachment: AttachmentView | null;
  /** For a call line: how the call went (kept on this device only). */
  call: CallLogView | null;
}

export type CallOutcome = "ended" | "missed" | "declined" | "unanswered" | "busy" | "cancelled" | "failed";

export interface CallLogView {
  video: boolean;
  outcome: CallOutcome;
  /** How long it was connected (0 unless "ended"). */
  durationSecs: number;
}

export interface AttachmentView {
  kind: "image" | "file" | "voice";
  mime: string;
  name: string | null;
  size: number;
  /** `available`: past the daily automatic-download allowance; the user taps to download. */
  state: "uploading" | "sent" | "downloading" | "ready" | "failed" | "too_large" | "available";
  /** 0 to 1 while uploading or downloading. */
  progress: number;
  durationMs: number | null;
  waveform: number[];
  /** Small JPEG preview. */
  thumbnail: number[] | null;
}

/** What `media.ts` prepares for sending. */
export interface OutgoingAttachment {
  kind: "image" | "file" | "voice";
  mime: string;
  name: string | null;
  data: Uint8Array;
  thumbnail: Uint8Array | null;
  durationMs: number | null;
  waveform: Uint8Array | null;
}

export interface SearchHit {
  contact: number;
  contactName: string;
  message: number;
  mine: boolean;
  snippet: string;
  atMs: number;
}

/** Own messages can be edited or deleted for everyone this long after sending. */
export const EDIT_WINDOW_MS = 24 * 3600 * 1000;

/** Notifications never name the sender or show text. */
export interface NotifySettings {
  enabled: boolean;
  /** Android: the system lets Veil post notifications. Always true elsewhere. */
  systemAllowed: boolean;
  /** Whether the background-connection option exists here (Android). */
  backgroundSetting: boolean;
  background: boolean;
}

/** Both off unless the user turns them on. */
export interface PrivacyView {
  readReceipts: boolean;
  typing: boolean;
}

export interface InviteView {
  link: string;
  /** QR modules, row-major, `size × size` characters of '1' (dark) and '0'. */
  qrModules: string;
  qrSize: number;
  expiresAtMs: number;
}

export interface SafetyView {
  groups: string[];
  verified: boolean;
  name: string;
  /** QR code of the scannable safety number, for the other phone to scan. */
  qrModules: string;
  qrSize: number;
}

export type SecretKind = "pin" | "password";

export interface SetupInput {
  relay: string;
  pin: string;
  name: string;
  kind: SecretKind;
  passphrase: string;
}

/** What the locked screen needs. */
export interface UnlockInfo {
  kind: SecretKind;
  biometric: boolean;
  waitSecs: number;
}

export interface SecurityView {
  kind: SecretKind;
  biometric: boolean;
  purgeSet: boolean;
}

/** What this device offers. */
export interface NativeInfo {
  android: boolean;
  biometric: boolean;
  screenshotSetting: boolean;
  screenshotsAllowed: boolean;
}

/** Errors from Rust are short, content-free strings (see `commands.rs`). */
export class IpcError extends Error {}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw new IpcError(typeof e === "string" ? e : "Something went wrong");
  }
}

const PART_BYTES = 1024 * 1024;

function base64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/**
 * A file goes to Rust in 1 MiB base64 parts: Android's IPC carries JSON only, so one raw body
 * is not an option there (see `attachment_begin` in `lib.rs`).
 */
async function sendOne(contact: number, a: OutgoingAttachment): Promise<MessageView> {
  const upload = await call<number>("attachment_begin", {
    meta: {
      contact,
      kind: a.kind,
      mime: a.mime,
      name: a.name,
      durationMs: a.durationMs,
      waveform: a.waveform ? Array.from(a.waveform) : null,
      thumbnail: a.thumbnail ? Array.from(a.thumbnail) : null,
    },
  });
  try {
    for (let at = 0; at < a.data.byteLength; at += PART_BYTES) {
      await call<void>("attachment_part", { upload, part: base64(a.data.subarray(at, at + PART_BYTES)) });
    }
  } catch (e) {
    await call<void>("attachment_abort", { upload }).catch(() => undefined);
    throw e;
  }
  return call<MessageView>("attachment_commit", { upload });
}

/** Rust holds one upload at a time, so sends from any chat take turns (review M3R2-1). */
let sending: Promise<unknown> = Promise.resolve();
function sendAttachment(contact: number, a: OutgoingAttachment): Promise<MessageView> {
  const run = sending.then(() => sendOne(contact, a), () => sendOne(contact, a));
  sending = run.catch(() => undefined);
  return run;
}

/** How every invite link starts (Rust's `veil_core::invite::LINK_PREFIX`). */
export const INVITE_PREFIX = "veil://i/";

export const ipc = {
  callSetup: (contact: number) => call<CallSetup>("call_setup", { contact }),
  /** `offer`/`answer` carry the webview's SDP; Rust filters it to relay-only before sending. */
  callSend: (contact: number, callId: string, kind: "offer" | "answer" | "hangup" | "busy", sdp: string | null = null) =>
    call<void>("call_send", { contact, callId, kind, sdp }),
  callSignals: () => call<CallSignal[]>("call_signals"),
  callLog: (contact: number, outgoing: boolean, video: boolean, outcome: CallOutcome, secs: number) =>
    call<void>("call_log", { contact, outgoing, video, outcome, secs }),
  callAudio: (active: boolean, speaker: boolean) => call<void>("call_audio", { active, speaker }),
  cancelCallNotice: () => call<void>("cancel_call_notice"),
  state: () => call<AppState>("app_state"),
  setup: (input: SetupInput) => call<void>("setup", { input }),
  unlock: (passphrase: string) => call<void>("unlock", { passphrase }),
  lock: () => call<void>("lock"),
  unlockInfo: () => call<UnlockInfo>("unlock_info"),
  unlockBiometric: () => call<void>("unlock_biometric"),
  security: () => call<SecurityView>("security"),
  changeSecret: (current: string, kind: SecretKind, next: string) => call<void>("change_secret", { current, kind, next }),
  /** The Purge PIN: entered at the lock screen, it deletes everything in Veil. */
  setPurge: (current: string, purge: string) => call<void>("set_purge", { current, purge }),
  clearPurge: (current: string) => call<void>("clear_purge", { current }),
  nativeInfo: () => call<NativeInfo>("native_info"),
  biometricEnable: (current: string) => call<void>("biometric_enable", { current }),
  biometricDisable: () => call<void>("biometric_disable"),
  setScreenshotsAllowed: (allow: boolean) => call<void>("set_screenshots_allowed", { allow }),
  /** Android: colours the status and navigation bars to match the theme. No-op elsewhere. */
  setDarkBars: (dark: boolean) => call<void>("set_dark_bars", { dark }),
  /** The user did something; postpones auto-lock. Event-driven refreshes must not call it. */
  touch: () => call<void>("touch"),
  /** Deletes the identity, contacts, messages and device secret. Cannot be undone. */
  reset: () => call<void>("reset"),
  /** "Erase everything" (Settings): the Purge PIN's effect, after the current PIN or password. */
  /** Resolves `false` if some file could not be deleted (the rest was erased anyway). */
  purgeAll: (current: string) => call<boolean>("purge_all", { current }),
  /** After a key-change warning: move the earlier conversation here, remove the old contact. */
  acceptKeyChange: (contact: number, previous: number) => call<void>("accept_key_change", { contact, previous }),
  me: () => call<Me>("me"),
  contacts: () => call<ContactView[]>("contacts"),
  messages: (contact: number) => call<MessageView[]>("messages", { contact }),
  send: (contact: number, text: string) => call<MessageView>("send", { contact, text }),
  reply: (contact: number, text: string, to: number) => call<MessageView>("reply", { contact, text, to }),
  /** Adds (`on`) or removes one of our reactions; up to 3 different ones per message. */
  react: (message: number, emoji: string, on: boolean) => call<void>("react", { message, emoji, on }),
  editMessage: (message: number, text: string) => call<void>("edit_message", { message, text }),
  deleteForEveryone: (message: number) => call<void>("delete_for_everyone", { message }),
  deleteForMe: (message: number) => call<void>("delete_for_me", { message }),
  /** Searches message text on this device only. */
  search: (query: string) => call<SearchHit[]>("search", { query }),
  /** Checks a code scanned from the contact's phone; `true` means it matched and they are now verified. */
  verifyScanned: (contact: number, code: string) => call<boolean>("verify_scanned", { contact, code }),
  /** Encrypts and uploads a photo, file or voice note; the message goes out when it is uploaded. */
  sendAttachment,
  /** The file of an attachment that is here, to show, play or save. */
  attachmentData: (message: number) => call<ArrayBuffer>("attachment_data", { message }),
  /** Android: the system "save as" screen. Elsewhere this fails with "Unsupported". */
  saveAttachment: (message: number) => call<void>("save_attachment", { message }),
  retryAttachment: (message: number) => call<void>("retry_attachment", { message }),
  notifySettings: () => call<NotifySettings>("notify_settings"),
  /** On Android, turning it on also asks for the system permission if needed. */
  /** Once after unlock: Android asks for the notification permission the first time. */
  notifyWelcome: () => call<void>("notify_welcome"),
  setNotify: (enabled: boolean) => call<void>("set_notify", { enabled }),
  /** Android: keep Veil connected in the background (a foreground service). */
  setBackground: (on: boolean) => call<void>("set_background", { on }),
  markRead: (contact: number) => call<void>("mark_read", { contact }),
  createInvite: () => call<InviteView>("create_invite"),
  acceptInvite: (link: string) => call<ContactView>("accept_invite", { link }),
  safety: (contact: number) => call<SafetyView>("safety_number", { contact }),
  setVerified: (contact: number, verified: boolean) => call<void>("set_verified", { contact, verified }),
  rename: (contact: number, name: string) => call<void>("rename_contact", { contact, name }),
  /** Deletes the contact, the conversation and the session. Cannot be undone. */
  deleteContact: (contact: number) => call<void>("delete_contact", { contact }),
  setBlocked: (contact: number, blocked: boolean) => call<void>("set_blocked", { contact, blocked }),
  setTimer: (contact: number, secs: number) => call<void>("set_timer", { contact, secs }),
  dismissKeyWarning: (contact: number) => call<void>("dismiss_key_warning", { contact }),
  privacy: () => call<PrivacyView>("privacy"),
  setPrivacy: (privacy: PrivacyView) => call<void>("set_privacy", { privacy }),
  /** The user is typing or stopped; Rust sends it only if typing indicators are on. */
  typing: (contact: number, started: boolean) => call<void>("typing", { contact, started }),
};

/** The disappearing-message timers offered, in seconds. */
export const TIMERS: [number, string, string][] = [
  [0, "Off", "Off"],
  [300, "5 minutes", "5m"],
  [3600, "1 hour", "1h"],
  [86400, "1 day", "1d"],
  [604800, "1 week", "1w"],
  [2419200, "4 weeks", "4w"],
];

export function timerName(secs: number): string {
  const t = TIMERS.find(([s]) => s === secs);
  if (t) return t[1];
  if (secs % 86400 === 0) return `${secs / 86400} days`;
  if (secs % 3600 === 0) return `${secs / 3600} hours`;
  if (secs % 60 === 0) return `${secs / 60} minutes`;
  return `${secs} seconds`;
}

export function timerShort(secs: number): string {
  return TIMERS.find(([s]) => s === secs)?.[2] ?? timerName(secs);
}

/** Something changed on the Rust side; the payload names what, never content. */
export type ChangeKind = "contacts" | "messages" | "connection" | "locked" | "typing" | "typingstopped" | "incoming" | "call" | "ringing";

/** TURN servers for one call (ADR-0018); the webview uses them relay-only. */
export interface CallSetup {
  iceServers: { urls: string[]; username: string; credential: string }[];
}

/** A call signal from a contact, already filtered by Rust. */
export interface CallSignal {
  contact: number;
  callId: string;
  kind: "offer" | "answer" | "hangup" | "busy";
  sdp: string | null;
  video: boolean;
}

export function onChange(handler: (kind: ChangeKind, contact: number | null) => void): Promise<UnlistenFn> {
  return listen<{ kind: ChangeKind; contact: number | null }>("veil://changed", (e) => {
    handler(e.payload.kind, e.payload.contact);
  });
}
