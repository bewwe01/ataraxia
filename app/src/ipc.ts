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
}

export type MessageStatus = "sending" | "sent" | "failed" | "delivered" | "read" | "received";

export interface MessageView {
  id: number;
  mine: boolean;
  /** "timer" is a notice that the disappearing-message timer changed. */
  kind: "text" | "timer";
  text: string;
  atMs: number;
  status: MessageStatus;
  timerSecs: number | null;
  expiresAtMs: number | null;
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

export const ipc = {
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
  me: () => call<Me>("me"),
  contacts: () => call<ContactView[]>("contacts"),
  messages: (contact: number) => call<MessageView[]>("messages", { contact }),
  send: (contact: number, text: string) => call<MessageView>("send", { contact, text }),
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
export type ChangeKind = "contacts" | "messages" | "connection" | "locked" | "typing" | "typingstopped";

export function onChange(handler: (kind: ChangeKind, contact: number | null) => void): Promise<UnlistenFn> {
  return listen<{ kind: ChangeKind; contact: number | null }>("veil://changed", (e) => {
    handler(e.payload.kind, e.payload.contact);
  });
}
