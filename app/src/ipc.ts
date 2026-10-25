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
}

export type MessageStatus = "sending" | "sent" | "failed" | "received";

export interface MessageView {
  id: number;
  mine: boolean;
  text: string;
  atMs: number;
  status: MessageStatus;
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
};

/** Something changed on the Rust side; the payload names what, never content. */
export type ChangeKind = "contacts" | "messages" | "connection" | "locked";

export function onChange(handler: (kind: ChangeKind, contact: number | null) => void): Promise<UnlistenFn> {
  return listen<{ kind: ChangeKind; contact: number | null }>("veil://changed", (e) => {
    handler(e.payload.kind, e.payload.contact);
  });
}
