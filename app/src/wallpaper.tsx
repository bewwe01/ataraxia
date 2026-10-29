// Chat wallpapers (milestone 4.5, ADR-0019): the default one, each chat's own, and their photos.
// Rust keeps them in the encrypted database; this module only holds what is on screen.
import { useEffect, useState, useSyncExternalStore } from "react";
import { base64, ipc, type ContactView, type WallpaperInput, type WallpaperView } from "./ipc";

let global: WallpaperView | null = null;
const listeners = new Set<() => void>();
/** Photo `data:` URLs by owner ("0" default, else the contact id), until changed here. */
const photos = new Map<string, Promise<string | null>>();

function emit() {
  for (const fn of [...listeners]) fn();
}

/** Reads the default wallpaper again (after unlock, or after it changed). */
export async function refreshWallpaper(): Promise<void> {
  try {
    global = await ipc.wallpaper();
  } catch {
    global = null;
  }
  photos.delete("0");
  emit();
}

/** Forgets everything (Veil locked). */
export function forgetWallpapers(): void {
  global = null;
  photos.clear();
  emit();
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useDefaultWallpaper(): WallpaperView | null {
  return useSyncExternalStore(subscribe, () => global);
}

/** Sets a chat's (or with null, the default) wallpaper, then refreshes what is shown. */
export async function saveWallpaper(contact: number | null, w: WallpaperInput | null): Promise<void> {
  await ipc.setWallpaper(contact, w);
  photos.delete(contact === null ? "0" : String(contact));
  if (contact === null) await refreshWallpaper();
  else emit();
}

function photo(owner: number | null): Promise<string | null> {
  const key = owner === null ? "0" : String(owner);
  let p = photos.get(key);
  if (!p) {
    p = ipc.wallpaperPhoto(owner).catch(() => null);
    photos.set(key, p);
  }
  return p;
}

/** What a chat shows: its own wallpaper or the default, with the photo when there is one. */
export function useChatWallpaper(contact: ContactView | null): { w: WallpaperView | null; photoUrl: string | null } {
  const def = useDefaultWallpaper();
  const own = contact?.wallpaper ?? null;
  const w = own ?? def;
  const owner = own ? (contact?.id ?? null) : null;
  const [photoUrl, setPhotoUrl] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => subscribe(() => setTick((t) => t + 1)), []);
  useEffect(() => {
    let live = true;
    if (!w?.photo) {
      setPhotoUrl(null);
      return;
    }
    void photo(owner).then((u) => {
      if (live) setPhotoUrl(u);
    });
    return () => {
      live = false;
    };
  }, [w?.photo, owner, tick]);
  return { w, photoUrl: w?.photo ? photoUrl : null };
}

/** A picked photo, made small and stripped: redrawn at most 1600 px on its long side and saved
 *  as JPEG, which also drops its metadata (place, camera). Returns base64 for the IPC. */
export async function preparePhoto(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("This picture could not be read");
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.85));
  if (!blob) throw new Error("This picture could not be read");
  return base64(new Uint8Array(await blob.arrayBuffer()));
}

/** The wallpaper layer behind a chat (or a preview of one). */
export function WallpaperLayer({ w, photoUrl }: { w: WallpaperView | null; photoUrl: string | null }) {
  if (!w || (w.photo && !photoUrl)) return null;
  const style: Record<string, string> = { "--wp-dim": String(w.dim / 100), "--wp-blur": `${w.blur}px` };
  if (w.photo && photoUrl) style["--wp-photo"] = `url("${photoUrl}")`;
  return <div className="chat-wallpaper" data-wp={w.photo ? "photo" : (w.preset ?? undefined)} style={style} aria-hidden="true" />;
}

export function ChatWallpaper({ contact }: { contact: ContactView }) {
  const { w, photoUrl } = useChatWallpaper(contact);
  return <WallpaperLayer w={w} photoUrl={photoUrl} />;
}
