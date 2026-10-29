// Profile pictures on screen (milestone 4.5, ADR-0020). Rust keeps them in the encrypted
// database and hands out `data:` URLs; a token from the views changes whenever a picture
// does, so a cached URL is never stale. Dropped when Veil locks.
import { useEffect, useState } from "react";
import { base64, ipc } from "./ipc";

const cache = new Map<string, Promise<string | null>>();

export function forgetPictures(): void {
  cache.clear();
}

/** A picture's URL: the user's own (`owner` null) or a contact's, for the given token. */
export function usePicture(owner: number | null, token: string | null): string | null {
  // Keyed, so an avatar that moves to another contact never shows the previous one's picture
  // while the new one loads (review PR-13).
  const key = token ? `${owner ?? "me"}:${token}` : null;
  const [state, setState] = useState<{ key: string; url: string | null } | null>(null);
  useEffect(() => {
    if (!key) return;
    let p = cache.get(key);
    if (!p) {
      p = ipc.picture(owner).catch(() => {
        cache.delete(key);
        return null;
      });
      cache.set(key, p);
    }
    let live = true;
    void p.then((u) => {
      if (live) setState({ key, url: u });
    });
    return () => {
      live = false;
    };
  }, [owner, key]);
  return key && state?.key === key ? state.url : null;
}

/** The largest file the webview will try to decode at all. */
const MAX_PICK_BYTES = 25 * 1024 * 1024;
/** Rust's limit (`content::MAX_PICTURE_LEN`): the picture travels inside one message. */
const MAX_PICTURE_BYTES = 48 * 1024;

/** Region of the source image to keep, in source pixels (a square). */
export interface Crop {
  x: number;
  y: number;
  size: number;
}

/** A picked picture, cropped square and redrawn as a JPEG of at most 512 px and 48 KiB.
 *  Redrawing drops its metadata (place, camera). Returns base64 for the IPC. */
export async function preparePicture(file: File, crop?: Crop): Promise<string> {
  if (file.size > MAX_PICK_BYTES) throw new Error("This picture is too large");
  const bitmap = await createImageBitmap(file);
  try {
    const c = crop ?? centreCrop(bitmap.width, bitmap.height);
    for (const side of [512, 384, 256]) {
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = Math.min(side, Math.round(c.size));
      const ctx = canvas.getContext("2d");
      if (!ctx) break;
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-1").trim();
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(bitmap, c.x, c.y, c.size, c.size, 0, 0, canvas.width, canvas.height);
      for (const q of [0.85, 0.7, 0.55]) {
        const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", q));
        if (blob && blob.size <= MAX_PICTURE_BYTES) return base64(new Uint8Array(await blob.arrayBuffer()));
      }
    }
  } finally {
    bitmap.close();
  }
  throw new Error("This picture could not be made small enough");
}

export function centreCrop(w: number, h: number): Crop {
  const size = Math.min(w, h);
  return { x: (w - size) / 2, y: (h - size) / 2, size };
}
