// QR scanner (DESIGN.md §6 `<QrScanner>`): the camera feed is decoded on this device with
// jsQR, a few times a second. Frames never leave the device and are never stored. The stream
// stops as soon as a code is read or the scanner closes.
import jsQR from "jsqr";
import { useEffect, useRef, useState } from "react";
import { Banner } from "../ui";

/** Longest side of the frame handed to the decoder: enough for a phone-held QR code. */
const DECODE_PX = 640;
const EVERY_MS = 200;

export function Scanner({ hint, onCode }: { hint: string; onCode: (text: string) => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const [error, setError] = useState<string | null>(null);
  const done = useRef(onCode);
  done.current = onCode;

  useEffect(() => {
    let stream: MediaStream | null = null;
    let timer = 0;
    let stopped = false;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const stop = () => {
      stopped = true;
      window.clearInterval(timer);
      for (const t of stream?.getTracks() ?? []) t.stop();
      stream = null;
    };

    const tick = () => {
      const v = video.current;
      if (stopped || !v || !ctx || v.readyState < 2 || v.videoWidth === 0) return;
      const scale = Math.min(1, DECODE_PX / Math.max(v.videoWidth, v.videoHeight));
      canvas.width = Math.round(v.videoWidth * scale);
      canvas.height = Math.round(v.videoHeight * scale);
      ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (code && code.data) {
        stop();
        done.current(code.data);
      }
    };

    if (!navigator.mediaDevices?.getUserMedia) {
      setError("This device has no camera Veil can use.");
      return stop;
    }
    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: "environment" }, audio: false })
      .then(async (s) => {
        if (stopped) {
          for (const t of s.getTracks()) t.stop();
          return;
        }
        stream = s;
        const v = video.current;
        if (!v) return;
        v.srcObject = s;
        await v.play().catch(() => undefined);
        timer = window.setInterval(tick, EVERY_MS);
      })
      .catch(() => setError("Veil could not use the camera. Allow camera access for Veil in your device's settings, then try again."));
    return stop;
  }, []);

  if (error) return <Banner tone="warning" icon="alert-triangle"><p>{error}</p></Banner>;
  return (
    <div className="scanner" role="img" aria-label="Camera viewfinder">
      <video ref={video} className="scanner-feed" muted playsInline aria-hidden="true" />
      <span className="frame"><i></i><i></i><i></i><i></i></span>
      <span className="line"></span>
      <span className="hint-pill">{hint}</span>
    </div>
  );
}
