// Touch gestures on a message bubble: press and hold for its actions, swipe right to reply.
// Pointer events cover touch, pen and mouse alike; vertical moves stay with the browser (the
// bubble has `touch-action: pan-y`), so scrolling the conversation is unaffected.
import { useRef, useState, type MouseEvent, type PointerEvent } from "react";

/** How long a press must last to count as "hold". */
const HOLD_MS = 450;
/** Movement allowed before a press stops being a press. */
const SLOP_PX = 10;
/** How far a swipe must go to start a reply, and how far the bubble follows the finger. */
export const SWIPE_AT_PX = 56;
const SWIPE_MAX_PX = 80;

interface Press {
  id: number;
  x: number;
  y: number;
  timer: number | null;
  swiping: boolean;
  el: HTMLElement;
}

export interface BubbleGestures {
  /** How far the bubble is pulled to the right, in px (0 when idle). */
  dx: number;
  handlers: {
    onPointerDown: (e: PointerEvent<HTMLElement>) => void;
    onPointerMove: (e: PointerEvent<HTMLElement>) => void;
    onPointerUp: (e: PointerEvent<HTMLElement>) => void;
    onPointerCancel: (e: PointerEvent<HTMLElement>) => void;
    onClickCapture: (e: MouseEvent<HTMLElement>) => void;
    onContextMenu: (e: MouseEvent<HTMLElement>) => void;
  };
}

/**
 * `onHold` opens the message's actions (also on right-click); `onSwipe`, when given, starts
 * a reply. A hold swallows the click that follows it, so holding a photo does not also open
 * it.
 */
export function useBubbleGestures(onHold: (el: HTMLElement) => void, onSwipe: (() => void) | null): BubbleGestures {
  const [dx, setDx] = useState(0);
  const press = useRef<Press | null>(null);
  const pulled = useRef(0);
  const held = useRef(false);

  function stopTimer(p: Press) {
    if (p.timer !== null) window.clearTimeout(p.timer);
    p.timer = null;
  }

  function end(e: PointerEvent<HTMLElement>, completed: boolean) {
    const p = press.current;
    if (!p || p.id !== e.pointerId) return;
    stopTimer(p);
    if (p.swiping && completed && pulled.current >= SWIPE_AT_PX) onSwipe?.();
    press.current = null;
    pulled.current = 0;
    setDx(0);
  }

  return {
    dx,
    handlers: {
      onPointerDown(e) {
        if (e.button !== 0 || press.current) return;
        held.current = false;
        const el = e.currentTarget;
        const p: Press = { id: e.pointerId, x: e.clientX, y: e.clientY, timer: null, swiping: false, el };
        p.timer = window.setTimeout(() => {
          p.timer = null;
          held.current = true;
          press.current = null;
          navigator.vibrate?.(10);
          onHold(el);
        }, HOLD_MS);
        press.current = p;
      },
      onPointerMove(e) {
        const p = press.current;
        if (!p || p.id !== e.pointerId) return;
        const mx = e.clientX - p.x;
        const my = e.clientY - p.y;
        if (!p.swiping) {
          if (Math.abs(mx) < SLOP_PX && Math.abs(my) < SLOP_PX) return;
          stopTimer(p);
          // Mostly sideways and to the right: a reply swipe. Anything else is not ours.
          if (onSwipe && mx > 0 && Math.abs(mx) > Math.abs(my) * 1.5) {
            p.swiping = true;
            p.el.setPointerCapture(e.pointerId);
          } else {
            press.current = null;
            return;
          }
        }
        pulled.current = Math.max(0, Math.min(SWIPE_MAX_PX, mx));
        setDx(pulled.current);
      },
      onPointerUp: (e) => end(e, true),
      onPointerCancel: (e) => end(e, false),
      onClickCapture(e) {
        if (held.current) {
          e.preventDefault();
          e.stopPropagation();
          held.current = false;
        }
      },
      onContextMenu(e) {
        // Right-click on desktop; on Android the hold timer has usually fired already.
        e.preventDefault();
        if (held.current) return;
        const p = press.current;
        if (p) stopTimer(p);
        press.current = null;
        onHold(e.currentTarget);
      },
    },
  };
}
