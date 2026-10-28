// UI primitives ported from design/proto/ui.js (DESIGN.md §6). All text is rendered as React
// text nodes; nothing is ever inserted as HTML.
import { useEffect, type ReactNode, type RefObject } from "react";

export function Icon({ name, className = "" }: { name: string; className?: string }) {
  return (
    <svg className={`icon ${className}`} aria-hidden="true" focusable="false">
      <use href={`/icons.svg#i-${name}`} />
    </svg>
  );
}

export function Logo({ className = "" }: { className?: string }) {
  return (
    <svg className={`logo ${className}`} viewBox="0 0 48 48" aria-hidden="true">
      <defs>
        <linearGradient id="veil-logo-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#4338ff" />
          <stop offset=".55" stopColor="#8b3dff" />
          <stop offset="1" stopColor="#00b8d9" />
        </linearGradient>
      </defs>
      <rect width="48" height="48" rx="15" fill="url(#veil-logo-g)" />
      <path d="M13 15c5 0 8.5 7 11 19 2.5-12 6-19 11-19" fill="none" stroke="#fff" strokeWidth="3.6" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M13 15c4 3 7 3 11 3s7 0 11-3" fill="none" stroke="#fff" strokeOpacity=".55" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  );
}

export function Avatar({ initials, hue, size = "" }: { initials: string; hue: number; size?: string }) {
  return (
    <span className={`avatar ${size} hue-${hue}`} aria-hidden="true">
      <span className="face">{initials}</span>
    </span>
  );
}

export function VerifiedMark({ verified }: { verified: boolean }) {
  if (!verified) return null;
  return (
    <span className="verified-mark" title="Verified">
      <Icon name="shield-check" />
      <span className="sr-only">Verified</span>
    </span>
  );
}

/** Renders QR modules computed in Rust as SVG rectangles (no HTML injection, no remote encoder). */
export function QrCode({ modules, size, label }: { modules: string; size: number; label: string }) {
  const quiet = 4;
  const dim = size + quiet * 2;
  const rects: ReactNode[] = [];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules.charCodeAt(y * size + x) === 49) {
        rects.push(<rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width="1" height="1" />);
      }
    }
  }
  return (
    <svg className="qr-svg" viewBox={`0 0 ${dim} ${dim}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={dim} height={dim} fill="#fff" />
      <g fill="#000">{rects}</g>
    </svg>
  );
}

export function TopBar({ title, onBack, actions }: { title: string; onBack?: () => void; actions?: ReactNode }) {
  return (
    <header className="m-topbar glass">
      {onBack ? (
        <button className="icon-btn" type="button" aria-label="Back" onClick={onBack}>
          <Icon name="back" />
        </button>
      ) : null}
      <h1>{title}</h1>
      <span className="spacer" />
      {actions}
    </header>
  );
}

export function Banner({ tone, icon, children }: { tone: "info" | "warning" | "danger" | "neutral"; icon: string; children: ReactNode }) {
  return (
    <div className={`banner ${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <Icon name={icon} />
      <div>{children}</div>
    </div>
  );
}

export function timeLabel(ms: number | null): string {
  if (ms === null) return "";
  const d = new Date(ms);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** PIN or password field. A PIN gets the number keyboard. Only new PINs drop non-digits:
 *  a field that checks an existing secret accepts anything, so a mismatch between the stored
 *  kind and the real secret can never lock the owner out (review U-5). */
export function SecretField({ id, label, kind, value, onChange, autoComplete, autoFocus = false }: {
  id: string;
  label: string;
  kind: "pin" | "password";
  value: string;
  onChange: (v: string) => void;
  autoComplete: "new-password" | "current-password";
  autoFocus?: boolean;
}) {
  const pin = kind === "pin";
  const strict = pin && autoComplete === "new-password";
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className={`input${pin ? " pin-input" : ""}`}>
        <input
          id={id}
          type="password"
          inputMode={pin ? "numeric" : "text"}
          pattern={pin ? "[0-9]*" : undefined}
          maxLength={strict ? 16 : 1024}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          spellCheck={false}
          value={value}
          onChange={(e) => onChange(strict ? e.target.value.replace(/[^0-9]/g, "") : e.target.value)}
        />
      </div>
    </div>
  );
}

/** Pill-shaped single choice (DESIGN.md §6 Segmented): native radios underneath. */
export function Segmented<T extends string>({ name, label, value, options, onChange }: {
  name: string;
  label: string;
  value: T;
  options: [T, string][];
  onChange: (v: T) => void;
}) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map(([v, t]) => (
        <label key={v}>
          <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} />
          <span>{t}</span>
        </label>
      ))}
    </div>
  );
}

/** A settings row with a switch (DESIGN.md §6 ToggleRow). */
export function ToggleRow({ id, icon, tone = "", title, sub, checked, disabled = false, onChange }: {
  id: string;
  icon: string;
  tone?: string;
  title: string;
  sub?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="row">
      <div className={`row-icon ${tone}`}><Icon name={icon} /></div>
      <div className="row-main">
        <label className="row-title" htmlFor={id}>{title}</label>
        {sub ? <div className="row-sub" id={`${id}-d`}>{sub}</div> : null}
      </div>
      <span className="switch">
        <input type="checkbox" role="switch" id={id} checked={checked} disabled={disabled} aria-describedby={sub ? `${id}-d` : undefined} onChange={(e) => onChange(e.target.checked)} />
        <span className="track"><span className="thumb"></span></span>
      </span>
    </div>
  );
}

/**
 * Keys for a modal dialog: Escape closes it from anywhere and Tab stays inside `box`
 * (DESIGN.md §6, reviews M2-4 and M3-11).
 */
export function useDialogKeys(box: RefObject<HTMLElement | null>, onClose: () => void): void {
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      // A dialog under a call is inert: the call has the keyboard (review C6R2-3).
      if (box.current?.closest("[inert]")) return;
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !box.current) return;
      const items = Array.from(box.current.querySelectorAll<HTMLElement>("button:not([disabled])"));
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !box.current.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !box.current.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [box, onClose]);
}
