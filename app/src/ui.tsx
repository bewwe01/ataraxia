// UI primitives ported from design/proto/ui.js (DESIGN.md §6). All text is rendered as React
// text nodes; nothing is ever inserted as HTML.
import type { ReactNode } from "react";

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
