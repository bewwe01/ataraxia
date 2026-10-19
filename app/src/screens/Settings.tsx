import { useState } from "react";
import { ipc, type Me } from "../ipc";
import { applyAppearance, loadAppearance, type Accent, type Appearance, type Mode, type Style } from "../settings";
import { Icon, TopBar } from "../ui";
import type { Nav } from "./Chats";

function Segmented<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <div className="field">
      <span className="label">{label}</span>
      <div className="segmented" role="radiogroup" aria-label={label}>
        {options.map(([v, t]) => (
          <button key={v} type="button" role="radio" aria-checked={value === v} onClick={() => onChange(v)}>{t}</button>
        ))}
      </div>
    </div>
  );
}

export function Settings({ me, nav, onLocked }: { me: Me | null; nav: Nav; onLocked: () => void }) {
  const [a, setA] = useState<Appearance>(loadAppearance());

  function update(next: Appearance) {
    setA(next);
    applyAppearance(next);
  }

  return (
    <div className="m-screen push">
      <TopBar title="Settings" onBack={() => nav({ screen: "chats" })} />
      <div className="m-body stack">
        {me ? (
          <section className="card stack-sm">
            <h2>{me.name || "You"}</h2>
            <p className="hint">Your identity · <span className="mono-wrap">{me.fingerprint}</span></p>
            <p className="hint">Relay · <span className="mono-wrap">{me.relay}</span> · {me.connection}</p>
          </section>
        ) : null}
        <section className="card stack">
          <h2>Appearance</h2>
          <Segmented<Style> label="Theme" value={a.style} options={[["aurora", "Aurora Glass"], ["ink", "Ink & Signal"]]} onChange={(style) => update({ ...a, style })} />
          <Segmented<Mode> label="Mode" value={a.mode} options={[["system", "System"], ["dark", "Dark"], ["light", "Light"]]} onChange={(mode) => update({ ...a, mode })} />
          <Segmented<Accent> label="Accent" value={a.accent} options={[["aurora", "Aurora"], ["lagoon", "Lagoon"], ["ember", "Ember"]]} onChange={(accent) => update({ ...a, accent })} />
          <label className="row">
            <span>Reduce motion</span>
            <input type="checkbox" checked={a.reduceMotion} onChange={(e) => update({ ...a, reduceMotion: e.target.checked })} />
          </label>
        </section>
        <section className="card stack-sm">
          <h2>Security</h2>
          <button className="btn btn-secondary btn-block" type="button" onClick={() => void ipc.lock().then(onLocked)}>
            <Icon name="lock" />Lock now
          </button>
          <p className="hint">Veil also locks itself after 5 minutes without use.</p>
        </section>
        <section className="card stack-sm">
          <h2>About</h2>
          <p className="hint">Veil 0.1 (preview). Free software, AGPL-3.0. Not independently audited.</p>
        </section>
      </div>
    </div>
  );
}
