import { useEffect, useState, type FormEvent } from "react";
import { ipc, IpcError, type Me, type NativeInfo, type SecretKind, type SecurityView } from "../ipc";
import { applyAppearance, loadAppearance, type Accent, type Appearance, type Mode, type Style } from "../settings";
import { Banner, Icon, SecretField, Segmented, ToggleRow, TopBar } from "../ui";
import type { Nav } from "./Chats";
import { checkSecret, KIND_HINT, kindName } from "./Onboarding";

type Panel = null | "change" | "purge" | "purge-remove" | "biometric";

function errText(err: unknown, fallback: string): string {
  return err instanceof IpcError ? err.message : fallback;
}

/** Change the PIN or password (and possibly switch between them). */
function ChangeSecret({ sec, onDone, onCancel }: { sec: SecurityView; onDone: (msg: string) => void; onCancel: () => void }) {
  const [current, setCurrent] = useState("");
  const [kind, setKind] = useState<SecretKind>(sec.kind);
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const bad = checkSecret(kind, next);
    if (bad) return setError(bad);
    if (next !== next2) return setError(`The two ${kindName(kind)}s do not match.`);
    setBusy(true);
    setError(null);
    try {
      await ipc.changeSecret(current, kind, next);
      onDone(sec.purgeSet ? `Your ${kindName(kind)} is changed. Your Purge PIN was removed; set it again if you want it.` : `Your ${kindName(kind)} is changed.`);
    } catch (err) {
      setError(errText(err, "Could not change it"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card stack" autoComplete="off" onSubmit={(e) => void submit(e)}>
      <h3>Change {kindName(sec.kind)}</h3>
      <SecretField id="cs-cur" label={`Current ${kindName(sec.kind)}`} kind={sec.kind} value={current} onChange={setCurrent} autoComplete="current-password" autoFocus />
      <div className="field">
        <span className="label">New</span>
        <Segmented<SecretKind> name="cs-kind" label="New PIN or password" value={kind} options={[["pin", "PIN"], ["password", "Password"]]} onChange={(k) => { setKind(k); setNext(""); setNext2(""); }} />
        <p className="hint">{KIND_HINT[kind]}</p>
      </div>
      <SecretField id="cs-new" label={kind === "pin" ? "New PIN" : "New password"} kind={kind} value={next} onChange={setNext} autoComplete="new-password" />
      <SecretField id="cs-new2" label={kind === "pin" ? "Repeat new PIN" : "Repeat new password"} kind={kind} value={next2} onChange={setNext2} autoComplete="new-password" />
      {sec.purgeSet ? <p className="hint">Changing this removes your Purge PIN. You can set it again afterwards.</p> : null}
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      <div className="btn-row">
        <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
        <button className="btn btn-primary" type="submit" disabled={busy || !current}>{busy ? "Saving…" : "Save"}</button>
      </div>
    </form>
  );
}

/** Set, replace or remove the Purge PIN. */
function PurgeForm({ sec, remove, onDone, onCancel }: { sec: SecurityView; remove: boolean; onDone: (msg: string) => void; onCancel: () => void }) {
  const [current, setCurrent] = useState("");
  const [purge, setPurge] = useState("");
  const [purge2, setPurge2] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const word = sec.kind === "pin" ? "Purge PIN" : "Purge password";

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!remove) {
      const bad = checkSecret(sec.kind, purge);
      if (bad) return setError(bad);
      if (purge !== purge2) return setError(`The two ${word}s do not match.`);
      if (!understood) return setError("Tick the box to confirm you understand what it does.");
    }
    setBusy(true);
    try {
      if (remove) {
        await ipc.clearPurge(current);
        onDone(`${word} removed.`);
      } else {
        await ipc.setPurge(current, purge);
        onDone(`${word} set. Entering it at the lock screen deletes Veil from this device.`);
      }
    } catch (err) {
      setError(errText(err, "Could not save it"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card stack" autoComplete="off" onSubmit={(e) => void submit(e)}>
      <h3>{remove ? `Remove ${word}` : sec.purgeSet ? `Change ${word}` : `Set a ${word}`}</h3>
      <SecretField id="pg-cur" label={`Your ${kindName(sec.kind)}`} kind={sec.kind} value={current} onChange={setCurrent} autoComplete="current-password" autoFocus />
      {remove ? null : (
        <>
          <SecretField id="pg-new" label={word} kind={sec.kind} value={purge} onChange={setPurge} autoComplete="new-password" />
          <SecretField id="pg-new2" label={`Repeat ${word}`} kind={sec.kind} value={purge2} onChange={setPurge2} autoComplete="new-password" />
          <Banner tone="danger" icon="alert-triangle">
            <p><b>This deletes everything, instantly.</b> Typing the {word} at the lock screen erases your identity, contacts, messages and keys from this device without asking. It can't be undone. Anyone watching sees only “Wrong {kindName(sec.kind)}”, and Veil then looks newly installed.</p>
          </Banner>
          <label className="check-row">
            <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
            <span>I understand that the {word} permanently deletes Veil's data.</span>
          </label>
        </>
      )}
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      <div className="btn-row">
        <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
        <button className={`btn ${remove ? "btn-secondary" : "btn-danger"}`} type="submit" disabled={busy || !current}>{busy ? "Saving…" : remove ? "Remove" : "Save"}</button>
      </div>
    </form>
  );
}

/** Ask for the PIN or password before turning on biometrics. */
function BiometricForm({ sec, onDone, onCancel }: { sec: SecurityView; onDone: (msg: string) => void; onCancel: () => void }) {
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await ipc.biometricEnable(current);
      onDone("Fingerprint unlock is on.");
    } catch (err) {
      setError(errText(err, "Could not turn it on"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card stack" autoComplete="off" onSubmit={(e) => void submit(e)}>
      <h3>Turn on fingerprint unlock</h3>
      <SecretField id="bio-cur" label={`Your ${kindName(sec.kind)}`} kind={sec.kind} value={current} onChange={setCurrent} autoComplete="current-password" autoFocus />
      <p className="hint">Your phone then asks for your fingerprint or face once to set it up. If you add a new fingerprint later, this turns itself off and you use your {kindName(sec.kind)} again.</p>
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      <div className="btn-row">
        <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
        <button className="btn btn-primary" type="submit" disabled={busy || !current}>{busy ? "Waiting…" : "Continue"}</button>
      </div>
    </form>
  );
}

export function Settings({ me, nav, onLocked }: { me: Me | null; nav: Nav; onLocked: () => void }) {
  const [a, setA] = useState<Appearance>(loadAppearance());
  const [sec, setSec] = useState<SecurityView | null>(null);
  const [native, setNative] = useState<NativeInfo | null>(null);
  const [panel, setPanel] = useState<Panel>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    void ipc.security().then(setSec, () => undefined);
    void ipc.nativeInfo().then(setNative, () => undefined);
  }
  useEffect(refresh, []);

  function update(next: Appearance) {
    setA(next);
    applyAppearance(next);
  }

  function done(msg: string) {
    setPanel(null);
    setNote(msg);
    setError(null);
    refresh();
  }

  async function toggleBiometric(on: boolean) {
    setNote(null);
    setError(null);
    if (on) {
      setPanel("biometric");
      return;
    }
    try {
      await ipc.biometricDisable();
      done("Fingerprint unlock is off.");
    } catch (err) {
      setError(errText(err, "Could not turn it off"));
    }
  }

  async function toggleScreenshots(allow: boolean) {
    setError(null);
    try {
      await ipc.setScreenshotsAllowed(allow);
      refresh();
    } catch (err) {
      setError(errText(err, "Could not change it"));
    }
  }

  const word = sec?.kind === "pin" ? "Purge PIN" : "Purge password";
  return (
    <div className="m-screen push">
      <TopBar title="Settings" onBack={() => nav({ screen: "chats" })} />
      <div className="m-body settings-page">
        {me ? (
          <section className="card stack-sm">
            <h2>{me.name || "You"}</h2>
            <p className="hint">Your identity · <span className="mono-wrap">{me.fingerprint}</span></p>
            <p className="hint">Relay · <span className="mono-wrap">{me.relay}</span> · {me.connection}</p>
          </section>
        ) : null}

        <h3 className="group-title">Security</h3>
        {note ? <Banner tone="neutral" icon="check"><p>{note}</p></Banner> : null}
        {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
        <div className="group card">
          <button className="row" type="button" onClick={() => void ipc.lock().then(onLocked, onLocked)}>
            <div className="row-icon accent"><Icon name="lock" /></div>
            <div className="row-main"><div className="row-title">Lock now</div><div className="row-sub">Veil also locks itself after 5 minutes without you touching it.</div></div>
          </button>
          {sec ? (
            <button className="row" type="button" aria-expanded={panel === "change"} onClick={() => { setNote(null); setPanel(panel === "change" ? null : "change"); }}>
              <div className="row-icon"><Icon name="key" /></div>
              <div className="row-main"><div className="row-title">Change {kindName(sec.kind)}</div><div className="row-sub">You unlock with a {kindName(sec.kind)}. You can switch to a {sec.kind === "pin" ? "password" : "PIN"}.</div></div>
              <Icon name="chevron-right" className="chev" />
            </button>
          ) : null}
          {sec && native?.biometric ? (
            <ToggleRow id="bio" icon="fingerprint" title="Unlock with fingerprint" sub="Uses your phone's fingerprint or face unlock. Your PIN or password still works." checked={sec.biometric || panel === "biometric"} onChange={(v) => void toggleBiometric(v)} />
          ) : null}
          {native?.screenshotSetting ? (
            <ToggleRow id="shots" icon="eye-off" tone={native.screenshotsAllowed ? "warning" : ""} title="Block screenshots" sub="Also hides Veil in the recent-apps screen. Turn off only for a moment, for example to send a screenshot of a problem." checked={!native.screenshotsAllowed} onChange={(v) => void toggleScreenshots(!v)} />
          ) : null}
        </div>
        {sec && panel === "change" ? <ChangeSecret sec={sec} onDone={done} onCancel={() => setPanel(null)} /> : null}
        {sec && panel === "biometric" ? <BiometricForm sec={sec} onDone={done} onCancel={() => setPanel(null)} /> : null}

        {sec ? (
          <>
            <h3 className="group-title">{word}</h3>
            <div className="group card">
              <div className="row">
                <div className="row-icon danger"><Icon name="flame" /></div>
                <div className="row-main">
                  <div className="row-title">{sec.purgeSet ? `${word} is set` : "Not set"}</div>
                  <div className="row-sub">A second {kindName(sec.kind)} for emergencies. Typed at the lock screen, it deletes everything Veil has on this device.</div>
                </div>
              </div>
              {sec.purgeSet ? (
                <>
                  <button className="row" type="button" onClick={() => { setNote(null); setPanel("purge"); }}>
                    <div className="row-icon"><Icon name="edit" /></div>
                    <div className="row-main"><div className="row-title">Change {word}</div></div>
                    <Icon name="chevron-right" className="chev" />
                  </button>
                  <button className="row" type="button" onClick={() => { setNote(null); setPanel("purge-remove"); }}>
                    <div className="row-icon"><Icon name="x" /></div>
                    <div className="row-main"><div className="row-title">Remove {word}</div></div>
                    <Icon name="chevron-right" className="chev" />
                  </button>
                </>
              ) : (
                <button className="row" type="button" onClick={() => { setNote(null); setPanel("purge"); }}>
                  <div className="row-icon"><Icon name="plus" /></div>
                  <div className="row-main"><div className="row-title">Set a {word}</div></div>
                  <Icon name="chevron-right" className="chev" />
                </button>
              )}
            </div>
            {panel === "purge" || panel === "purge-remove" ? <PurgeForm sec={sec} remove={panel === "purge-remove"} onDone={done} onCancel={() => setPanel(null)} /> : null}
          </>
        ) : null}

        <h3 className="group-title">Appearance</h3>
        <section className="card stack">
          <div className="field">
            <span className="label">Theme</span>
            <Segmented<Style> name="style" label="Theme" value={a.style} options={[["aurora", "Aurora Glass"], ["ink", "Ink & Signal"]]} onChange={(style) => update({ ...a, style })} />
          </div>
          <div className="field">
            <span className="label">Mode</span>
            <Segmented<Mode> name="mode" label="Mode" value={a.mode} options={[["system", "System"], ["dark", "Dark"], ["light", "Light"]]} onChange={(mode) => update({ ...a, mode })} />
          </div>
          <div className="field">
            <span className="label">Accent</span>
            <Segmented<Accent> name="accent" label="Accent" value={a.accent} options={[["aurora", "Aurora"], ["lagoon", "Lagoon"], ["ember", "Ember"]]} onChange={(accent) => update({ ...a, accent })} />
          </div>
        </section>
        <div className="group card">
          <ToggleRow id="motion" icon="sparkle" title="Reduce motion" checked={a.reduceMotion} onChange={(v) => update({ ...a, reduceMotion: v })} />
        </div>

        <h3 className="group-title">About</h3>
        <section className="card stack-sm">
          <p className="hint">Veil 0.1 (preview). Free software, AGPL-3.0. Not independently audited.</p>
        </section>
      </div>
    </div>
  );
}
