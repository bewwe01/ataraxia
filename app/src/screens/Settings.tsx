import { noteEraseIncomplete } from "../notices";
import { useEffect, useState, type FormEvent } from "react";
import { ipc, IpcError, type Me, type NativeInfo, type NotifySettings, type PrivacyView, type SecretKind, type SecurityView } from "../ipc";
import { applyAppearance, isDark, loadAppearance, type Accent, type Appearance, type Bubble, type Density, type Mode, type Style, type TextSize } from "../settings";
import { HuePicker, LookPreview, WallpaperPicker } from "../components/Look";
import { useChatWallpaper } from "../wallpaper";
import { Banner, Icon, SecretField, Segmented, ToggleRow, TopBar } from "../ui";
import type { Nav } from "./Chats";
import { checkSecret, KIND_HINT, kindName } from "./Onboarding";

type Panel = null | "change" | "purge" | "purge-remove" | "biometric" | "erase";

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
function PurgeForm({ sec, native, remove, onDone, onCancel }: { sec: SecurityView; native: NativeInfo | null; remove: boolean; onDone: (msg: string) => void; onCancel: () => void }) {
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
            <p><b>This deletes everything, instantly.</b> Typing the {word} at the lock screen erases your identity, contacts, messages and keys from this device without asking{native === null ? "" : native.android ? ", and destroys the phone's hardware key that protects them, so even a copy of the phone's storage can't be opened" : ". On a computer, a forensic copy of the disk might still recover deleted files"}. It can't be undone. Anyone watching sees “Wrong {kindName(sec.kind)}”; after Veil restarts it looks newly installed.</p>
          </Banner>
          {native?.biometric ? <p className="hint">If you rely on the {word}, turn off fingerprint unlock: someone can force your finger onto the phone without ever seeing the {word} screen.</p> : null}
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

/**
 * "Erase everything": what the Purge PIN does, from Settings. Three deliberate steps so it
 * cannot happen by a slip: read and tick, type ERASE, then the current PIN or password.
 */
function EraseForm({ sec, native, onErased, onCancel }: { sec: SecurityView; native: NativeInfo | null; onErased: () => void; onCancel: () => void }) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [understood, setUnderstood] = useState(false);
  const [typed, setTyped] = useState("");
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function erase(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (!(await ipc.purgeAll(current))) noteEraseIncomplete();
      onErased();
    } catch (err) {
      setError(errText(err, "Could not erase"));
      setBusy(false);
    }
  }

  return (
    <form className="card stack" autoComplete="off" onSubmit={(e) => (step === 3 ? void erase(e) : e.preventDefault())}>
      <h3>Erase everything <span className="hint">· step {step} of 3</span></h3>
      {step === 1 ? (
        <>
          <Banner tone="danger" icon="alert-triangle">
            <p><b>This deletes Veil's data from this device, for good.</b> Your identity, every contact, every message, photo, file and voice note, and the keys that protect them{native?.android ? ", including the phone's hardware key" : ""}. Nobody can bring them back, not even you. Your contacts keep their copies of your conversations.</p>
          </Banner>
          <label className="check-row">
            <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
            <span>I understand this cannot be undone.</span>
          </label>
          <div className="btn-row">
            <button className="btn btn-secondary" type="button" autoFocus onClick={onCancel}>Cancel</button>
            <button className="btn btn-danger-ghost" type="button" disabled={!understood} onClick={() => setStep(2)}>Continue</button>
          </div>
        </>
      ) : step === 2 ? (
        <>
          <div className="field">
            <label className="label" htmlFor="er-word">Type ERASE to confirm</label>
            <div className="input"><input id="er-word" autoFocus autoCapitalize="characters" spellCheck={false} value={typed} onChange={(e) => setTyped(e.target.value)} /></div>
          </div>
          <div className="btn-row">
            <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
            <button className="btn btn-danger-ghost" type="button" disabled={typed.trim().toUpperCase() !== "ERASE"} onClick={() => setStep(3)}>Continue</button>
          </div>
        </>
      ) : (
        <>
          <SecretField id="er-cur" label={`Your ${kindName(sec.kind)}, to erase everything`} kind={sec.kind} value={current} onChange={setCurrent} autoComplete="current-password" autoFocus />
          {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
          <div className="btn-row">
            <button className="btn btn-secondary" type="button" onClick={onCancel}>Cancel</button>
            <button className="btn btn-danger" type="submit" disabled={busy || !current}>{busy ? "Erasing…" : "Erase everything now"}</button>
          </div>
        </>
      )}
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
  const wallpaper = useChatWallpaper(null);
  const [sec, setSec] = useState<SecurityView | null>(null);
  const [native, setNative] = useState<NativeInfo | null>(null);
  const [privacy, setPrivacy] = useState<PrivacyView | null>(null);
  const [notify, setNotify] = useState<NotifySettings | null>(null);
  const [panel, setPanel] = useState<Panel>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    void ipc.security().then(setSec, () => undefined);
    void ipc.nativeInfo().then(setNative, () => undefined);
    void ipc.privacy().then(setPrivacy, () => undefined);
    void ipc.notifySettings().then(setNotify, () => undefined);
  }

  async function changeNotify(f: () => Promise<void>) {
    setError(null);
    try {
      await f();
    } catch (err) {
      setError(errText(err, "Could not change it"));
    }
    // The system permission answer comes later; read everything again.
    void ipc.notifySettings().then(setNotify, () => undefined);
    window.setTimeout(() => void ipc.notifySettings().then(setNotify, () => undefined), 1500);
  }

  async function changePrivacy(next: PrivacyView) {
    setError(null);
    try {
      await ipc.setPrivacy(next);
      setPrivacy(next);
    } catch (err) {
      setError(errText(err, "Could not change it"));
    }
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
            {panel === "purge" || panel === "purge-remove" ? <PurgeForm sec={sec} native={native} remove={panel === "purge-remove"} onDone={done} onCancel={() => setPanel(null)} /> : null}
          </>
        ) : null}

        {notify ? (
          <>
            <h3 className="group-title">Notifications</h3>
            <div className="group card">
              <ToggleRow id="notify" icon="bell" title="Message notifications" sub="Say only that something arrived: never who, never what. While Veil is locked it keeps its relay sign-in in memory to hear about new messages; it still cannot read them." checked={notify.enabled} onChange={(v) => void changeNotify(() => ipc.setNotify(v))} />
              {notify.backgroundSetting ? (
                <ToggleRow id="background" icon="wifi" title="Stay connected in the background" sub="Keeps Veil running when you leave it, so notifications still come. Shows a silent notification and uses some battery." checked={notify.background} disabled={!notify.enabled} onChange={(v) => void changeNotify(() => ipc.setBackground(v))} />
              ) : null}
            </div>
            {notify.enabled && !notify.systemAllowed ? (
              <Banner tone="warning" icon="bell-off">
                <p>Your phone does not let Veil show notifications.</p>
                <div className="banner-actions">
                  <button className="btn btn-secondary" type="button" onClick={() => void changeNotify(() => ipc.setNotify(true))}>Allow notifications</button>
                </div>
              </Banner>
            ) : null}
          </>
        ) : null}

        {privacy ? (
          <>
            <h3 className="group-title">Privacy</h3>
            <div className="group card">
              <ToggleRow id="receipts" icon="check-double" title="Read receipts" sub="On: contacts see when their messages reached you and when you read them, and you see the same from contacts who have it on. Off: neither." checked={privacy.readReceipts} onChange={(v) => void changePrivacy({ ...privacy, readReceipts: v })} />
              <ToggleRow id="typing" icon="keyboard" title="Typing indicators" sub="On: contacts see when you are typing, and you see the same from contacts who have it on." checked={privacy.typing} onChange={(v) => void changePrivacy({ ...privacy, typing: v })} />
            </div>
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
            <Segmented<Accent> name="accent" label="Accent" value={a.accent} options={[["aurora", "Aurora"], ["lagoon", "Lagoon"], ["ember", "Ember"], ["custom", "Custom"]]} onChange={(accent) => update({ ...a, accent })} />
          </div>
          {a.accent === "custom" ? (
            <HuePicker name="accent-hue" label="Custom accent" value={a.hue} onChange={(hue) => update({ ...a, hue: hue ?? a.hue })} />
          ) : null}
          <div className="field">
            <span className="label">Message bubbles</span>
            <Segmented<Bubble> name="bubble" label="Message bubbles" value={a.bubble} options={[["gradient", "Gradient"], ["soft", "Solid"], ["minimal", "Minimal"]]} onChange={(bubble) => update({ ...a, bubble })} />
          </div>
          <div className="field">
            <span className="label">Message text size</span>
            <Segmented<TextSize> name="text-size" label="Message text size" value={a.textSize} options={[["sm", "Small"], ["md", "Default"], ["lg", "Large"], ["xl", "Larger"]]} onChange={(textSize) => update({ ...a, textSize })} />
          </div>
          <div className="field">
            <span className="label">Spacing</span>
            <Segmented<Density> name="density" label="Spacing" value={a.density} options={[["regular", "Regular"], ["compact", "Compact"]]} onChange={(density) => update({ ...a, density })} />
          </div>
          <LookPreview w={wallpaper.w} photoUrl={wallpaper.photoUrl} />
        </section>
        <div className="group card">
          {isDark(a) ? (
            <ToggleRow id="black" icon="moon" title="Pure black" sub="Black backgrounds in dark mode; saves power on OLED screens." checked={a.black} onChange={(v) => update({ ...a, black: v })} />
          ) : null}
          <ToggleRow id="motion" icon="sparkle" title="Reduce motion" checked={a.reduceMotion} onChange={(v) => update({ ...a, reduceMotion: v })} />
        </div>
        <h3 className="group-title">Chat wallpaper</h3>
        <section className="card stack">
          <WallpaperPicker contact={null} value={wallpaper.w} photoUrl={wallpaper.photoUrl} />
        </section>

        <h3 className="group-title">About</h3>
        <section className="card stack-sm">
          <p className="hint">Veil 0.1 (preview). Free software, AGPL-3.0. Not independently audited.</p>
        </section>
        {sec ? (
          <>
            <h3 className="group-title">Erase</h3>
            <div className="group card">
              <button className="row" type="button" aria-expanded={panel === "erase"} onClick={() => { setNote(null); setPanel(panel === "erase" ? null : "erase"); }}>
                <div className="row-icon danger"><Icon name="trash" /></div>
                <div className="row-main"><div className="row-title">Erase everything…</div><div className="row-sub">Deletes Veil's data from this device now, like the {word}. Veil starts afresh.</div></div>
                <Icon name="chevron-right" className="chev" />
              </button>
            </div>
            {panel === "erase" ? <EraseForm sec={sec} native={native} onErased={onLocked} onCancel={() => setPanel(null)} /> : null}
          </>
        ) : null}
      </div>
    </div>
  );
}
