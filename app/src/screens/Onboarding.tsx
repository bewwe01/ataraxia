import { useEffect, useRef, useState, type FormEvent } from "react";
import { ipc, IpcError, type SecretKind, type UnlockInfo } from "../ipc";
import { Banner, Icon, Logo, SecretField, Segmented } from "../ui";

// Also enforced in Rust (crates/client/src/unlock.rs).
const MIN_PIN = 6;
const MAX_PIN = 16;
const MIN_PASSWORD = 12;

/** Returns an error message, or null if the PIN or password is acceptable. */
export function checkSecret(kind: SecretKind, s: string): string | null {
  if (kind === "pin") {
    return /^[0-9]+$/.test(s) && s.length >= MIN_PIN && s.length <= MAX_PIN ? null : `Use ${MIN_PIN} to ${MAX_PIN} digits.`;
  }
  return [...s].length >= MIN_PASSWORD ? null : `Use at least ${MIN_PASSWORD} characters; four random words is good.`;
}

export const KIND_HINT: Record<SecretKind, string> = {
  pin: "6 to 16 digits. Quick to type, but weaker: someone who copies this device's files could try every short PIN.",
  password: "At least 12 characters. Four random words is strong and easy to remember.",
};

export function kindName(kind: SecretKind): string {
  return kind === "pin" ? "PIN" : "password";
}

export function Setup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<"welcome" | "form" | "honest">("welcome");
  const [relay, setRelay] = useState("");
  const [pin, setPin] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SecretKind>("pin");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (step === "welcome") {
    return (
      <div className="m-screen full onb-screen">
        <div className="onb welcome">
          <div className="lock-hero">
            <Logo className="lg" />
            <h1 className="onb-title">Veil</h1>
            <p className="muted">Private messages through a relay you choose. No phone number, no account, no directory.</p>
          </div>
          <div className="onb-actions">
            <button className="btn btn-primary btn-block" type="button" onClick={() => setStep("honest")}>
              Get started
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (step === "honest") {
    return (
      <div className="m-screen full onb-screen">
        <div className="onb protection">
          <div className="stack"><h1 className="onb-title sm">What Veil protects, honestly</h1></div>
          <section className="card protect-card">
            <h2 className="protect-h yes"><Icon name="shield-check" className="icon-sm" />Protected</h2>
            <ul className="protect-list yes">
              <li>What you write: end-to-end encrypted, also against quantum attacks (PQXDH + SPQR).</li>
              <li>Names and keys: the relay never sees them, only random mailbox ids.</li>
              <li>Everything stored on this device: encrypted with your passphrase.</li>
            </ul>
          </section>
          <section className="card protect-card">
            <h2 className="protect-h no"><Icon name="alert-triangle" className="icon-sm" />Not protected</h2>
            <ul className="protect-list no">
              <li>The relay sees your IP address while you are connected, and message timing and sizes.</li>
              <li>Who talks to whom: the relay can link your mailbox to the mailboxes you send to. This version does not rotate mailboxes.</li>
              <li>A contact can screenshot or copy what you send.</li>
              <li>A device that is unlocked and compromised can read your messages.</li>
              <li>Veil has not had an independent security audit.</li>
            </ul>
          </section>
          <div className="onb-actions">
            <button className="btn btn-primary btn-block" type="button" onClick={() => setStep("form")}>I understand</button>
          </div>
        </div>
      </div>
    );
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const bad = checkSecret(kind, pass);
    if (bad) return setError(bad);
    if (pass !== pass2) return setError(`The two ${kindName(kind)}s do not match.`);
    setBusy(true);
    try {
      await ipc.setup({ relay: relay.trim(), pin: pin.trim(), name: name.trim(), kind, passphrase: pass });
      setPass("");
      setPass2("");
      onDone();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Setup failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="m-screen full onb-screen">
      <form className="onb passphrase" autoComplete="off" onSubmit={(e) => void submit(e)}>
        <div className="stack">
          <h1 className="onb-title sm">Set up Veil</h1>
          <p className="muted">Your relay's address and pin come from whoever runs it (see deploy/README.md).</p>
        </div>
        <div className="field">
          <label htmlFor="relay">Relay address</label>
          <div className="input mono"><input id="relay" required placeholder="relay.example.org:8443" value={relay} onChange={(e) => setRelay(e.target.value)} /></div>
        </div>
        <div className="field">
          <label htmlFor="pin">Relay pin (64 hex characters)</label>
          <div className="input mono"><input id="pin" required spellCheck={false} value={pin} onChange={(e) => setPin(e.target.value)} /></div>
        </div>
        <div className="field">
          <label htmlFor="name">Your name (shown only to contacts you add)</label>
          <div className="input"><input id="name" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} /></div>
        </div>
        <div className="field">
          <span className="label" id="kind-l">Unlock Veil with</span>
          <Segmented<SecretKind> name="kind" label="Unlock Veil with" value={kind} options={[["pin", "PIN"], ["password", "Password"]]} onChange={(k) => { setKind(k); setPass(""); setPass2(""); }} />
          <p className="hint">{KIND_HINT[kind]}</p>
        </div>
        <SecretField id="pp" label={kind === "pin" ? "PIN" : "Password"} kind={kind} value={pass} onChange={setPass} autoComplete="new-password" />
        <SecretField id="pp2" label={kind === "pin" ? "Repeat PIN" : "Repeat password"} kind={kind} value={pass2} onChange={setPass2} autoComplete="new-password" />
        <p className="hint">You can turn on fingerprint unlock and set a Purge PIN later in Settings.</p>
        <Banner tone="warning" icon="alert-triangle">
          <p><b>No one can recover it for you.</b> Not us, not the relay.</p>
        </Banner>
        {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
        <div className="onb-actions">
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            {busy ? "Creating your keys…" : "Create my identity"}
          </button>
        </div>
      </form>
    </div>
  );
}

export function Unlock({ onDone }: { onDone: () => void }) {
  const [info, setInfo] = useState<UnlockInfo | null>(null);
  const [wait, setWait] = useState(0);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const prompted = useRef(false);

  async function biometric() {
    setBusy(true);
    setError(null);
    try {
      await ipc.unlockBiometric();
      onDone();
    } catch (err) {
      const msg = err instanceof IpcError ? err.message : "Biometric unlock failed";
      if (msg !== "Cancelled") setError(msg);
      // A changed fingerprint set turns biometrics off: hide the button.
      void ipc.unlockInfo().then((i) => setInfo((cur) => (cur ? { ...cur, biometric: i.biometric } : i)), () => undefined);
    } finally {
      setBusy(false);
    }
  }

  // The keyboard and the biometric button are fixed when the screen opens (ADR-0012).
  useEffect(() => {
    void ipc.unlockInfo().then((i) => {
      setInfo(i);
      setWait(i.waitSecs);
    }, () => setInfo({ kind: "password", biometric: false, waitSecs: 0 }));
  }, []);

  useEffect(() => {
    if (info?.biometric && !prompted.current) {
      prompted.current = true;
      void biometric();
    }
  }, [info]);

  useEffect(() => {
    if (wait <= 0) return;
    const t = window.setTimeout(() => setWait((w) => w - 1), 1000);
    return () => window.clearTimeout(t);
  }, [wait]);

  async function reset() {
    setBusy(true);
    setError(null);
    try {
      await ipc.reset();
      onDone();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not delete the data");
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!pass || wait > 0) return;
    setBusy(true);
    setError(null);
    try {
      await ipc.unlock(pass);
      setPass("");
      onDone();
    } catch (err) {
      setPass("");
      setError(err instanceof IpcError ? err.message : "Unlock failed");
      // Only the wait is refreshed; the kind stays as it was.
      void ipc.unlockInfo().then((i) => setWait(i.waitSecs), () => undefined);
    } finally {
      setBusy(false);
    }
  }

  const kind = info?.kind ?? "password";
  const label = kind === "pin" ? "PIN" : "Password";
  return (
    <div className="m-screen full onb-screen">
      <form className="onb lock" autoComplete="off" onSubmit={(e) => void submit(e)}>
        <div className="lock-hero">
          <Logo className="lg" />
          <h1 className="onb-title sm">Veil is locked</h1>
        </div>
        <div className="stack">
          {info ? <SecretField id="unlock-pp" label={label} kind={kind} value={pass} onChange={setPass} autoComplete="current-password" autoFocus={!info.biometric} /> : null}
          {wait > 0 ? (
            <Banner tone="warning" icon="clock"><p>Too many wrong attempts. Try again in {wait < 60 ? `${wait} s` : `${Math.ceil(wait / 60)} min`}.</p></Banner>
          ) : null}
          {error && wait <= 0 ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
          <button className="btn btn-primary btn-block" type="submit" disabled={busy || wait > 0 || !pass}>{busy ? "Unlocking…" : "Unlock"}</button>
          {info?.biometric ? (
            <button className="btn btn-secondary btn-block" type="button" disabled={busy} onClick={() => void biometric()}>
              <Icon name="fingerprint" />Use fingerprint
            </button>
          ) : null}
        </div>
        <details className="err-details forgot">
          <summary>Forgot your {kindName(kind)}?</summary>
          <p className="hint">It can't be reset or recovered, by anyone. Without it, start over with a new identity. This deletes all contacts and messages on this device.</p>
          {confirmReset ? (
            <div className="stack-sm">
              <p className="hint"><strong>Delete everything on this device and start over?</strong> This cannot be undone.</p>
              <button className="btn btn-danger btn-block" type="button" disabled={busy} onClick={() => void reset()}>Yes, delete and start over</button>
              <button className="btn btn-secondary btn-block" type="button" onClick={() => setConfirmReset(false)}>Cancel</button>
            </div>
          ) : (
            <button className="btn btn-secondary btn-block" type="button" onClick={() => setConfirmReset(true)}>Start over…</button>
          )}
        </details>
      </form>
    </div>
  );
}
