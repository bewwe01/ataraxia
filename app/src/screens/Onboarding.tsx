import { useState, type FormEvent } from "react";
import { ipc, IpcError } from "../ipc";
import { Banner, Icon, Logo } from "../ui";

const MIN_PASSPHRASE = 12; // also enforced in Rust

export function Setup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<"welcome" | "form" | "honest">("welcome");
  const [relay, setRelay] = useState("");
  const [pin, setPin] = useState("");
  const [name, setName] = useState("");
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
    if (pass.length < MIN_PASSPHRASE) return setError(`Use at least ${MIN_PASSPHRASE} characters; four random words is good.`);
    if (pass !== pass2) return setError("The passphrases do not match.");
    setBusy(true);
    try {
      await ipc.setup({ relay: relay.trim(), pin: pin.trim(), name: name.trim(), passphrase: pass });
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
          <label htmlFor="pp">Passphrase</label>
          <div className="input"><input id="pp" type="password" autoComplete="new-password" required value={pass} onChange={(e) => setPass(e.target.value)} /></div>
        </div>
        <div className="field">
          <label htmlFor="pp2">Repeat passphrase</label>
          <div className="input"><input id="pp2" type="password" autoComplete="new-password" required value={pass2} onChange={(e) => setPass2(e.target.value)} /></div>
        </div>
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
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);

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
    setBusy(true);
    setError(null);
    try {
      await ipc.unlock(pass);
      setPass("");
      onDone();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Unlock failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="m-screen full onb-screen">
      <form className="onb lock" autoComplete="off" onSubmit={(e) => void submit(e)}>
        <div className="lock-hero">
          <Logo className="lg" />
          <h1 className="onb-title sm">Veil is locked</h1>
        </div>
        <div className="stack">
          <div className="field">
            <label htmlFor="unlock-pp" className="sr-only">Passphrase</label>
            <div className="input"><span className="lead-icon"><Icon name="key" /></span>
              <input id="unlock-pp" type="password" placeholder="Passphrase" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} />
            </div>
          </div>
          {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>{busy ? "Unlocking…" : "Unlock"}</button>
        </div>
        <details className="err-details forgot">
          <summary>Forgot your passphrase?</summary>
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
