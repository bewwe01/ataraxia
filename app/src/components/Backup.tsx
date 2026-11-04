// Settings → Backup (milestone 7, ADR-0021): make an encrypted backup, and see the backup code
// again after the PIN or password. The code is shown, never copied (no clipboard, CLAUDE.md
// rule 6), and Veil keeps it only inside its encrypted database. While it is on screen,
// Android blocks screenshots (review BK-14); it lives in this component's state only, so it is
// gone when Settings closes or Veil locks.
import { useEffect, useState, type FormEvent } from "react";
import { IpcError, ipc, type BackupSaved, type SecretKind } from "../ipc";
import { Banner, Icon, SecretField } from "../ui";

function size(bytes: number): string {
  return bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function CodeCard({ code }: { code: string }) {
  useEffect(() => {
    void ipc.backupCodeOnScreen(true).catch(() => undefined);
    return () => {
      void ipc.backupCodeOnScreen(false).catch(() => undefined);
    };
  }, []);
  return (
    <div className="backup-code card" role="group" aria-label="Your backup code">
      <p className="mono backup-code-text">{code}</p>
      <p className="hint">Write it down and keep it apart from the backup file. Anyone with both can read your messages; without the code, nobody can, not even you.</p>
    </div>
  );
}

export function BackupCard({ kind }: { kind: SecretKind }) {
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState<BackupSaved | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);
  const [current, setCurrent] = useState("");
  const [shown, setShown] = useState<string | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function make() {
    setError(null);
    setNote(null);
    setShown(null);
    setBusy(true);
    try {
      setSaved(await ipc.createBackup());
    } catch (e) {
      const m = e instanceof IpcError ? e.message : "";
      if (m !== "Cancelled") setError(m || "The backup could not be made");
    } finally {
      setBusy(false);
    }
  }

  /** The user wrote the code down: later backups no longer show it (review BK-7). */
  async function seen() {
    try {
      await ipc.backupCodeSeen();
      setSaved((v) => (v ? { ...v, code: null } : v));
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not save that");
    }
  }

  async function renew() {
    setError(null);
    try {
      await ipc.newBackupCode();
      setRenewing(false);
      setShown(null);
      setSaved(null);
      setNote("The next backup gets a new code. Backups made before open with the old code only.");
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not do that");
    }
  }

  async function show(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaved((v) => (v ? { ...v, code: null } : v));
    try {
      const c = await ipc.backupCode(current);
      setShown(c);
      setAsking(false);
      if (!c) setError("Make a backup first: the code is made with it.");
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not check that");
    } finally {
      setCurrent("");
    }
  }

  return (
    <section className="card stack">
      <p className="hint">A backup holds your identity, contacts and messages, encrypted with a backup code. Restore it on a new phone or computer with that code.</p>
      <button className="btn btn-secondary btn-block" type="button" disabled={busy} onClick={() => void make()}>
        <Icon name="download" />{busy ? "Making the backup…" : "Make a backup"}
      </button>
      {saved ? (
        <div role="status" className="stack-sm">
          <p className="hint">Saved {saved.file} ({size(saved.bytes)}).</p>
          {saved.code ? (
            <>
              <Banner tone="warning" icon="key"><p><b>Your backup code.</b> After this it is shown only with your {kind === "pin" ? "PIN" : "password"}.</p></Banner>
              <CodeCard code={saved.code} />
              <button className="btn btn-primary btn-block" type="button" onClick={() => void seen()}>I wrote it down</button>
            </>
          ) : null}
        </div>
      ) : null}
      {shown ? <CodeCard code={shown} /> : null}
      {asking ? (
        <form className="stack-sm" onSubmit={(e) => void show(e)}>
          <SecretField id="bk-cur" label={kind === "pin" ? "Your PIN" : "Your password"} kind={kind} value={current} onChange={setCurrent} autoComplete="current-password" />
          <div className="banner-actions">
            <button className="btn btn-secondary" type="button" onClick={() => { setAsking(false); setCurrent(""); }}>Cancel</button>
            <button className="btn btn-primary" type="submit">Show code</button>
          </div>
        </form>
      ) : shown ? (
        <button className="btn btn-ghost btn-block" type="button" onClick={() => setShown(null)}>Hide the code</button>
      ) : (
        <button className="btn btn-ghost btn-block" type="button" onClick={() => { setAsking(true); setShown(null); }}>Show my backup code</button>
      )}
      {renewing ? (
        <div className="stack-sm" role="group" aria-label="New backup code">
          <p className="hint">Use this if someone may have seen your code. Your next backup gets a new code; backups you made before still open with the old one, so delete them.</p>
          <div className="banner-actions">
            <button className="btn btn-secondary" type="button" onClick={() => setRenewing(false)}>Cancel</button>
            <button className="btn btn-primary" type="button" onClick={() => void renew()}>New code</button>
          </div>
        </div>
      ) : (
        <button className="btn btn-ghost btn-block" type="button" onClick={() => { setRenewing(true); setNote(null); }}>Make a new backup code</button>
      )}
      {note ? <p className="hint" role="status">{note}</p> : null}
      {error ? <p className="field-error" role="alert">{error}</p> : null}
    </section>
  );
}
