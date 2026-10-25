import { useEffect, useState, type FormEvent } from "react";
import { ipc, IpcError, type ContactView, type InviteView, type SafetyView } from "../ipc";
import { Banner, Icon, QrCode, Segmented, TopBar } from "../ui";
import type { Nav } from "./Chats";

export function AddContact({ nav }: { nav: Nav }) {
  const [tab, setTab] = useState<"mine" | "theirs">("mine");
  const [invite, setInvite] = useState<InviteView | null>(null);
  const [link, setLink] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function make() {
    setBusy(true);
    setError(null);
    try {
      setInvite(await ipc.createInvite());
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not create an invite");
    } finally {
      setBusy(false);
    }
  }

  async function accept(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = await ipc.acceptInvite(link.trim());
      setLink("");
      nav({ screen: "chat", contact: c.id });
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not use this invite");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="m-screen push">
      <TopBar title="Add contact" onBack={() => nav({ screen: "chats" })} />
      <div className="m-body">
        <div className="pairing">
          <Segmented<"mine" | "theirs"> name="add-tab" label="Add contact" value={tab} options={[["mine", "My invite"], ["theirs", "Their invite"]]} onChange={setTab} />
          {tab === "mine" ? (
            invite ? (
              <>
                <div className="qr-wrap"><div className="qr-card"><QrCode modules={invite.qrModules} size={invite.qrSize} label="Your invite code" /></div></div>
                <div className="invite card">
                  <div className="field">
                    <span className="label">Invite link (single use, expires {new Date(invite.expiresAtMs).toLocaleString()})</span>
                    <p className="mono-wrap" aria-label="Invite link">{invite.link}</p>
                  </div>
                  <p className="hint">Send it over a channel you trust, or let them read the code above with their camera app and paste the link. Anyone who gets it first can use it. Contacts added this way start as <b>not verified</b>.</p>
                </div>
              </>
            ) : (
              <div className="center stack-sm">
                <p className="hint">An invite is single use and expires after 24 hours.</p>
                <button className="btn btn-primary btn-block" type="button" disabled={busy} onClick={() => void make()}>{busy ? "Creating…" : "Create invite"}</button>
              </div>
            )
          ) : (
            <form className="stack" autoComplete="off" onSubmit={(e) => void accept(e)}>
              <div className="field">
                <label htmlFor="inv-link">Paste their invite link</label>
                <div className="input mono"><input id="inv-link" spellCheck={false} value={link} onChange={(e) => setLink(e.target.value)} placeholder="veil://invite/…" /></div>
              </div>
              <button className="btn btn-primary btn-block" type="submit" disabled={busy || !link.trim()}>{busy ? "Connecting…" : "Add contact"}</button>
            </form>
          )}
          {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
        </div>
      </div>
    </div>
  );
}

export function ContactProfile({ contact, nav, onChanged }: { contact: ContactView; nav: Nav; onChanged: () => void }) {
  const [safety, setSafety] = useState<SafetyView | null>(null);
  const [name, setName] = useState(contact.name);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void ipc.safety(contact.id).then(setSafety, () => setError("Safety number unavailable"));
  }, [contact.id, contact.verified]);

  async function verify(v: boolean) {
    try {
      await ipc.setVerified(contact.id, v);
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not change verification");
    }
  }

  async function rename(e: FormEvent) {
    e.preventDefault();
    try {
      await ipc.rename(contact.id, name.trim());
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not rename");
    }
  }

  return (
    <div className="m-screen push">
      <TopBar title={contact.name} onBack={() => nav({ screen: "chat", contact: contact.id })} />
      <div className="m-body">
        <div className="safety">
          {contact.verified ? (
            <Banner tone="neutral" icon="shield-check"><strong>Verified</strong><p>If this number ever changes, Veil treats them as a new, unverified contact and never sends to the old conversation silently.</p></Banner>
          ) : (
            <Banner tone="info" icon="shield"><strong>Not verified</strong><p>Compare these numbers with {contact.name} in person or on a call you trust. If they match, no one is in the middle.</p></Banner>
          )}
          {safety ? (
            <div className="safety-num card">
              <div className="safety-grid" aria-label="Safety number">{safety.groups.map((g, i) => <span key={i}>{g}</span>)}</div>
            </div>
          ) : null}
          <div className="safety-actions">
            {contact.verified ? (
              <button className="btn btn-secondary btn-block" type="button" onClick={() => void verify(false)}>Clear verification</button>
            ) : (
              <button className="btn btn-primary btn-block" type="button" onClick={() => void verify(true)}><Icon name="check" />Numbers match: mark as verified</button>
            )}
          </div>
          <form className="stack" onSubmit={(e) => void rename(e)}>
            <div className="field">
              <label htmlFor="cname">Name (only on this device)</label>
              <div className="input"><input id="cname" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} /></div>
            </div>
            <button className="btn btn-secondary btn-block" type="submit">Save name</button>
          </form>
          {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
          <p className="hint center">Safety numbers are derived from both identity keys. They never leave your devices.</p>
        </div>
      </div>
    </div>
  );
}
