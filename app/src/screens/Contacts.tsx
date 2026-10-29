import { useEffect, useRef, useState, type FormEvent } from "react";
import { INVITE_PREFIX, ipc, IpcError, TIMERS, timerName, type ContactView, type InviteView, type SafetyView } from "../ipc";
import { Avatar, Banner, Icon, QrCode, Segmented, ToggleRow, TopBar } from "../ui";
import { PictureCropper } from "../components/Profile";
import { preparePicture, type Crop } from "../pictures";
import { Scanner } from "../components/Scanner";
import { HuePicker, WallpaperPicker } from "../components/Look";
import { useChatWallpaper } from "../wallpaper";
import { KeyWarning, type Nav } from "./Chats";

export function AddContact({ nav }: { nav: Nav }) {
  const [tab, setTab] = useState<"mine" | "theirs">("mine");
  const [invite, setInvite] = useState<InviteView | null>(null);
  const [link, setLink] = useState("");
  const [scanning, setScanning] = useState(false);
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

  async function accept(e?: FormEvent, scanned?: string) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = await ipc.acceptInvite((scanned ?? link).trim());
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
              {scanning ? (
                <>
                  <Scanner
                    hint="Point at their invite code"
                    onCode={(text) => {
                      setScanning(false);
                      // The link exactly as encoded; Rust checks the rest.
                      const scanned = text.trim();
                      if (scanned.startsWith(INVITE_PREFIX)) void accept(undefined, scanned);
                      else setError("That is not a Veil invite code.");
                    }}
                  />
                  <button className="btn btn-secondary btn-block" type="button" onClick={() => setScanning(false)}>Stop scanning</button>
                </>
              ) : (
                <button className="btn btn-secondary btn-block" type="button" disabled={busy} onClick={() => { setError(null); setScanning(true); }}><Icon name="scan" />Scan their code</button>
              )}
              <div className="field">
                <label htmlFor="inv-link">Paste their invite link</label>
                <div className="input mono"><input id="inv-link" spellCheck={false} value={link} onChange={(e) => setLink(e.target.value)} placeholder={`${INVITE_PREFIX}…`} /></div>
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
  const [confirmDelete, setConfirmDelete] = useState(false);
  const wallpaper = useChatWallpaper(contact);
  const [picked, setPicked] = useState<File | null>(null);
  const pictureFile = useRef<HTMLInputElement>(null);
  useEffect(() => setName(contact.name), [contact.name]);
  const [verifyMode, setVerifyMode] = useState<"show" | "scan">("show");
  const [verifyResult, setVerifyResult] = useState<null | "match" | "mismatch">(null);
  const deleteBtn = useRef<HTMLButtonElement>(null);
  const reopenFocus = useRef(false);

  // Focus goes back to "Delete contact" when the confirmation closes (review M1-13).
  useEffect(() => {
    if (!confirmDelete && reopenFocus.current) {
      reopenFocus.current = false;
      deleteBtn.current?.focus();
    }
  }, [confirmDelete]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void ipc.safety(contact.id).then(setSafety, () => setError("Safety number unavailable"));
  }, [contact.id, contact.verified]);

  async function scanned(code: string) {
    setVerifyMode("show");
    setError(null);
    try {
      const ok = await ipc.verifyScanned(contact.id, code);
      setVerifyResult(ok ? "match" : "mismatch");
      if (ok) onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not check the code");
    }
  }

  async function act(f: () => Promise<void>, fallback: string) {
    setBusy(true);
    setError(null);
    try {
      await f();
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : fallback);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await ipc.deleteContact(contact.id);
      onChanged();
      nav({ screen: "chats" });
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not delete");
      setBusy(false);
    }
  }

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
      await ipc.setNickname(contact.id, name.trim());
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not rename");
    }
  }

  async function localPicture(c: Crop) {
    const f = picked;
    setPicked(null);
    if (!f) return;
    await act(async () => ipc.setContactPicture(contact.id, await preparePicture(f, c)), "Could not set the picture");
  }

  return (
    <div className="m-screen push">
      <TopBar title={contact.name} onBack={() => nav({ screen: "chat", contact: contact.id })} />
      <div className="m-body">
        <div className="safety">
          <div className="stack-sm contact-head">
            <Avatar initials={contact.initials} hue={contact.hue} size="xxl" owner={contact.id} picture={contact.picture} />
            <h2>{contact.name}</h2>
            {contact.theirName ? <p className="hint">Calls themself “{contact.theirName}”</p> : null}
            {contact.status ? <p className="their-status">{contact.status}</p> : null}
          </div>
          <KeyWarning contact={contact} nav={nav} onChanged={onChanged} />
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
          <div className="stack-sm">
            <span className="label">Verify in person</span>
            <Segmented<"show" | "scan">
              name="verify-mode"
              label="Verify in person"
              value={verifyMode}
              options={[["show", "Show my code"], ["scan", "Scan their code"]]}
              onChange={(m) => { setVerifyResult(null); setVerifyMode(m); }}
            />
            {verifyMode === "show" && safety ? (
              <div className="qr-wrap"><div className="qr-card"><QrCode modules={safety.qrModules} size={safety.qrSize} label={`Your safety code for ${contact.name}`} /></div></div>
            ) : null}
            {verifyMode === "scan" ? <Scanner hint={`Point at ${contact.name}'s safety code`} onCode={(t) => void scanned(t)} /> : null}
            {verifyResult === "match" ? <Banner tone="neutral" icon="shield-check"><strong>Codes match</strong><p>{contact.name} is now verified. No one is in the middle.</p></Banner> : null}
            {verifyResult === "mismatch" ? (
              <div role="alert"><Banner tone="danger" icon="shield-alert"><strong>Codes do not match</strong><p>This is not the phone of the {contact.name} you are talking to here, or someone is in the middle. Do not mark them as verified.</p></Banner></div>
            ) : null}
            <p className="hint">Each of you opens this page: one shows the code, the other scans it. A match marks {contact.name} as verified.</p>
          </div>
          <div className="safety-actions">
            {contact.verified ? (
              <button className="btn btn-secondary btn-block" type="button" onClick={() => void verify(false)}>Clear verification</button>
            ) : (
              <button className="btn btn-primary btn-block" type="button" onClick={() => void verify(true)}><Icon name="check" />Numbers match: mark as verified</button>
            )}
          </div>
          <form className="stack" onSubmit={(e) => void rename(e)}>
            <div className="field">
              <label htmlFor="cname">Nickname (only on this device)</label>
              <div className="input"><input id="cname" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} /></div>
            </div>
            <button className="btn btn-secondary btn-block" type="submit">Save nickname</button>
            {contact.nickname && contact.theirName ? (
              <button className="btn btn-ghost btn-block" type="button" disabled={busy} onClick={() => void act(() => ipc.setNickname(contact.id, null), "Could not change the name")}>
                Use their name, “{contact.theirName}”
              </button>
            ) : null}
          </form>

          <div className="field">
            <span className="label">Picture only you see</span>
            <div className="banner-actions">
              <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => pictureFile.current?.click()}><Icon name="image" />Choose picture</button>
              {contact.picture?.startsWith("l") ? (
                <button className="btn btn-danger-ghost" type="button" disabled={busy} onClick={() => void act(() => ipc.setContactPicture(contact.id, null), "Could not remove the picture")}>Remove</button>
              ) : null}
            </div>
            <input ref={pictureFile} type="file" accept="image/*" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) setPicked(f); }} />
            {picked ? <PictureCropper file={picked} onDone={(c) => void localPicture(c)} onCancel={() => setPicked(null)} /> : null}
            <p className="hint">Shown instead of theirs, on this device only. They are not told.</p>
          </div>
          <div className="group card">
            <ToggleRow id="hide-picture" icon="eye-off" title={`Hide my picture from ${contact.name}`} sub="Whatever Settings says, they do not get your picture. If they had it, it is taken back from their screen." checked={contact.pictureHidden} disabled={busy} onChange={(v) => void act(() => ipc.setPictureHidden(contact.id, v), "Could not change this")} />
          </div>

          <div className="field">
            <span className="label">Disappearing messages</span>
            <div className="input select-field">
            <select
              className="select"
              aria-label="Disappearing messages"
              value={contact.timerSecs}
              disabled={busy || contact.blocked}
              onChange={(e) => void act(() => ipc.setTimer(contact.id, Number(e.target.value)), "Could not change the timer")}
            >
              {TIMERS.some(([s]) => s === contact.timerSecs) ? null : <option value={contact.timerSecs}>{timerName(contact.timerSecs)}</option>}
              {TIMERS.map(([s, label]) => <option key={s} value={s}>{label}</option>)}
            </select>
            <Icon name="chevron-down" className="select-chevron" />
            </div>
            <p className="hint">Applies to both of you, for new messages. They are deleted from both phones that long after they arrive. Anyone can still copy or photograph them before that.</p>
          </div>

          <div className="field">
            <span className="label">Chat colour</span>
            <HuePicker name={`chat-hue-${contact.id}`} label="Chat colour" none="App accent" value={contact.accentHue} onChange={(h) => void act(() => ipc.setChatAccent(contact.id, h), "Could not change the colour")} />
          </div>
          <div className="field">
            <span className="label">Chat wallpaper</span>
            <WallpaperPicker contact={contact.id} value={contact.wallpaper} photoUrl={wallpaper.photoUrl} />
          </div>

          <div className="stack-sm">
            {contact.blocked ? (
              <button className="btn btn-secondary btn-block" type="button" disabled={busy} onClick={() => void act(() => ipc.setBlocked(contact.id, false), "Could not unblock")}>Unblock {contact.name}</button>
            ) : (
              <button className="btn btn-secondary btn-block" type="button" disabled={busy} onClick={() => void act(() => ipc.setBlocked(contact.id, true), "Could not block")}><Icon name="ban" />Block {contact.name}</button>
            )}
            <p className="hint">
              {contact.blocked
                ? "Unblocking needs the relay: Veil sends them a new address to write to."
                : contact.unblockPending
                  ? "Unblocked. Veil is still trying to send them their new address; until it arrives, their messages cannot reach you."
                  : "The relay will refuse their messages. They are not told, but they can notice that their messages fail."}
            </p>
            {confirmDelete ? (
              <div role="alertdialog" aria-labelledby="del-t" aria-describedby="del-d">
                <Banner tone="danger" icon="trash">
                  <strong id="del-t">Delete {contact.name}?</strong>
                  <p id="del-d">The conversation and the encryption session are deleted from this device, and the relay refuses their messages. To talk again, one of you needs a new invite. This cannot be undone.</p>
                  <div className="banner-actions">
                    <button className="btn btn-secondary" type="button" autoFocus onClick={() => { reopenFocus.current = true; setConfirmDelete(false); }}>Cancel</button>
                    <button className="btn btn-danger" type="button" disabled={busy} onClick={() => void remove()}>Delete</button>
                  </div>
                </Banner>
              </div>
            ) : (
              <button ref={deleteBtn} className="btn btn-danger-ghost btn-block" type="button" disabled={busy} onClick={() => setConfirmDelete(true)}><Icon name="trash" />Delete contact</button>
            )}
          </div>
          {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
          <p className="hint center">Safety numbers are derived from both identity keys. They never leave your devices.</p>
        </div>
      </div>
    </div>
  );
}
