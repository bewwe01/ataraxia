import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type KeyboardEvent } from "react";
import { AttachmentBody, PhotoViewer } from "../components/Attachment";
import { formatDuration, MAX_VOICE_MS, prepareFile, startRecording, TooLarge, type Recording } from "../media";
import { EDIT_WINDOW_MS, ipc, IpcError, timerName, timerShort, type ContactView, type Me, type MessageView } from "../ipc";
import { Avatar, Banner, Icon, TopBar, VerifiedMark, timeLabel } from "../ui";

export type Nav = (to: Route) => void;
export type Route =
  | { screen: "chats" }
  | { screen: "chat"; contact: number; focus?: number | undefined }
  | { screen: "search" }
  | { screen: "add" }
  | { screen: "contact"; contact: number }
  | { screen: "settings" };

export function ConnectionBar({ me }: { me: Me | null }) {
  if (!me || me.connection === "online") return null;
  return (
    <div className={`conn-bar ${me.connection === "connecting" ? "reconnecting" : "offline"}`} role="status">
      <Icon name="refresh" className="icon-sm spin" />
      {me.connection === "connecting" ? "Connecting to relay…" : "Relay unreachable; messages wait until it is back"}
    </div>
  );
}

function Dots() {
  return <span className="dots" aria-hidden="true"><i></i><i></i><i></i></span>;
}

export function TimerChip({ secs }: { secs: number }) {
  if (secs === 0) return null;
  return (
    <span className="timer-chip" title={`Disappearing messages: ${timerName(secs)}`}>
      <Icon name="timer" />{timerShort(secs)}<span className="sr-only">disappearing messages {timerName(secs)}</span>
    </span>
  );
}

/** "The safety number is new for this name" (INV-ID-2). Never merged with the old contact. */
export function KeyWarning({ contact, nav, onChanged }: { contact: ContactView; nav: Nav; onChanged: () => void }) {
  if (!contact.keyWarning) return null;
  return (
    <div role="alert">
      <Banner tone="warning" icon="alert-triangle">
        <strong>Is this really {contact.name}?</strong>
        <p>You already have a contact with this name, and this one has a different safety number. If {contact.name} reinstalled Veil or got a new phone, that is expected. If not, this may be someone else. This conversation is kept apart from the old one.</p>
        <div className="banner-actions">
          <button className="btn btn-primary" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })}>Compare safety numbers</button>
          <button className="btn btn-secondary" type="button" onClick={() => void ipc.dismissKeyWarning(contact.id).then(onChanged, () => undefined)}>Dismiss</button>
        </div>
      </Banner>
    </div>
  );
}

export function ChatList({ contacts, me, nav, typing }: { contacts: ContactView[]; me: Me | null; nav: Nav; typing: ReadonlySet<number> }) {
  return (
    <div className="m-screen tab">
      <ConnectionBar me={me} />
      <header className="m-appbar">
        <h1>Chats</h1>
        <span className="spacer" />
        <button className="icon-btn" type="button" aria-label="Search messages" onClick={() => nav({ screen: "search" })}><Icon name="search" /></button>
        <button className="icon-btn" type="button" aria-label="Add contact" onClick={() => nav({ screen: "add" })}><Icon name="user-plus" /></button>
        <button className="icon-btn" type="button" aria-label="Settings" onClick={() => nav({ screen: "settings" })}><Icon name="settings" /></button>
      </header>
      <div className="m-body">
        {contacts.length === 0 ? (
          <div className="state">
            <h2>No conversations yet</h2>
            <p className="muted">Add a contact by showing your invite code, or by pasting theirs.</p>
            <button className="btn btn-primary" type="button" onClick={() => nav({ screen: "add" })}>
              <Icon name="user-plus" />Add a contact
            </button>
          </div>
        ) : (
          <ul className="conv-list" aria-label="Conversations">
            {contacts.map((c) => (
              <li key={c.id}>
                <button
                  className="conv"
                  type="button"
                  onClick={() => nav({ screen: "chat", contact: c.id })}
                  aria-label={[
                    c.name,
                    c.verified ? "verified" : "not verified",
                    c.keyWarning ? "new safety number" : "",
                    c.blocked ? "blocked" : "",
                    c.timerSecs ? `disappearing messages ${timerName(c.timerSecs)}` : "",
                    typing.has(c.id) ? "typing" : "",
                    c.unread ? `${c.unread} unread` : "",
                  ].filter(Boolean).join(", ")}
                >
                  <Avatar initials={c.initials} hue={c.hue} />
                  <div className="conv-main">
                    <div className="conv-top">
                      <span className="conv-name">{c.name}</span>
                      <VerifiedMark verified={c.verified} />
                      <time className={c.unread ? "unread" : ""}>{timeLabel(c.lastAtMs)}</time>
                    </div>
                    <div className="conv-bottom">
                      {typing.has(c.id) ? (
                        <span className="conv-preview typing"><Dots />typing</span>
                      ) : c.keyWarning ? (
                        <span className="conv-preview warn"><Icon name="alert-triangle" className="icon-sm" />New safety number</span>
                      ) : (
                        <span className="conv-preview">{c.blocked ? "Blocked" : c.lastText === null ? "No messages yet" : `${c.lastMine ? "You: " : ""}${c.lastText}`}</span>
                      )}
                      <span className="conv-flags">
                        {c.blocked ? <Icon name="ban" className="icon-sm" /> : null}
                        <TimerChip secs={c.timerSecs} />
                        {c.unread ? <span className="badge">{c.unread}</span> : null}
                      </span>
                    </div>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

const STATUS: Record<MessageView["status"], [string, string] | null> = {
  sending: ["clock", "Sending"],
  sent: ["check", "Sent"],
  failed: ["alert-circle", "Not sent"],
  delivered: ["check-double", "Delivered"],
  // A different shape, not only a different colour, from "Delivered".
  read: ["eye", "Read"],
  received: null,
};

function TimerNotice({ m, name }: { m: MessageView; name: string }) {
  const secs = m.timerSecs ?? 0;
  const who = m.mine ? "You" : name;
  return (
    <div className="sys-msg">
      <Icon name="timer" />
      {secs === 0 ? `${who} turned off disappearing messages` : `${who} set disappearing messages to ${timerName(secs)}`}
    </div>
  );
}

/** Quick reactions offered on a message. */
const QUICK = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

/** Reactions grouped by emoji, as `.reactions` chips. */
function groupReactions(m: MessageView): { emoji: string; n: number; mine: boolean }[] {
  const out: { emoji: string; n: number; mine: boolean }[] = [];
  for (const r of m.reactions) {
    const g = out.find((x) => x.emoji === r.emoji);
    if (g) {
      g.n += 1;
      g.mine ||= r.mine;
    } else out.push({ emoji: r.emoji, n: 1, mine: r.mine });
  }
  return out;
}

function withinEditWindow(m: MessageView): boolean {
  return m.mine && m.actionable && Date.now() - m.atMs < EDIT_WINDOW_MS;
}

/** What one can do with a message: react, reply, edit, delete (DESIGN.md `.dialog`). */
function MessageActions({ m, name, blocked, onClose, onReply, onEdit, onDone }: {
  m: MessageView;
  name: string;
  blocked: boolean;
  onClose: () => void;
  onReply: () => void;
  onEdit: () => void;
  /** `removed`: the message is gone from the list, so focus goes to the composer. */
  onDone: (error?: string, removed?: boolean) => void;
}) {
  const [confirm, setConfirm] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const mineEmoji = m.reactions.find((r) => r.mine)?.emoji ?? null;

  // Escape closes from anywhere; Tab stays inside the dialog (DESIGN.md §6, review M2-4).
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
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
  }, [onClose]);
  const canChange = withinEditWindow(m) && !blocked;

  async function run(f: () => Promise<void>, fallback: string, removed = false) {
    try {
      await f();
      onDone(undefined, removed);
    } catch (err) {
      onDone(err instanceof IpcError ? err.message : fallback);
    }
  }

  return (
    <div className="scrim" onClick={onClose}>
      <div ref={box} className="dialog glass-strong msg-dialog" role="dialog" aria-modal="true" aria-labelledby="ma-t" onClick={(e) => e.stopPropagation()}>
        <h2 id="ma-t" className="sr-only">Message from {m.mine ? "you" : name}</h2>
        {m.actionable && !blocked ? (
          <div className="emoji-row" role="group" aria-label="React">
            {QUICK.map((e, i) => (
              <button
                key={e}
                className={`emoji-btn ${mineEmoji === e ? "mine" : ""}`}
                type="button"
                autoFocus={i === 0}
                aria-pressed={mineEmoji === e}
                aria-label={mineEmoji === e ? `Remove ${e}` : `React with ${e}`}
                onClick={() => void run(() => ipc.react(m.id, mineEmoji === e ? null : e), "Could not react")}
              >
                {e}
                {mineEmoji === e ? <Icon name="check" className="mine-mark" /> : null}
              </button>
            ))}
          </div>
        ) : null}
        <div className="dialog-actions">
          {m.actionable && !blocked ? <button className="btn btn-secondary" type="button" onClick={onReply}><Icon name="reply" />Reply</button> : null}
          {canChange ? <button className="btn btn-secondary" type="button" onClick={onEdit}><Icon name="edit" />Edit</button> : null}
          {confirm ? (
            <div role="alertdialog" aria-labelledby="del-q">
              <p id="del-q">{canChange ? "Delete for you only, or for both of you?" : "Delete this message from this device?"}</p>
              <div className="dialog-actions">
                <button className="btn btn-danger-ghost" type="button" autoFocus onClick={() => void run(() => ipc.deleteForMe(m.id), "Could not delete", true)}>Delete for me</button>
                {canChange ? <button className="btn btn-danger" type="button" onClick={() => void run(() => ipc.deleteForEveryone(m.id), "Could not delete")}>Delete for everyone</button> : null}
              </div>
              {canChange ? <p className="hint">{name} may already have seen it, and an old version of Veil keeps it.</p> : null}
            </div>
          ) : (
            <button className="btn btn-danger-ghost" type="button" autoFocus={!m.actionable || blocked} onClick={() => setConfirm(true)}><Icon name="trash" />Delete…</button>
          )}
          <button className="btn btn-ghost" type="button" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

export function Chat({ contact, me, nav, version, typing, focus, onChanged }: { contact: ContactView; me: Me | null; nav: Nav; version: number; typing: boolean; focus?: number | undefined; onChanged: () => void }) {
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [actionsFor, setActionsFor] = useState<MessageView | null>(null);
  const [replyTo, setReplyTo] = useState<MessageView | null>(null);
  const [editing, setEditing] = useState<MessageView | null>(null);
  const [found, setFound] = useState<number | undefined>(focus);
  const [loaded, setLoaded] = useState(false);
  const [tooOld, setTooOld] = useState(false);
  const opener = useRef<HTMLElement | null>(null);
  const [viewing, setViewing] = useState<MessageView | null>(null);
  const [recording, setRecording] = useState<Recording | null>(null);
  const [recMs, setRecMs] = useState(0);
  const picker = useRef<HTMLInputElement>(null);
  const end = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let live = true;
    ipc.messages(contact.id).then(
      (m) => {
        if (!live) return;
        setMessages(m);
        setLoaded(true);
      },
      () => {
        if (live) setError("Could not load messages");
      },
    );
    return () => {
      live = false;
    };
  }, [contact.id, version]);

  // Read means seen: only while the window is visible and focused, and again when the user
  // comes back to it (review M1-5). markRead also sends read receipts if they are on.
  useEffect(() => {
    const seen = () => {
      if (document.visibilityState === "visible" && document.hasFocus()) void ipc.markRead(contact.id).catch(() => undefined);
    };
    seen();
    document.addEventListener("visibilitychange", seen);
    window.addEventListener("focus", seen);
    return () => {
      document.removeEventListener("visibilitychange", seen);
      window.removeEventListener("focus", seen);
    };
  }, [contact.id, version]);

  // Scroll to the end on new messages, or to a search result once it is loaded.
  useEffect(() => {
    if (found !== undefined) {
      const el = document.getElementById(`msg-${found}`);
      if (el) {
        el.scrollIntoView({ block: "center" });
        const t = window.setTimeout(() => setFound(undefined), 2500);
        return () => window.clearTimeout(t);
      }
      // Older than the messages shown here: say so, and go back to following new ones.
      if (loaded) {
        setTooOld(true);
        setFound(undefined);
      }
      return;
    }
    end.current?.scrollIntoView({ block: "end" });
  }, [messages.length, typing, found, loaded]);

  // Tell the contact we stopped typing when leaving the chat.
  useEffect(() => () => void ipc.typing(contact.id, false).catch(() => undefined), [contact.id]);

  // Messages whose timer runs out disappear from view on time; Rust deletes them too.
  useEffect(() => {
    const next = Math.min(...messages.map((m) => m.expiresAtMs ?? Infinity));
    if (!Number.isFinite(next)) return;
    // Browsers fire at once for delays past 2^31-1 ms (about 24.8 days), so clamp; and keep
    // the same array when nothing expired, or this effect would loop (review M1-1).
    const delay = Math.min(Math.max(0, next - Date.now()) + 50, 2_147_483_647);
    const t = window.setTimeout(() => {
      const now = Date.now();
      setMessages((prev) => {
        const kept = prev.filter((m) => m.expiresAtMs === null || m.expiresAtMs > now);
        return kept.length === prev.length ? prev : kept;
      });
    }, delay);
    return () => window.clearTimeout(t);
  }, [messages]);

  function edit(value: string) {
    setText(value);
    if (!editing) void ipc.typing(contact.id, value.trim() !== "").catch(() => undefined);
  }

  async function unblock() {
    setError(null);
    try {
      await ipc.setBlocked(contact.id, false);
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Could not unblock");
    }
  }

  function cancelContext() {
    if (editing) setText("");
    setReplyTo(null);
    setEditing(null);
  }

  async function send(e?: FormEvent) {
    e?.preventDefault();
    const body = text.trim();
    if (!body || sending) return;
    setSending(true);
    setError(null);
    try {
      if (editing) {
        await ipc.editMessage(editing.id, body);
        setEditing(null);
        setText("");
        return;
      }
      const m = replyTo ? await ipc.reply(contact.id, body, replyTo.id) : await ipc.send(contact.id, body);
      setText("");
      setReplyTo(null);
      setMessages((prev) => [...prev, m]);
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Not sent");
    } finally {
      setSending(false);
    }
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    } else if (e.key === "Escape" && (replyTo || editing)) {
      cancelContext();
    }
  }

  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setError(null);
    setSending(true);
    try {
      const m = await ipc.sendAttachment(contact.id, await prepareFile(file));
      setMessages((prev) => [...prev, m]);
    } catch (err) {
      setError(err instanceof TooLarge ? "Files can be up to 25 MB." : err instanceof IpcError ? err.message : "Could not send this file");
    } finally {
      setSending(false);
    }
  }

  async function startVoice() {
    setError(null);
    try {
      setRecording(await startRecording());
    } catch {
      setError("Veil could not use the microphone. Allow it for Veil in your device's settings.");
    }
  }

  // Elapsed time while recording.
  useEffect(() => {
    if (!recording) return;
    const t = window.setInterval(() => setRecMs(recording.elapsed()), 200);
    return () => window.clearInterval(t);
  }, [recording]);

  // Leaving the chat discards an unfinished recording (only on unmount: finishing one also
  // changes `recording`).
  const live = useRef<Recording | null>(null);
  live.current = recording;
  useEffect(() => () => live.current?.cancel(), []);

  async function finishVoice(send: boolean) {
    const r = recording;
    setRecording(null);
    setRecMs(0);
    if (!r) return;
    if (!send) {
      r.cancel();
      return;
    }
    setSending(true);
    try {
      const m = await ipc.sendAttachment(contact.id, await r.stop());
      setMessages((prev) => [...prev, m]);
    } catch (err) {
      setError(err instanceof TooLarge ? "That voice message is too long." : err instanceof IpcError ? err.message : "Could not send the voice message");
    } finally {
      setSending(false);
    }
  }

  function openActions(m: MessageView, from: HTMLElement) {
    setError(null);
    opener.current = from;
    setActionsFor(m);
  }

  /** Closes the action dialog and puts focus back where it was, or on the composer. */
  function closeActions(focusComposer = false) {
    setActionsFor(null);
    const back = opener.current;
    opener.current = null;
    window.setTimeout(() => {
      if (!focusComposer && back && back.isConnected) back.focus();
      else input.current?.focus();
    }, 0);
  }

  return (
    <div className="m-screen chat-screen">
      <header className="chat-hdr glass">
        <button className="icon-btn" type="button" aria-label="Back to chats" onClick={() => nav({ screen: "chats" })}><Icon name="back" /></button>
        <button className="who" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })} aria-label={`${contact.name}, view profile`}>
          <Avatar initials={contact.initials} hue={contact.hue} />
          <span className="who-text">
            <span className="who-name">{contact.name}<VerifiedMark verified={contact.verified} /><TimerChip secs={contact.timerSecs} /></span>
            <span className="who-sub">
              {typing ? (
                <span>typing…</span>
              ) : (
                <>
                  {contact.verified ? null : <span>Not verified · </span>}
                  <span className="transport relay"><Icon name="shield" />Relayed · IP hidden</span>
                </>
              )}
            </span>
          </span>
        </button>
      </header>
      <ConnectionBar me={me} />
      <KeyWarning contact={contact} nav={nav} onChanged={onChanged} />
      {!contact.verified && !contact.keyWarning ? (
        <Banner tone="info" icon="shield">
          <p>Not verified yet. <button className="link-btn" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })}>Compare safety numbers</button> to be sure no one is in the middle.</p>
        </Banner>
      ) : null}
      <div className="msgs chat-scroll" role="log" aria-live="polite">
        {messages.map((m) => {
          if (m.kind === "timer") return <TimerNotice key={m.id} m={m} name={contact.name} />;
          const st = m.mine ? STATUS[m.status] : null;
          const groups = groupReactions(m);
          return (
            <div key={m.id} id={`msg-${m.id}`} className={`msg ${m.mine ? "out" : "in"} ${found === m.id ? "found" : ""}`}>
              <div
                className={`bubble ${m.attachment?.kind === "image" ? "media" : ""}`}
                // A bubble with its own controls (play, save) is not itself a button: its
                // options sit in a separate button below it.
                {...(m.attachment
                  ? {}
                  : {
                      role: "button",
                      tabIndex: 0,
                      "aria-haspopup": "dialog" as const,
                      onClick: (e: React.MouseEvent<HTMLDivElement>) => openActions(m, e.currentTarget),
                      onKeyDown: (e: React.KeyboardEvent<HTMLDivElement>) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          openActions(m, e.currentTarget);
                        }
                      },
                    })}
              >
                {m.reply ? (
                  <span className="reply">
                    {m.reply.mine === null ? null : <b>{m.reply.mine ? "You" : contact.name}</b>}
                    <span>{m.reply.text || "Original message not available"}</span>
                  </span>
                ) : null}
                {m.deleted ? (
                  <span className="deleted-text"><Icon name="ban" />This message was deleted</span>
                ) : m.attachment ? (
                  <AttachmentBody m={m} onOpenImage={() => setViewing(m)} onError={setError} />
                ) : (
                  m.text
                )}
                <span className="meta">
                  {m.edited && !m.deleted ? <span className="edited">edited · </span> : null}
                  {m.expiresAtMs !== null ? (<><Icon name="timer" /><span className="sr-only">disappears</span></>) : null}
                  <time>{timeLabel(m.atMs)}</time>
                  {st ? (<><Icon name={st[0]} /><span className="sr-only">{st[1]}</span></>) : null}
                </span>
              </div>
              {m.attachment && !m.deleted ? (
                <button className="icon-btn msg-more" type="button" aria-haspopup="dialog" aria-label="Message options" onClick={(e) => openActions(m, e.currentTarget)}><Icon name="more" /></button>
              ) : null}
              {groups.length ? (
                <div className="reactions" role="group" aria-label="Reactions">
                  {groups.map((g) => (
                    <button
                      key={g.emoji}
                      className={`reaction ${g.mine ? "mine" : ""}`}
                      type="button"
                      disabled={!m.actionable || contact.blocked}
                      aria-pressed={g.mine}
                      aria-label={`${g.emoji} ${g.n}${g.mine ? ", including you. Remove yours" : `. React with ${g.emoji}`}`}
                      onClick={() => void ipc.react(m.id, g.mine ? null : g.emoji).catch((err: unknown) => setError(err instanceof IpcError ? err.message : "Could not react"))}
                    >
                      {g.emoji}{g.n > 1 ? <b>{g.n}</b> : null}
                      {g.mine ? <Icon name="check" className="mine-mark" /> : null}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
        {typing ? <div className="typing-bubble" role="status" aria-label={`${contact.name} is typing`}><Dots /></div> : null}
        <div ref={end} />
      </div>
      {tooOld ? <Banner tone="info" icon="info"><p>That message is older than the ones shown here.</p></Banner> : null}
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      {contact.blocked ? (
        <div className="composer blocked-bar">
          <Banner tone="neutral" icon="ban">
            <p>You blocked {contact.name}. They cannot send you messages.</p>
            <div className="banner-actions">
              <button className="btn btn-secondary" type="button" onClick={() => void unblock()}>Unblock</button>
            </div>
          </Banner>
        </div>
      ) : (
        <>
          {replyTo || editing ? (
            <div className="composer-ctx">
              <span className="reply">
                <b>{editing ? "Editing your message" : `Replying to ${replyTo?.mine ? "yourself" : contact.name}`}</b>
                <span>{(editing ?? replyTo)?.text}</span>
              </span>
              <button className="icon-btn" type="button" aria-label={editing ? "Cancel editing" : "Cancel reply"} onClick={cancelContext}><Icon name="x" /></button>
            </div>
          ) : null}
          {recording ? (
            <div className="composer recording-bar" role="status" aria-live="polite">
              <button className="icon-btn" type="button" aria-label="Discard voice message" onClick={() => void finishVoice(false)}><Icon name="trash" /></button>
              <span className="rec-dot" aria-hidden="true" />
              <span className="rec-time">Recording · {formatDuration(recMs)} / {formatDuration(MAX_VOICE_MS)}</span>
              <button className="icon-btn accent send-btn" type="button" aria-label="Send voice message" onClick={() => void finishVoice(true)}><Icon name="send" /></button>
            </div>
          ) : (
            <form className="composer" autoComplete="off" onSubmit={(e) => void send(e)}>
              {editing ? null : (
                <>
                  <input ref={picker} type="file" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => void pick(e)} />
                  <button className="icon-btn" type="button" aria-label="Attach a photo or file" disabled={sending} onClick={() => picker.current?.click()}><Icon name="paperclip" /></button>
                </>
              )}
              <div className="box">
                <label className="sr-only" htmlFor="composer">{editing ? "Edit message" : `Message ${contact.name}`}</label>
                <textarea ref={input} id="composer" rows={1} placeholder="Message" spellCheck value={text} maxLength={62464} onChange={(e) => edit(e.target.value)} onKeyDown={onKey} />
              </div>
              {text.trim() === "" && !editing && !replyTo ? (
                <button className="icon-btn accent send-btn" type="button" aria-label="Record a voice message" disabled={sending} onClick={() => void startVoice()}><Icon name="mic" /></button>
              ) : (
                <button className="icon-btn accent send-btn" type="submit" aria-label={editing ? "Save edit" : "Send"} disabled={sending}><Icon name={editing ? "check" : "send"} /></button>
              )}
            </form>
          )}
        </>
      )}
      {viewing ? <PhotoViewer m={viewing} onClose={() => setViewing(null)} onError={setError} /> : null}
      {actionsFor ? (
        <MessageActions
          m={actionsFor}
          name={contact.name}
          blocked={contact.blocked}
          onClose={closeActions}
          onReply={() => {
            setEditing(null);
            setReplyTo(actionsFor);
            closeActions(true);
          }}
          onEdit={() => {
            setReplyTo(null);
            setEditing(actionsFor);
            setText(actionsFor.text);
            closeActions(true);
          }}
          onDone={(err, removed) => {
            closeActions(removed === true);
            if (err) setError(err);
          }}
        />
      ) : null}
    </div>
  );
}
