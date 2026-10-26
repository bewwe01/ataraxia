import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { ipc, IpcError, timerName, timerShort, type ContactView, type Me, type MessageView } from "../ipc";
import { Avatar, Banner, Icon, TopBar, VerifiedMark, timeLabel } from "../ui";

export type Nav = (to: Route) => void;
export type Route =
  | { screen: "chats" }
  | { screen: "chat"; contact: number }
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

export function Chat({ contact, me, nav, version, typing, onChanged }: { contact: ContactView; me: Me | null; nav: Nav; version: number; typing: boolean; onChanged: () => void }) {
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    ipc.messages(contact.id).then(
      (m) => {
        if (live) setMessages(m);
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

  useEffect(() => {
    end.current?.scrollIntoView({ block: "end" });
  }, [messages.length, typing]);

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
    void ipc.typing(contact.id, value.trim() !== "").catch(() => undefined);
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

  async function send(e?: FormEvent) {
    e?.preventDefault();
    const body = text.trim();
    if (!body || sending) return;
    setSending(true);
    setError(null);
    try {
      const m = await ipc.send(contact.id, body);
      setText("");
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
    }
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
          return (
            <div key={m.id} className={`msg ${m.mine ? "out" : "in"}`}>
              <div className="bubble">
                {m.text}
                <span className="meta">
                  {m.expiresAtMs !== null ? (<><Icon name="timer" /><span className="sr-only">disappears</span></>) : null}
                  <time>{timeLabel(m.atMs)}</time>
                  {st ? (<><Icon name={st[0]} /><span className="sr-only">{st[1]}</span></>) : null}
                </span>
              </div>
            </div>
          );
        })}
        {typing ? <div className="typing-bubble" role="status" aria-label={`${contact.name} is typing`}><Dots /></div> : null}
        <div ref={end} />
      </div>
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
        <form className="composer" autoComplete="off" onSubmit={(e) => void send(e)}>
          <div className="box">
            <label className="sr-only" htmlFor="composer">Message {contact.name}</label>
            <textarea id="composer" rows={1} placeholder="Message" spellCheck value={text} maxLength={62464} onChange={(e) => edit(e.target.value)} onKeyDown={onKey} />
          </div>
          <button className="icon-btn accent send-btn" type="submit" aria-label="Send" disabled={sending}><Icon name="send" /></button>
        </form>
      )}
    </div>
  );
}
