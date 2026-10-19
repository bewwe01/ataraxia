import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { ipc, IpcError, type ContactView, type Me, type MessageView } from "../ipc";
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

export function ChatList({ contacts, me, nav }: { contacts: ContactView[]; me: Me | null; nav: Nav }) {
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
                  aria-label={[c.name, c.verified ? "verified" : "not verified", c.unread ? `${c.unread} unread` : ""].filter(Boolean).join(", ")}
                >
                  <Avatar initials={c.initials} hue={c.hue} />
                  <div className="conv-main">
                    <div className="conv-top">
                      <span className="conv-name">{c.name}</span>
                      <VerifiedMark verified={c.verified} />
                      <time className={c.unread ? "unread" : ""}>{timeLabel(c.lastAtMs)}</time>
                    </div>
                    <div className="conv-bottom">
                      <span className="conv-preview">{c.lastText === null ? "No messages yet" : `${c.lastMine ? "You: " : ""}${c.lastText}`}</span>
                      <span className="conv-flags">{c.unread ? <span className="badge">{c.unread}</span> : null}</span>
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
  received: null,
};

export function Chat({ contact, me, nav, version }: { contact: ContactView; me: Me | null; nav: Nav; version: number }) {
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    void ipc.messages(contact.id).then((m) => {
      if (live) setMessages(m);
    });
    void ipc.markRead(contact.id);
    return () => {
      live = false;
    };
  }, [contact.id, version]);

  useEffect(() => {
    end.current?.scrollIntoView({ block: "end" });
  }, [messages.length]);

  async function send(e?: FormEvent) {
    e?.preventDefault();
    const body = text.trim();
    if (!body) return;
    setError(null);
    try {
      const m = await ipc.send(contact.id, body);
      setText("");
      setMessages((prev) => [...prev, m]);
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Not sent");
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
            <span className="who-name">{contact.name}<VerifiedMark verified={contact.verified} /></span>
            <span className="who-sub">
              {contact.verified ? null : <span>Not verified · </span>}
              <span className="transport relay"><Icon name="shield" />Relayed · IP hidden</span>
            </span>
          </span>
        </button>
      </header>
      <ConnectionBar me={me} />
      {!contact.verified ? (
        <Banner tone="info" icon="shield">
          <p>Not verified yet. <button className="link-btn" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })}>Compare safety numbers</button> to be sure no one is in the middle.</p>
        </Banner>
      ) : null}
      <div className="msgs chat-scroll" role="log" aria-live="polite">
        {messages.map((m) => {
          const st = m.mine ? STATUS[m.status] : null;
          return (
            <div key={m.id} className={`msg ${m.mine ? "out" : "in"}`}>
              <div className="bubble">
                {m.text}
                <span className="meta">
                  <time>{timeLabel(m.atMs)}</time>
                  {st ? (<><Icon name={st[0]} /><span className="sr-only">{st[1]}</span></>) : null}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={end} />
      </div>
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      <form className="composer" autoComplete="off" onSubmit={(e) => void send(e)}>
        <div className="box">
          <label className="sr-only" htmlFor="composer">Message {contact.name}</label>
          <textarea id="composer" rows={1} placeholder="Message" spellCheck value={text} maxLength={62464} onChange={(e) => setText(e.target.value)} onKeyDown={onKey} />
        </div>
        <button className="icon-btn accent send-btn" type="submit" aria-label="Send"><Icon name="send" /></button>
      </form>
    </div>
  );
}
