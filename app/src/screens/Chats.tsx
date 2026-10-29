import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type KeyboardEvent } from "react";
import { AttachmentBody, PhotoViewer } from "../components/Attachment";
import { formatDuration, MAX_VOICE_MS, prepareFile, startRecording, TooLarge, type Recording } from "../media";
import { EDIT_WINDOW_MS, ipc, IpcError, timerName, timerShort, type ContactView, type Me, type MessageView } from "../ipc";
import { Avatar, Banner, Icon, TopBar, VerifiedMark, timeLabel, useDialogKeys } from "../ui";
import { SWIPE_AT_PX, useBubbleGestures } from "../gestures";
import { calls } from "../calls";
import { bubbleVars } from "../color";
import { ChatWallpaper } from "../wallpaper";

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

/**
 * "The safety number is new for this name" (INV-ID-2). Never merged with the old contact by
 * itself: the user decides. "It's them" moves the earlier conversation here and removes the
 * old contact; "Keep apart" leaves both.
 */
export function KeyWarning({ contact, nav, onChanged }: { contact: ContactView; nav: Nav; onChanged: () => void }) {
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!contact.keyWarning) return null;
  const prev = contact.previous;

  async function act(f: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await f();
      setConfirm(false);
      onChanged();
    } catch (err) {
      setError(err instanceof IpcError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div role="alert">
      <Banner tone={contact.verified ? "info" : "warning"} icon={contact.verified ? "shield-check" : "alert-triangle"}>
        {confirm ? null : contact.verified ? (
          <>
            <strong>Safety number verified.</strong>
            <p>{prev ? `Is this the ${contact.name} you talked to before? Then their earlier conversation can move here.` : "Keep this contact apart from the earlier one, or delete the one you no longer need."}</p>
          </>
        ) : (
          <>
            <strong>Is this really {contact.name}?</strong>
            <p>You already have a contact with this name, and this one has a different safety number. If {contact.name} reinstalled Veil or got a new phone, that is expected. If not, this may be someone else. Compare safety numbers to be sure.</p>
          </>
        )}
        {confirm ? (
          <div role="alertdialog" aria-labelledby={`kw-q-${contact.id}`}>
            {prev ? (
              <p id={`kw-q-${contact.id}`}>
                <strong>Move the conversation with your earlier contact “{prev.name}” here and remove that contact?</strong>{" "}
                That contact is {prev.verified ? "verified" : "not verified"}{prev.blocked ? " and blocked" : ""}{prev.lastAtMs !== null ? `, last message ${timeLabel(prev.lastAtMs)}` : ", with no messages"}. Only if you are sure this is them. This cannot be undone.
              </p>
            ) : (
              <p id={`kw-q-${contact.id}`}>Veil cannot tell which earlier contact this would replace (there is more than one, or it is gone). Keep them apart, or delete the one you no longer need.</p>
            )}
            <div className="banner-actions">
              {prev ? <button className="btn btn-primary" type="button" autoFocus disabled={busy} onClick={() => void act(() => ipc.acceptKeyChange(contact.id, prev.id))}>Yes, it's them</button> : null}
              <button className="btn btn-secondary" type="button" autoFocus={!prev} disabled={busy} onClick={() => setConfirm(false)}>Not now</button>
            </div>
          </div>
        ) : (
          <div className="banner-actions">
            {contact.verified ? null : <button className="btn btn-primary" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })}>Compare safety numbers</button>}
            <button className={`btn ${contact.verified ? "btn-primary" : "btn-secondary"}`} type="button" onClick={() => setConfirm(true)}>It's them…</button>
            <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => void act(() => ipc.dismissKeyWarning(contact.id))}>Keep apart</button>
          </div>
        )}
        {error ? <p className="field-error" role="alert">{error}</p> : null}
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
                  <Avatar initials={c.initials} hue={c.hue} owner={c.id} picture={c.picture} />
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
                        <span className="conv-preview">{c.blocked ? "Blocked" : c.lastText === null ? "No messages yet" : `${c.lastMine && !c.lastText.startsWith("📞") ? "You: " : ""}${c.lastText}`}</span>
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

/** "2:05", "1:02:09": how long a call lasted. */
function callLength(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = String(secs % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
}

/** A call line: how a call went (this device's own record). Tapping it calls back. */
function CallNotice({ m, contact }: { m: MessageView; contact: ContactView }) {
  const c = m.call;
  if (!c) return null;
  const name = contact.name;
  const kind = c.video ? "video" : "voice";
  const Kind = c.video ? "Video" : "Voice";
  const text =
    c.outcome === "ended" ? `${m.mine ? "Outgoing" : "Incoming"} ${kind} call · ${callLength(c.durationSecs)}`
    : c.outcome === "missed" ? `Missed ${kind} call`
    : c.outcome === "declined" ? `Declined ${kind} call`
    : c.outcome === "busy" ? `${name} was busy`
    : c.outcome === "unanswered" ? `${Kind} call not answered`
    : c.outcome === "cancelled" ? `Cancelled ${kind} call`
    : `${Kind} call failed`;
  const missed = c.outcome === "missed";
  const icon = c.outcome === "ended" ? (c.video ? "video" : "phone") : "phone-off";
  const body = (
    <>
      <Icon name={icon} />
      <span>{text}</span>
      <span className="call-line-time">{timeLabel(m.atMs)}</span>
    </>
  );
  return contact.blocked ? (
    <div className={`sys-msg call-line${missed ? " missed" : ""}`}>{body}</div>
  ) : (
    <button
      type="button"
      className={`sys-msg call-line${missed ? " missed" : ""}`}
      aria-label={`${text}, ${timeLabel(m.atMs)}. Call ${name} back`}
      onClick={() => void calls.start(contact.id, c.video)}
    >
      {body}
    </button>
  );
}

/** Quick reactions offered on a message. */
const QUICK = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

/** Reactions grouped by emoji, as `.reactions` chips, in the order they were first added. */
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

/** Different reactions one person may add to a message (Rust's `MAX_REACTIONS`). */
const MAX_REACTIONS = 3;

function myReactions(m: MessageView): Set<string> {
  return new Set(m.reactions.filter((r) => r.mine).map((r) => r.emoji));
}

/** A single emoji, as typed with the keyboard's emoji panel; null if it is not one. */
function oneEmoji(raw: string): string | null {
  const text = raw.trim();
  if (!text) return null;
  const first =
    typeof Intl.Segmenter === "function"
      ? (new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(text)[Symbol.iterator]().next().value?.segment ?? "")
      : Array.from(text)[0] ?? "";
  return /\p{Extended_Pictographic}|\p{Regional_Indicator}/u.test(first) ? first : null;
}

function withinEditWindow(m: MessageView): boolean {
  return m.mine && m.actionable && Date.now() - m.atMs < EDIT_WINDOW_MS;
}

/** What a message is, in a few words: for the action dialog and the reply bar. */
export function messageSummary(m: MessageView): string {
  if (m.deleted) return "This message was deleted";
  const a = m.attachment;
  if (a) {
    if (a.kind === "image") return "📷 Photo";
    if (a.kind === "voice") return `🎤 Voice message${a.durationMs ? `, ${formatDuration(a.durationMs)}` : ""}`;
    return `📎 ${a.name ?? "File"}`;
  }
  return m.text;
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
  const [picking, setPicking] = useState(false);
  const [custom, setCustom] = useState("");
  const [customError, setCustomError] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const mine = myReactions(m);
  const full = mine.size >= MAX_REACTIONS;
  const extra = [...mine].filter((e) => !QUICK.includes(e));

  // Escape closes from anywhere; Tab stays inside the dialog (DESIGN.md §6, review M2-4).
  useDialogKeys(box, onClose);
  const canChange = withinEditWindow(m) && !blocked;
  const canReact = m.actionable && !blocked;

  async function run(f: () => Promise<void>, fallback: string, removed = false) {
    try {
      await f();
      onDone(undefined, removed);
    } catch (err) {
      onDone(err instanceof IpcError ? err.message : fallback);
    }
  }

  function toggle(e: string) {
    void run(() => ipc.react(m.id, e, !mine.has(e)), "Could not react");
  }

  function addCustom(ev: FormEvent) {
    ev.preventDefault();
    const e = oneEmoji(custom);
    if (!e) {
      setCustomError("Choose one emoji from your keyboard.");
      return;
    }
    toggle(e);
  }

  return (
    <div className="scrim" onClick={onClose}>
      <div ref={box} className="dialog glass-strong msg-dialog" role="dialog" aria-modal="true" aria-labelledby="ma-t" onClick={(e) => e.stopPropagation()}>
        <h2 id="ma-t" className="sr-only">Message from {m.mine ? "you" : name}</h2>
        {/* Which message this is about, so a mis-tap is easy to see. */}
        <figure className={`msg-preview ${m.mine ? "out" : "in"}`}>
          <figcaption>{m.mine ? "You" : name} · {timeLabel(m.atMs)}</figcaption>
          <p>{messageSummary(m)}</p>
        </figure>
        {canReact ? (
          <>
            <div className="emoji-row" role="group" aria-label="React">
              {[...QUICK, ...extra].map((e, i) => {
                const on = mine.has(e);
                return (
                  <button
                    key={e}
                    className={`emoji-btn ${on ? "mine" : ""}`}
                    type="button"
                    autoFocus={i === 0}
                    disabled={!on && full}
                    aria-pressed={on}
                    aria-label={on ? `Remove ${e}` : `React with ${e}`}
                    onClick={() => toggle(e)}
                  >
                    {e}
                    {on ? <Icon name="check" className="mine-mark" /> : null}
                  </button>
                );
              })}
              <button className="emoji-btn more" type="button" disabled={full} aria-expanded={picking} aria-label="Another emoji" onClick={() => setPicking((v) => !v)}>
                <Icon name="plus" />
              </button>
            </div>
            {picking ? (
              <form className="emoji-custom" onSubmit={addCustom}>
                <label htmlFor="ma-emoji">Any emoji (use your keyboard's emoji key)</label>
                <div className="emoji-custom-row">
                  <div className="input"><input id="ma-emoji" autoFocus autoComplete="off" spellCheck={false} maxLength={32} value={custom} onChange={(e) => { setCustom(e.target.value); setCustomError(null); }} aria-invalid={customError !== null} aria-describedby={customError ? "ma-emoji-err" : undefined} /></div>
                  <button className="btn btn-primary" type="submit">React</button>
                </div>
                {customError ? <p id="ma-emoji-err" className="field-error" role="alert">{customError}</p> : null}
              </form>
            ) : null}
            <p className="hint">{full ? "That's 3 reactions. Tap one of yours to remove it." : "Up to 3 reactions. Tap one of yours again to remove it."}</p>
          </>
        ) : null}
        <div className="dialog-actions">
          {canReact ? <button className="btn btn-secondary" type="button" onClick={onReply}><Icon name="reply" />Reply</button> : null}
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
            <button className="btn btn-danger-ghost" type="button" autoFocus={!canReact} onClick={() => setConfirm(true)}><Icon name="trash" />Delete…</button>
          )}
          <button className="btn btn-ghost" type="button" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

/**
 * One message: hold (or right-click) for its actions, swipe right to reply, tap a quote to
 * go to the original. Reactions sit on the bubble's lower edge; tapping one adds or removes
 * yours. The "⋯" button gives keyboard and screen-reader users the same actions.
 */
function MessageRow({ m, contact, found, onActions, onReply, onJump, onOpenImage, onError }: {
  m: MessageView;
  contact: ContactView;
  found: boolean;
  onActions: (m: MessageView, from: HTMLElement) => void;
  onReply: (m: MessageView) => void;
  onJump: (id: number) => void;
  onOpenImage: (m: MessageView) => void;
  onError: (e: string) => void;
}) {
  const canReply = m.actionable && !contact.blocked && !m.deleted;
  const { dx, handlers } = useBubbleGestures(
    (el) => onActions(m, el),
    canReply ? () => onReply(m) : null,
  );
  const st = m.mine ? STATUS[m.status] : null;
  const groups = groupReactions(m);
  const mine = myReactions(m);
  const reply = m.reply;
  return (
    <div id={`msg-${m.id}`} className={`msg ${m.mine ? "out" : "in"} ${found ? "found" : ""} ${groups.length ? "has-reactions" : ""}`}>
      <span className="swipe-reply" aria-hidden="true" style={{ opacity: Math.min(1, dx / SWIPE_AT_PX) }}><Icon name="reply" /></span>
      <div className={`msg-body ${dx > 0 ? "dragging" : ""}`} style={dx > 0 ? { transform: `translateX(${dx}px)` } : undefined}>
        <div className={`bubble ${m.attachment?.kind === "image" ? "media" : ""}`} {...handlers}>
          {reply ? (
            <button
              className="reply"
              type="button"
              disabled={reply.id === null}
              onClick={() => reply.id !== null && onJump(reply.id)}
            >
              {/* The quote itself stays the button's name, so it is read out (P6-8). */}
              <span className="sr-only">{reply.id === null ? "Quoted message: " : "Quoted message, go to the original: "}</span>
              {reply.mine === null ? null : <b>{reply.mine ? "You" : contact.name}</b>}
              <span>{reply.text || "Original message not available"}</span>
            </button>
          ) : null}
          {m.deleted ? (
            <span className="deleted-text"><Icon name="ban" />This message was deleted</span>
          ) : m.attachment ? (
            <AttachmentBody m={m} onOpenImage={() => onOpenImage(m)} onError={onError} />
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
        <button className="icon-btn msg-more" type="button" aria-haspopup="dialog" aria-label="Message options" onClick={(e) => onActions(m, e.currentTarget)}><Icon name="more" /></button>
      </div>
      {groups.length ? (
        <div className="reactions" role="group" aria-label="Reactions">
          {groups.map((g) => (
            <button
              key={g.emoji}
              className={`reaction ${g.mine ? "mine" : ""}`}
              type="button"
              disabled={!m.actionable || contact.blocked || (!g.mine && mine.size >= MAX_REACTIONS)}
              aria-pressed={g.mine}
              aria-label={`${g.emoji} ${g.n}${g.mine ? ", including you. Remove yours" : `. React with ${g.emoji}`}`}
              onClick={() => void ipc.react(m.id, g.emoji, !g.mine).catch((err: unknown) => onError(err instanceof IpcError ? err.message : "Could not react"))}
            >
              <span className="reaction-emoji">{g.emoji}</span>
              {g.n > 1 ? <b>{g.n}</b> : null}
              {g.mine ? <Icon name="check" className="mine-mark" /> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function Chat({ contact, me, nav, version, typing, focus, onChanged }: { contact: ContactView; me: Me | null; nav: Nav; version: number; typing: boolean; focus?: number | undefined; onChanged: () => void }) {
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  /** How the last file was sent, when the user should know (see `Prepared.note`). */
  const [notice, setNotice] = useState<string | null>(null);
  /** The recording stopped itself at MAX_VOICE_MS and waits for Send or Discard. */
  const [atLimit, setAtLimit] = useState(false);
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

  // Follow new messages, unless the user was sent to an older one.
  const shown = useRef(0);
  useEffect(() => {
    if (found !== undefined) return;
    if (messages.length !== shown.current || typing) end.current?.scrollIntoView({ block: "end" });
    shown.current = messages.length;
    // `found` is left out on purpose: clearing the highlight must not jump to the end.
  }, [messages.length, typing]);

  // A search result or a tapped quote: scroll to it and highlight it for a moment.
  useEffect(() => {
    if (found === undefined) return;
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
  }, [found, loaded, messages.length]);

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

  /** Swipe right or "Reply": quote this message above the composer. */
  function startReply(m: MessageView) {
    setEditing(null);
    if (editing) setText("");
    setReplyTo(m);
    window.setTimeout(() => input.current?.focus(), 0);
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
    setNotice(null);
    setSending(true);
    try {
      const prepared = await prepareFile(file);
      const m = await ipc.sendAttachment(contact.id, prepared);
      setMessages((prev) => [...prev, m]);
      setNotice(prepared.note);
    } catch (err) {
      setError(err instanceof TooLarge ? "Files can be up to 25 MB." : err instanceof IpcError ? err.message : "Could not send this file");
    } finally {
      setSending(false);
    }
  }

  async function startVoice() {
    setError(null);
    setNotice(null);
    setAtLimit(false);
    try {
      setRecording(await startRecording(() => setAtLimit(true)));
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
    setAtLimit(false);
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
    <div
      className="m-screen chat-screen"
      data-own-colour={contact.accentHue != null ? "" : undefined}
      style={contact.accentHue != null ? bubbleVars(contact.accentHue) : undefined}
    >
      <ChatWallpaper contact={contact} />
      <header className="chat-hdr glass">
        <button className="icon-btn" type="button" aria-label="Back to chats" onClick={() => nav({ screen: "chats" })}><Icon name="back" /></button>
        <button className="who" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })} aria-label={`${contact.name}, view profile`}>
          <Avatar initials={contact.initials} hue={contact.hue} owner={contact.id} picture={contact.picture} />
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
        {contact.blocked ? null : (
          <>
            <button className="icon-btn" type="button" aria-label={`Voice call ${contact.name}`} onClick={() => void calls.start(contact.id, false)}><Icon name="phone" /></button>
            <button className="icon-btn" type="button" aria-label={`Video call ${contact.name}`} onClick={() => void calls.start(contact.id, true)}><Icon name="video" /></button>
          </>
        )}
      </header>
      <ConnectionBar me={me} />
      <KeyWarning contact={contact} nav={nav} onChanged={onChanged} />
      {!contact.verified && !contact.keyWarning ? (
        <Banner tone="info" icon="shield">
          <p>Not verified yet. <button className="link-btn" type="button" onClick={() => nav({ screen: "contact", contact: contact.id })}>Compare safety numbers</button> to be sure no one is in the middle.</p>
        </Banner>
      ) : null}
      <div className="msgs chat-scroll" role="log" aria-live="polite">
        {messages.map((m) =>
          m.kind === "timer" ? (
            <TimerNotice key={m.id} m={m} name={contact.name} />
          ) : m.kind === "call" ? (
            <CallNotice key={m.id} m={m} contact={contact} />
          ) : (
            <MessageRow
              key={m.id}
              m={m}
              contact={contact}
              found={found === m.id}
              onActions={openActions}
              onReply={startReply}
              onJump={setFound}
              onOpenImage={setViewing}
              onError={setError}
            />
          ),
        )}
        {typing ? <div className="typing-bubble" role="status" aria-label={`${contact.name} is typing`}><Dots /></div> : null}
        <div ref={end} />
      </div>
      {tooOld ? <Banner tone="info" icon="info"><p>That message is older than the ones shown here.</p></Banner> : null}
      {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
      {notice && !error ? <Banner tone="info" icon="info"><p>{notice}</p></Banner> : null}
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
                <span>{editing ? editing.text : replyTo ? messageSummary(replyTo) : ""}</span>
              </span>
              <button className="icon-btn" type="button" aria-label={editing ? "Cancel editing" : "Cancel reply"} onClick={cancelContext}><Icon name="x" /></button>
            </div>
          ) : null}
          {recording ? (
            <div className="composer recording-bar">
              {/* Announced once per state; the running timer stays out of the live region. */}
              <span className="sr-only" role="status">{atLimit ? "Recording stopped at the 5 minute limit" : "Recording"}</span>
              <button className="icon-btn" type="button" aria-label="Discard voice message" onClick={() => void finishVoice(false)}><Icon name="trash" /></button>
              {atLimit ? null : <span className="rec-dot" aria-hidden="true" />}
              <span className="rec-time">{atLimit ? "Stopped" : "Recording"} · {formatDuration(recMs)} / {formatDuration(MAX_VOICE_MS)}</span>
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
            startReply(actionsFor);
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
