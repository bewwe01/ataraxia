import { useCallback, useEffect, useRef, useState } from "react";
import { forgetWallpapers, refreshWallpaper } from "./wallpaper";
import { forgetPictures } from "./pictures";
import { ipc, onChange, type AppState, type ContactView, type Me } from "./ipc";
import { Chat, ChatList, type Route } from "./screens/Chats";
import { AddContact, ContactProfile } from "./screens/Contacts";
import { Setup, Unlock } from "./screens/Onboarding";
import { Search } from "./screens/Search";
import { Settings } from "./screens/Settings";
import { Banner } from "./ui";
import { calls, useCall } from "./calls";
import { CallScreen } from "./screens/Call";

export function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [route, setRoute] = useState<Route>({ screen: "chats" });
  const [contacts, setContacts] = useState<ContactView[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [version, setVersion] = useState(0);
  const [fatal, setFatal] = useState<string | null>(null);
  // Contacts shown as typing; each entry clears itself if no "stopped" arrives.
  const [typing, setTyping] = useState<ReadonlySet<number>>(new Set());
  const typingTimers = useRef(new Map<number, number>());
  const call = useCall();
  const underCall = useRef<HTMLDivElement>(null);
  // Full-screen calls take the app; a minimized one leaves it usable.
  const inCall = call !== null && !(call.minimized && call.phase !== "incoming");

  const setTypingFor = useCallback((contact: number, on: boolean) => {
    const old = typingTimers.current.get(contact);
    if (old !== undefined) window.clearTimeout(old);
    typingTimers.current.delete(contact);
    if (on) typingTimers.current.set(contact, window.setTimeout(() => setTypingFor(contact, false), 8000));
    setTyping((prev) => {
      if (prev.has(contact) === on) return prev;
      const next = new Set(prev);
      if (on) next.add(contact);
      else next.delete(contact);
      return next;
    });
  }, []);

  const refreshState = useCallback(() => {
    void ipc.state().then(setState, () => setFatal("Veil could not start its secure storage."));
  }, []);

  const refresh = useCallback(() => {
    void ipc.contacts().then(setContacts, () => undefined);
    void ipc.me().then(setMe, () => undefined);
  }, []);

  useEffect(refreshState, [refreshState]);

  // The app under a full-screen call is inert (review C6-4).
  useEffect(() => {
    const el = underCall.current;
    if (!el) return;
    if (inCall) el.setAttribute("inert", "");
    else el.removeAttribute("inert");
  }, [inCall, state]);

  // Notifications are on by default; Android asks for its permission the first time
  // (review M4-3). Kotlin remembers that it asked.
  useEffect(() => {
    if (state === "unlocked") void ipc.notifyWelcome().catch(() => undefined);
  }, [state]);

  // Auto-lock counts only real user input (review P4-2): report it, at most every 20 s.
  useEffect(() => {
    if (state !== "unlocked") return;
    let last = 0;
    const onInput = () => {
      const now = Date.now();
      if (now - last < 20_000) return;
      last = now;
      void ipc.touch().catch(() => undefined);
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
    for (const e of events) window.addEventListener(e, onInput, { passive: true });
    return () => {
      for (const e of events) window.removeEventListener(e, onInput);
    };
  }, [state]);

  useEffect(() => {
    if (state !== "unlocked") return;
    refresh();
    void refreshWallpaper();
    let off: (() => void) | undefined;
    void onChange((kind, contact) => {
      if (kind === "locked") {
        // The session that carried the call's signaling is gone.
        calls.drop();
        forgetWallpapers();
        // Drop everything shown while unlocked, previews included.
        setContacts([]);
        setMe(null);
        setRoute({ screen: "chats" });
        for (const t of typingTimers.current.values()) window.clearTimeout(t);
        typingTimers.current.clear();
        setTyping(new Set());
        refreshState();
        return;
      }
      // The shell already turned it into a notification; messages refresh on "messages".
      if (kind === "incoming" || kind === "ringing") return;
      if (kind === "call") {
        void ipc.callSignals().then((s) => calls.handle(s), () => undefined);
        return;
      }
      if (kind === "typing" || kind === "typingstopped") {
        if (contact !== null) setTypingFor(contact, kind === "typing");
        return;
      }
      refresh();
      if (kind === "messages") {
        // A new message ends "typing".
        if (contact !== null) setTypingFor(contact, false);
        setVersion((v) => v + 1);
      }
    }).then((u) => {
      off = u;
    });
    return () => {
      off?.();
      // Leaving "unlocked" by any path drops the wallpaper photos, whether or not the
      // "locked" event was still heard.
      forgetWallpapers();
      forgetPictures();
    };
  }, [state, refresh, refreshState, setTypingFor]);

  if (fatal) return <div className="app-error"><Banner tone="danger" icon="alert-triangle"><p>{fatal}</p></Banner></div>;
  if (state === null) return null;
  if (state === "new") return <Setup onDone={refreshState} />;
  if (state === "locked") return <Unlock onDone={refreshState} />;

  const byId = (id: number) => contacts.find((c) => c.id === id);
  // The app stays mounted under a call (drafts and scroll survive it), but inert, so focus and
  // screen readers stay in the call (review C6-4).
  return (
    <>
      <div className="under-call" ref={underCall}>{mainScreen()}</div>
      {call ? <CallScreen call={call} contact={byId(call.contact)} /> : null}
    </>
  );

  function mainScreen() {
  switch (route.screen) {
    case "chat": {
      const c = byId(route.contact);
      return c ? <Chat key={`${c.id}-${route.focus ?? ""}`} contact={c} me={me} nav={setRoute} version={version} typing={typing.has(c.id)} focus={route.focus} onChanged={refresh} /> : <ChatList contacts={contacts} me={me} nav={setRoute} typing={typing} />;
    }
    case "contact": {
      const c = byId(route.contact);
      return c ? <ContactProfile contact={c} nav={setRoute} onChanged={refresh} /> : <ChatList contacts={contacts} me={me} nav={setRoute} typing={typing} />;
    }
    case "add":
      return <AddContact nav={(to) => { refresh(); setRoute(to); }} />;
    case "search":
      return <Search nav={setRoute} />;
    case "settings":
      return <Settings me={me} nav={setRoute} onLocked={() => { setContacts([]); setMe(null); refreshState(); }} />;
    case "chats":
      return <ChatList contacts={contacts} me={me} nav={setRoute} typing={typing} />;
  }
  }
}
