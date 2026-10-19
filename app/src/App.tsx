import { useCallback, useEffect, useState } from "react";
import { ipc, onChange, type AppState, type ContactView, type Me } from "./ipc";
import { Chat, ChatList, type Route } from "./screens/Chats";
import { AddContact, ContactProfile } from "./screens/Contacts";
import { Setup, Unlock } from "./screens/Onboarding";
import { Settings } from "./screens/Settings";
import { Banner } from "./ui";

export function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [route, setRoute] = useState<Route>({ screen: "chats" });
  const [contacts, setContacts] = useState<ContactView[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [version, setVersion] = useState(0);
  const [fatal, setFatal] = useState<string | null>(null);

  const refreshState = useCallback(() => {
    void ipc.state().then(setState, () => setFatal("Veil could not start its secure storage."));
  }, []);

  const refresh = useCallback(() => {
    void ipc.contacts().then(setContacts, () => undefined);
    void ipc.me().then(setMe, () => undefined);
  }, []);

  useEffect(refreshState, [refreshState]);

  useEffect(() => {
    if (state !== "unlocked") return;
    refresh();
    let off: (() => void) | undefined;
    void onChange((kind) => {
      if (kind === "locked") {
        setRoute({ screen: "chats" });
        refreshState();
        return;
      }
      refresh();
      if (kind === "messages") setVersion((v) => v + 1);
    }).then((u) => {
      off = u;
    });
    return () => off?.();
  }, [state, refresh, refreshState]);

  if (fatal) return <div className="app-error"><Banner tone="danger" icon="alert-triangle"><p>{fatal}</p></Banner></div>;
  if (state === null) return null;
  if (state === "new") return <Setup onDone={refreshState} />;
  if (state === "locked") return <Unlock onDone={refreshState} />;

  const byId = (id: number) => contacts.find((c) => c.id === id);
  switch (route.screen) {
    case "chat": {
      const c = byId(route.contact);
      return c ? <Chat contact={c} me={me} nav={setRoute} version={version} /> : <ChatList contacts={contacts} me={me} nav={setRoute} />;
    }
    case "contact": {
      const c = byId(route.contact);
      return c ? <ContactProfile contact={c} nav={setRoute} onChanged={refresh} /> : <ChatList contacts={contacts} me={me} nav={setRoute} />;
    }
    case "add":
      return <AddContact nav={(to) => { refresh(); setRoute(to); }} />;
    case "settings":
      return <Settings me={me} nav={setRoute} onLocked={refreshState} />;
    case "chats":
      return <ChatList contacts={contacts} me={me} nav={setRoute} />;
  }
}
