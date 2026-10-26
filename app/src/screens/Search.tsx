import { useEffect, useState } from "react";
import { ipc, IpcError, type SearchHit } from "../ipc";
import { Banner, Icon, TopBar, timeLabel } from "../ui";
import type { Nav } from "./Chats";

/** Searches message text on this device (in the encrypted database); nothing is sent anywhere. */
export function Search({ nav }: { nav: Nav }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<SearchHit[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setHits(null);
      return;
    }
    let live = true;
    const t = window.setTimeout(() => {
      ipc.search(term).then(
        (h) => {
          if (live) setHits(h);
        },
        (err: unknown) => {
          if (live) setError(err instanceof IpcError ? err.message : "Search failed");
        },
      );
    }, 250);
    return () => {
      live = false;
      window.clearTimeout(t);
    };
  }, [q]);

  return (
    <div className="m-screen push">
      <TopBar title="Search" onBack={() => nav({ screen: "chats" })} />
      <div className="m-body">
        <div className="field">
          <label htmlFor="search-q" className="sr-only">Search messages</label>
          <div className="input"><Icon name="search" className="icon-sm" /><input id="search-q" type="search" autoFocus spellCheck={false} placeholder="Search messages" value={q} maxLength={100} onChange={(e) => setQ(e.target.value)} /></div>
          <p className="hint">Searches only this device. Nothing leaves it.</p>
        </div>
        {error ? <Banner tone="danger" icon="alert-circle"><p>{error}</p></Banner> : null}
        {hits === null ? null : hits.length === 0 ? (
          <p className="muted center" role="status">No messages found</p>
        ) : (
          <ul className="conv-list" aria-label={`${hits.length} results`}>
            {hits.map((h) => (
              <li key={h.message}>
                <button className="conv" type="button" onClick={() => nav({ screen: "chat", contact: h.contact, focus: h.message })}>
                  <div className="conv-main">
                    <div className="conv-top">
                      <span className="conv-name">{h.mine ? `You to ${h.contactName}` : h.contactName}</span>
                      <time>{timeLabel(h.atMs)}</time>
                    </div>
                    <div className="conv-bottom"><span className="conv-preview search-snippet">{h.snippet}</span></div>
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
