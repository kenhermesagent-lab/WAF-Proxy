import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import Icon, { type IconName } from "./Icon";
import type { NavItem } from "../nav";

type SearchResult = { kind: string; title: string; subtitle: string; href: string };

type Row = {
  key: string;
  title: string;
  subtitle: string;
  kind: string;
  icon: IconName;
  run: () => void;
};

export default function CommandPalette({
  open,
  onClose,
  nav,
  onNavigate,
  onSignOut,
  onOpenSource,
}: {
  open: boolean;
  onClose: () => void;
  nav: NavItem[];
  onNavigate: (id: string, query?: string) => void;
  onSignOut: () => void;
  onOpenSource: (ip: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const requestSeq = useRef(0);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setResults([]);
    setActive(0);
    const t = window.setTimeout(() => inputRef.current?.focus(), 20);
    return () => window.clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const q = query.trim();
    if (q.length < 2) {
      setResults([]);
      setLoading(false);
      return;
    }
    const seq = ++requestSeq.current;
    setLoading(true);
    const t = window.setTimeout(() => {
      api
        .get<{ results: SearchResult[] }>(`/api/search?q=${encodeURIComponent(q)}`)
        .then((r) => {
          if (seq === requestSeq.current) setResults(r.results ?? []);
        })
        .catch(() => {
          if (seq === requestSeq.current) setResults([]);
        })
        .finally(() => {
          if (seq === requestSeq.current) setLoading(false);
        });
    }, 180);
    return () => window.clearTimeout(t);
  }, [query, open]);

  const rows = useMemo<Row[]>(() => {
    const q = query.trim().toLowerCase();
    const pageRows: Row[] = nav
      .filter((n) => !q || n.label.toLowerCase().includes(q) || (n.hint ?? "").toLowerCase().includes(q))
      .map((n) => ({
        key: `page-${n.id}`,
        title: n.label,
        subtitle: n.hint ?? "",
        kind: "Page",
        icon: n.icon,
        run: () => onNavigate(n.id),
      }));
    const searchRows: Row[] = results.map((r) => ({
      key: `search-${r.kind}-${r.href}-${r.title}`,
      title: r.title,
      subtitle: r.subtitle,
      kind: r.kind === "ip" ? "Source IP" : r.kind === "ban" ? "Ban" : r.kind === "event" ? "Event" : "Proxy",
      icon: r.kind === "ip" ? "globe" : r.kind === "ban" ? "shield" : r.kind === "event" ? "logs" : "server",
      run: () => {
        if (r.kind === "ip") {
          onOpenSource(r.title);
          return;
        }
        const [page, qs] = r.href.replace(/^#\//, "").split("?");
        onNavigate(page, qs);
      },
    }));
    const actions: Row[] = q
      ? []
      : [
          { key: "action-account", title: "Account settings", subtitle: "Password and authenticator", kind: "Action", icon: "user", run: () => onNavigate("account") },
          { key: "action-signout", title: "Sign out", subtitle: "End this browser session", kind: "Action", icon: "power", run: onSignOut },
        ];
    return [...searchRows, ...pageRows, ...actions];
  }, [nav, onNavigate, onOpenSource, onSignOut, query, results]);

  useEffect(() => {
    if (active >= rows.length) setActive(0);
  }, [active, rows.length]);

  if (!open) return null;

  const choose = (row?: Row) => {
    if (!row) return;
    row.run();
    onClose();
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (rows.length ? (i + 1) % rows.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (rows.length ? (i - 1 + rows.length) % rows.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(rows[active]);
    }
  };

  const grouped: { label: string; rows: (Row & { index: number })[] }[] = [];
  rows.forEach((row, index) => {
    const label = row.kind === "Page" ? "Go to" : row.kind === "Action" ? "Actions" : "Search results";
    const group = grouped.find((g) => g.label === label);
    if (group) group.rows.push({ ...row, index });
    else grouped.push({ label, rows: [{ ...row, index }] });
  });

  return (
    <div className="palette-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search console" onKeyDown={onKey}>
        <div className="palette-search">
          <Icon name="search" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            placeholder="Search proxies, IPs, bans or jump to a page…"
            aria-label="Search proxies, IPs, bans or pages"
            autoComplete="off"
            spellCheck={false}
          />
          {loading ? <span className="faint small-text">Searching…</span> : <kbd>ESC</kbd>}
        </div>
        <div className="palette-body" role="listbox" aria-label="Results">
          {rows.length === 0 ? (
            <div className="palette-empty">No matches for “{query}”.</div>
          ) : (
            grouped.map((group) => (
              <div key={group.label}>
                <div className="palette-group">{group.label}</div>
                {group.rows.map((row) => (
                  <button
                    key={row.key}
                    className="palette-item"
                    role="option"
                    aria-selected={active === row.index}
                    onMouseEnter={() => setActive(row.index)}
                    onClick={() => choose(row)}
                  >
                    <span className="ico"><Icon name={row.icon} /></span>
                    <span>
                      <span className="palette-title">{row.title}</span>
                      {row.subtitle ? <span className="palette-sub">{row.subtitle}</span> : null}
                    </span>
                    <span className="palette-kind">{row.kind}</span>
                  </button>
                ))}
              </div>
            ))
          )}
        </div>
        <div className="palette-foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
          {query.trim().length >= 2 && <span style={{ marginLeft: "auto" }}>Searches this console only</span>}
        </div>
      </div>
    </div>
  );
}
