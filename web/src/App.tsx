import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api, setCSRF, setSite } from "./api";
import { COFFEE_URL, DOCS_URL } from "./links";
import { errText } from "./ui";
import PageBoundary from "./components/PageBoundary";
import CommandPalette from "./components/CommandPalette";
import QuickActions, { COMMANDS, type CommandId } from "./components/QuickActions";
import SourceDrawer from "./components/SourceDrawer";
import AdminsOnline from "./components/AdminsOnline";
import Icon from "./components/Icon";
import { Me, SetupStatus, can } from "./types";
import { NAV, NAV_GROUPS, NAV_UTILITY, href, navAllowed, routeFromHash, type NavItem } from "./nav";
import Dashboard from "./pages/Dashboard";
import Statistics from "./pages/Statistics";
import Proxies from "./pages/Proxies";
import AgentPage from "./pages/Agent";
import TailscalePage from "./pages/Tailscale";
import CloudflarePage from "./pages/Cloudflare";
import Policies from "./pages/Policies";
import Intel from "./pages/Intel";
import Anomalies from "./pages/Anomalies";
import Activity from "./pages/Activity";
import Access from "./pages/Access";
import Notifications from "./pages/Notifications";
import Logs from "./pages/Logs";
import SettingsPage from "./pages/Settings";
import Account from "./pages/Account";
import SitesPage from "./pages/Sites";
import HelpPage from "./help/HelpPage";
import { helpPageFromHash } from "./help";
import HAPage from "./pages/HA";

type Phase = "loading" | "setup" | "enrol" | "login" | "app";

type Enrolment = { username: string; secret: string; url: string; codes: string[] };
type ToastTone = "ok" | "error" | "info" | "warn";
type Toast = { id: number; tone: ToastTone; title: string; message: string };
export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [route, setRoute] = useState(() => routeFromHash(window.location.hash));
  const { page, tab } = route;
  const [pageQuery, setPageQuery] = useState(() => window.location.hash.split("?")[1] ?? "");
  // Bumped on every navigation: a page reached with the query it already has
  // gets no hashchange, so the page itself needs a reason to reapply it.
  const [navSeq, setNavSeq] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [enrol, setEnrol] = useState<Enrolment | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [home, setHome] = useState({ lat: 51.5, lon: -0.12 });
  const [navOpen, setNavOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("waf.nav.collapsed") === "1");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sourceIp, setSourceIp] = useState<string | null>(null);
  const [command, setCommand] = useState<CommandId | null>(null);
  const [userMenu, setUserMenu] = useState(false);
  // The site every view below answers for. Kept in localStorage so a reload
  // returns to the site the operator was looking at.
  const [activeSite, setActiveSite] = useState(() => localStorage.getItem("waf.site") ?? "");
  const [adminsOnline, setAdminsOnline] = useState(false);
  const toastSeq = useRef(0);
  const userWrap = useRef<HTMLDivElement>(null);

  const pushToast = (tone: ToastTone, message: string, title?: string) => {
    const id = ++toastSeq.current;
    const fallback = tone === "error" ? "Action failed" : tone === "warn" ? "Attention" : tone === "info" ? "Notice" : "Done";
    setToasts((list) => [...list.slice(-3), { id, tone, title: title ?? fallback, message }]);
    window.setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), tone === "error" ? 9000 : 5000);
  };
  const onError = (message: string) => pushToast("error", message);
  const onOK = (message: string) => pushToast("ok", message);

  const navigate = (id: string, query?: string, nextTab?: string) => {
    const target = routeFromHash(href(id, nextTab));
    const nextHash = `${href(target.page, target.tab)}${query ? `?${query}` : ""}`;
    setRoute(target);
    setPageQuery(query ?? "");
    setNavSeq((n) => n + 1);
    // A drawer or a command belongs to the page that opened it, and its
    // backdrop would otherwise block the page the operator just asked for.
    setSourceIp(null);
    setCommand(null);
    if (window.location.hash !== nextHash) window.location.hash = nextHash;
  };

  // rememberSite restores the stored choice when the role can still read it,
  // and otherwise falls back to the site this console was reached on.
  const rememberSite = (m: Me) => {
    const saved = localStorage.getItem("waf.site") ?? "";
    const slug = (m.sites ?? []).some((s) => s.slug === saved) ? saved : m.site ?? "";
    setActiveSite(slug);
    setSite(slug && slug !== m.site ? slug : "");
    if (slug) localStorage.setItem("waf.site", slug);
    else localStorage.removeItem("waf.site");
  };

  const switchSite = (slug: string) => {
    setActiveSite(slug);
    setSite(slug === me?.site ? "" : slug);
    localStorage.setItem("waf.site", slug);
    loadHome();
  };

  const loadHome = () =>
    api
      .get<Record<string, string>>("/api/settings")
      .then((s) => {
        const lat = Number(s.home_lat);
        const lon = Number(s.home_lon);
        if (Number.isFinite(lat) && Number.isFinite(lon)) setHome({ lat, lon });
      })
      .catch(() => undefined);

  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth > 760) setNavOpen(false);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    localStorage.setItem("waf.nav.collapsed", collapsed ? "1" : "0");
  }, [collapsed]);

  useEffect(() => {
    const applyHash = () => {
      const hash = window.location.hash;
      const next = routeFromHash(hash);
      const query = hash.split("?")[1];
      const canonical = `${href(next.page, next.tab)}${query ? `?${query}` : ""}`;
      // A pre-restructure hash is redirected by rewriting the URL, so a stale
      // bookmark lands on the new route without a detour in the history. The
      // signed-out invite and reset links are not app routes and keep their
      // page so the login form can tell them apart.
      const signedOutLink = /^#\/(invite|reset-password)\b/.test(hash);
      if (hash && hash !== canonical && !signedOutLink && !helpPageFromHash(hash)) {
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${canonical}`);
      }
      setRoute(next);
      setPageQuery(query ?? "");
      setNavSeq((n) => n + 1);
      setSourceIp(null);
      setCommand(null);
    };
    applyHash();
    window.addEventListener("hashchange", applyHash);
    return () => window.removeEventListener("hashchange", applyHash);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (phase === "app") setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [phase]);

  useEffect(() => {
    if (!userMenu) return;
    const close = (e: MouseEvent) => {
      if (!userWrap.current?.contains(e.target as Node)) setUserMenu(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [userMenu]);

  useEffect(() => {
    if (!me) return;
    const item = NAV.find((n) => n.id === page);
    // A tab the role cannot read (or one that no longer exists) opens the
    // first tab it can, so the URL never points at an invisible view.
    const allowedTabs = (item?.tabs ?? []).filter((t) => !t.permission || can(me.permissions, t.permission));
    if (allowedTabs.length > 0 && !allowedTabs.some((t) => t.id === tab)) {
      window.location.hash = href(page, allowedTabs[0].id);
    }
  }, [me, page, tab]);

  useEffect(() => {
    (async () => {
      try {
        const st = await api.get<SetupStatus>("/api/setup/status");
        if (st.needs_setup) {
          setSetupStatus(st);
          setPhase("setup");
          return;
        }
        try {
          const m = await api.get<Me>("/api/me");
          setCSRF(m.csrf);
          setMe(m);
          rememberSite(m);
          setPhase("app");
          loadHome();
        } catch {
          setPhase("login");
        }
      } catch {
        setPhase("login");
      }
    })();
  }, []);

  const logout = async () => {
    try {
      await api.post("/api/logout");
    } finally {
      setCSRF("");
      setMe(null);
      setPhase("login");
    }
  };

  if (phase === "loading") {
    return (
      <div className="auth-wrap">
        <div className="row" style={{ gap: 10, color: "var(--muted)", fontSize: 13 }}>
          <span className="skeleton" style={{ width: 18, height: 18, borderRadius: 5 }} />
          Loading console…
        </div>
      </div>
    );
  }

  if (phase === "setup") {
    return <Setup defaults={setupStatus} onDone={(e) => { setEnrol(e); setPhase("enrol"); }} />;
  }

  if (phase === "enrol" && enrol) {
    return (
      <AuthFrame title="Save your second factor" sub="Scan or paste this secret into an authenticator app. It is shown once.">
        <div className="secret-box">{enrol.secret}</div>
        <div className="secret-box" style={{ fontSize: 11.5 }}>{enrol.url}</div>
        <label style={{ marginTop: 16 }}>Recovery codes</label>
        <div className="code-list">
          {(enrol.codes || []).map((c) => <div key={c}>{c}</div>)}
        </div>
        <button className="primary mt" style={{ width: "100%" }} onClick={() => setPhase("login")}>
          I have saved them — sign in
        </button>
      </AuthFrame>
    );
  }

  if (phase === "login") {
    return (
      <Login
        onDone={(m) => {
          setCSRF(m.csrf);
          setMe(m);
          rememberSite(m);
          setPhase("app");
          loadHome();
        }}
      />
    );
  }

  // /api/me is the source of the nav, so a saved HA switch has to refresh it
  // for the item to appear without a reload.
  const reloadMe = () =>
    api.get<Me>("/api/me").then((m) => {
      setCSRF(m.csrf);
      setMe(m);
    }).catch(() => undefined);
  const allowed = (n: NavItem) => navAllowed(n, me);
  const visibleNav = NAV.filter(allowed);
  // The crumb names the page the URL asked for, even when the role cannot read
  // it; the card offers the first page the role can open instead.
  const current = NAV.find((n) => n.id === page) ?? visibleNav[0] ?? NAV[0];
  const fallback = visibleNav[0] ?? NAV[0];
  const pageAllowed = allowed(current);
  // #/<page>/help is its own route: the printable copy of the page's help,
  // with the same text as the drawer.
  const helpPage = helpPageFromHash(window.location.hash);
  const tabsFor = (id: string) =>
    (NAV.find((n) => n.id === id)?.tabs ?? []).filter((t) => !t.permission || can(me?.permissions, t.permission));
  const tabProps = (id: string) => ({ tab, tabs: tabsFor(id), onTab: (next: string) => navigate(id, undefined, next) });

  const navButton = (n: NavItem) => (
    <button
      key={n.id}
      className={`nav-item ${page === n.id ? "active" : ""}`}
      onClick={() => {
        navigate(n.id);
        setNavOpen(false);
      }}
      title={collapsed ? n.label : undefined}
      aria-current={page === n.id ? "page" : undefined}
    >
      <span className="ico"><Icon name={n.icon} /></span>
      <span className="label">{n.label}</span>
    </button>
  );

  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      {navOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} />}
      <aside className={`sidebar ${navOpen ? "open" : ""} ${collapsed ? "collapsed" : ""}`}>
        <div className="brand">
          <span className="brand-mark"><BrandMark /></span>
          <span className="brand-name">WAF-Proxy</span>
        </div>
        {NAV_GROUPS.map((g) => {
          const items = g.items.filter((n) => navAllowed(n, me));
          if (items.length === 0) return null;
          return (
            <div className="nav-group" key={g.title}>
              <div className="nav-group-title">{g.title}</div>
              {items.map(navButton)}
            </div>
          );
        })}
        <div className="nav-spacer" />
        {NAV_UTILITY.filter((n) => navAllowed(n, me)).map(navButton)}
        <div className="nav-foot">
          <span className="nav-foot-who">{me?.username} · v{me?.version}</span>
          <a className="nav-coffee" href={COFFEE_URL} target="_blank" rel="noreferrer" title="Buy me a coffee" aria-label="Buy me a coffee">
            <Icon name="coffee" size={13} />
          </a>
        </div>
        <button className="nav-collapse" onClick={() => setCollapsed((v) => !v)} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>
          <Icon name={collapsed ? "expand" : "collapse"} size={15} />
          <span className="label">{collapsed ? "Expand" : "Collapse"}</span>
        </button>
      </aside>

      <main className="main" id="main-content">
        <header className="topbar">
          <button
            className="nav-toggle icon-btn"
            aria-label="Open navigation"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            <Icon name="menu" />
          </button>
          <div className="crumb">
            <span className="crumb-root">Console</span>
            <span className="crumb-sep">/</span>
            <h1>{current.label}</h1>
          </div>
          <div className="spacer" />
          <button className="search-trigger" onClick={() => setPaletteOpen(true)} aria-label="Search console">
            <Icon name="search" size={14} />
            <span>Search</span>
            <kbd>⌘K</kbd>
          </button>
          {me?.can_switch && (me.sites?.length ?? 0) > 1 ? (
            <label className="env-chip site-switch" title="Every page answers for this site">
              <span className="env-dot" />
              <span className="site-switch-label">Site</span>
              <select value={activeSite} onChange={(e) => switchSite(e.target.value)} aria-label="Active site">
                {(me.sites ?? []).map((s) => (
                  <option key={s.slug} value={s.slug}>{s.name}</option>
                ))}
              </select>
            </label>
          ) : me?.site_name ? (
            <span
              className="env-chip"
              title={me.can_switch ? "The only site configured" : "You administer this site only; switching needs the Sites permission"}
            >
              <span className="env-dot" />
              <b className="env-domain">{me.site_name}</b>
            </span>
          ) : me?.base_domain ? (
            <span className="env-chip" title="Self-hosted deployment">
              <span className="env-dot" />
              <span>Self-hosted</span>
              <b className="env-domain">{me.base_domain}</b>
            </span>
          ) : null}
          <a className="icon-btn" href={DOCS_URL} target="_blank" rel="noreferrer" aria-label="Documentation">
            <Icon name="help" />
          </a>
          <div className="user-wrap" ref={userWrap}>
            <button className="user-btn" onClick={() => setUserMenu((v) => !v)} aria-expanded={userMenu} aria-haspopup="menu">
              <span className="avatar">{(me?.username ?? "?").slice(0, 2).toUpperCase()}</span>
              <span className="user-name">{me?.username}</span>
              <Icon name="chevronDown" size={13} />
            </button>
            {userMenu && (
              <div className="menu" role="menu">
                <div className="menu-head">
                  <strong>{me?.username}</strong>
                  <span>{me?.role}{me?.totp_enabled ? " · 2FA enabled" : ""}</span>
                </div>
                {/* The topbar chip is hidden on a phone; offer the same choice here. */}
                {me?.can_switch && (me.sites?.length ?? 0) > 1 && (
                  <>
                    <div className="menu-label">Site</div>
                    {(me.sites ?? []).map((s) => (
                      <button
                        key={s.slug}
                        className={s.slug === activeSite ? "menu-item on" : "menu-item"}
                        role="menuitemradio"
                        aria-checked={s.slug === activeSite}
                        onClick={() => { switchSite(s.slug); setUserMenu(false); }}
                      >
                        <span className="ico">{s.slug === activeSite ? <Icon name="check" size={15} /> : null}</span>
                        {s.name}
                      </button>
                    ))}
                    <div className="menu-sep" />
                  </>
                )}
                {can(me?.permissions, "settings.read") && (
                  <button className="menu-item" role="menuitem" onClick={() => { navigate("settings"); setUserMenu(false); }}>
                    <span className="ico"><Icon name="settings" size={15} /></span> Settings
                  </button>
                )}
                <button className="menu-item" role="menuitem" onClick={() => { navigate("account"); setUserMenu(false); }}>
                  <span className="ico"><Icon name="user" size={15} /></span> Account
                </button>
                {can(me?.permissions, "settings.read") && (
                  <button className="menu-item" role="menuitem" onClick={() => { setAdminsOnline(true); setUserMenu(false); }}>
                    <span className="ico"><Icon name="users" size={15} /></span> Signed-in administrators
                  </button>
                )}
                <a className="menu-item" role="menuitem" href={DOCS_URL} target="_blank" rel="noreferrer">
                  <span className="ico"><Icon name="help" size={15} /></span> Documentation
                </a>
                <a className="menu-item" role="menuitem" href={COFFEE_URL} target="_blank" rel="noreferrer">
                  <span className="ico"><Icon name="coffee" size={15} /></span> Buy me a coffee
                </a>
                <div className="menu-sep" />
                <button className="menu-item danger" role="menuitem" onClick={logout}>
                  <span className="ico"><Icon name="power" size={15} /></span> Sign out
                </button>
              </div>
            )}
          </div>
        </header>

        <div className="content">
          {!pageAllowed && page === "ha" && can(me?.permissions, "ha.read") ? (
            <HAPage me={me} version={me?.version ?? ""} onError={onError} onOK={onOK} />
          ) : !pageAllowed ? (
            <div className="card">
              <p style={{ marginTop: 0 }}>Your role does not include this page.</p>
              <button className="primary" onClick={() => navigate(fallback.id)}>Open {fallback.label}</button>
            </div>
          ) : helpPage ? (
            <HelpPage page={helpPage} />
          ) : (
            <PageBoundary page={page} key={`${page}-${activeSite}`}>
              {page === "dashboard" && <Dashboard onError={onError} home={home} onOpenSource={setSourceIp} />}
              {page === "statistics" && <Statistics onError={onError} {...tabProps("statistics")} />}
              {page === "proxies" && <Proxies onError={onError} onOK={onOK} base={me?.base_domain ?? ""} {...tabProps("proxies")} />}
              {page === "agent" && <AgentPage onError={onError} onOK={onOK} />}
              {page === "tailscale" && <TailscalePage onError={onError} onOK={onOK} />}
              {page === "cloudflare" && <CloudflarePage onError={onError} onOK={onOK} {...tabProps("cloudflare")} />}
              {page === "policies" && <Policies onError={onError} onOK={onOK} {...tabProps("policies")} />}
              {page === "intel" && (
                <Intel
                  onError={onError}
                  onOK={onOK}
                  onOpenSource={setSourceIp}
                  onOpenPolicies={() => navigate("policies", undefined, "profiles")}
                  {...tabProps("intel")}
                />
              )}
              {page === "anomalies" && <Anomalies onError={onError} onOK={onOK} />}
              {page === "activity" && <Activity onError={onError} onOK={onOK} permissions={me?.permissions ?? []} />}
              {page === "access" && <Access onError={onError} onOK={onOK} {...tabProps("access")} />}
              {page === "notifications" && <Notifications onError={onError} onOK={onOK} />}
              {page === "logs" && (
                <Logs
                  onError={onError}
                  onOK={onOK}
                  query={pageQuery}
                  queryVersion={navSeq}
                  onOpenSource={setSourceIp}
                  canWrite={can(me?.permissions, "policies.write")}
                  canShareViews={can(me?.permissions, "traffic.write")}
                />
              )}
              {page === "settings" && <SettingsPage onError={onError} onOK={onOK} version={me?.version ?? ""} me={me} onMeChanged={reloadMe} />}
              {page === "ha" && <HAPage me={me} version={me?.version ?? ""} onError={onError} onOK={onOK} />}
              {page === "sites" && <SitesPage onError={onError} onOK={onOK} me={me} />}
              {page === "account" && (
                <Account
                  me={me}
                  onError={onError}
                  onOK={onOK}
                  onSignedOut={() => { setCSRF(""); setMe(null); setPhase("login"); }}
                />
              )}
            </PageBoundary>
          )}
        </div>
      </main>

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        nav={visibleNav}
        onNavigate={navigate}
        onSignOut={logout}
        onOpenSource={setSourceIp}
        permissions={me?.permissions ?? []}
        onCommand={setCommand}
      />

      {adminsOnline && <AdminsOnline onClose={() => setAdminsOnline(false)} onError={onError} />}

      {command && (
        <QuickActions
          command={command}
          canWrite={can(me?.permissions, COMMANDS.find((c) => c.id === command)?.permission ?? "")}
          onClose={() => setCommand(null)}
          onError={onError}
          onOK={onOK}
        />
      )}

      {sourceIp && (
        <SourceDrawer
          ip={sourceIp}
          canWrite={can(me?.permissions, "policies.write")}
          onClose={() => setSourceIp(null)}
          onError={onError}
          onOK={onOK}
        />
      )}

      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div className={`toast ${t.tone}`} key={t.id}>
            <span className="toast-icon">
              <Icon name={t.tone === "error" ? "alert" : t.tone === "ok" ? "check" : t.tone === "warn" ? "alert" : "info"} />
            </span>
            <span className="toast-msg">
              <strong>{t.title}</strong>
              {t.message}
            </span>
            <button
              className="icon-btn toast-close"
              aria-label="Dismiss notification"
              onClick={() => setToasts((list) => list.filter((x) => x.id !== t.id))}
            >
              <Icon name="x" size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function BrandMark() {
  const uid = useId().replace(/:/g, "");
  const rim = `m5-rim-${uid}`;
  const face = `m5-face-${uid}`;
  return (
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={rim} x1="7" y1="4" x2="25" y2="28" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7DD3FC" />
          <stop offset="1" stopColor="#2563EB" />
        </linearGradient>
        <linearGradient id={face} x1="16" y1="5" x2="16" y2="27" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#0A172E" />
          <stop offset="1" stopColor="#030712" />
        </linearGradient>
      </defs>
      <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" fill="#050A17" stroke="#1E293B" />
      <path
        d="M16 4.8L25 8.1V15.8C25 21.2 21.1 25.2 16 27.3C10.9 25.2 7 21.2 7 15.8V8.1L16 4.8Z"
        fill={`url(#${face})`}
        stroke={`url(#${rim})`}
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M16 5.6L24.1 8.6V15.8C24.1 20.6 20.6 24.3 16 26.3V5.6Z" fill="#2563EB" fillOpacity="0.14" />
      <path d="M16 7.5V24.5" stroke="#38BDF8" strokeOpacity="0.2" strokeWidth="1" strokeDasharray="1 2" />
      <path d="M11.8 12.2H20.2" stroke="#E0F2FE" strokeWidth="1.7" strokeLinecap="round" />
      <path d="M12.6 15.6H19.4" stroke="#38BDF8" strokeWidth="1.7" strokeLinecap="round" />
      <path d="M13.8 19H18.2" stroke="#3B82F6" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}

function BrandLockup({ large }: { large?: boolean }) {
  return (
    <div className="brand" style={large ? { fontSize: 16 } : undefined}>
      <span className="brand-mark" style={large ? { width: 28, height: 28, flexBasis: 28 } : undefined}>
        <BrandMark />
      </span>
      <span className="brand-name">WAF-Proxy</span>
    </div>
  );
}

function AuthFrame({ title, sub, children }: { title: string; sub: string; children: React.ReactNode }) {
  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div style={{ marginBottom: 18 }}><BrandLockup /></div>
        <h1>{title}</h1>
        <p className="sub">{sub}</p>
        {children}
      </div>
    </div>
  );
}

function Setup({ defaults, onDone }: { defaults: SetupStatus | null; onDone: (e: Enrolment) => void }) {
  const [form, setForm] = useState({
    username: "admin",
    password: "",
    // The native installer returns its real first-boot listener addresses, so
    // the wizard cannot silently undo the LAN-only admin binding. Without them
    // (Docker's all-interface fallback) the fields stay blank rather than
    // prefill another network's addresses.
    base_domain: "",
    wan_ip: defaults?.wan_ip ?? "",
    wan_port: defaults?.wan_port ?? 443,
    lan_ip: defaults?.lan_ip ?? "",
    gui_port: defaults?.gui_port ?? 8443,
    duckdns_token: "",
    email: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api.post<{ username: string; totp_secret: string; otpauth_url: string; recovery_codes: string[] }>("/api/setup", form);
      onDone({ username: r.username, secret: r.totp_secret, url: r.otpauth_url, codes: r.recovery_codes });
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <div className="auth-card setup-card">
        <BrandLockup />
        <h1 style={{ marginTop: 18 }}>Set up WAF-Proxy</h1>
        <p className="sub">Network binding is written to the database, not a config file. Only 443 needs to be forwarded.</p>
        <details className="why">
          <summary>Why the base domain matters</summary>
          <p className="faint small-text">
            Every hostname you proxy later is one label under this domain, so a certificate for it covers them all:
            <code>app.example.com</code> works, <code>a.b.example.com</code> does not. The apex domain itself is reserve
            for redirects and is never proxied.
          </p>
        </details>
        <div className="field-grid">
          <div className="field"><label>Admin username</label><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
          <div className="field"><label>Password (12+ characters)</label><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
        </div>
        <div className="field"><label>Base domain</label><input value={form.base_domain} onChange={(e) => setForm({ ...form, base_domain: e.target.value })} placeholder="example.duckdns.org" /></div>
        <div className="field-grid">
          <div className="field"><label>WAN IP</label><input value={form.wan_ip} onChange={(e) => setForm({ ...form, wan_ip: e.target.value })} placeholder="192.168.1.2" /></div>
          <div className="field"><label>WAN port</label><input type="number" value={form.wan_port} onChange={(e) => setForm({ ...form, wan_port: Number(e.target.value) })} /></div>
          <div className="field"><label>LAN egress IP</label><input value={form.lan_ip} onChange={(e) => setForm({ ...form, lan_ip: e.target.value })} placeholder="192.168.1.2" /></div>
          <div className="field"><label>GUI port</label><input type="number" value={form.gui_port} onChange={(e) => setForm({ ...form, gui_port: Number(e.target.value) })} /></div>
        </div>
        <p className="faint small-text" style={{ marginTop: -4 }}>
          Both addresses must exist on this host. On a single-NIC host enter the same address for WAN and LAN.
        </p>
        <details className="why">
          <summary>Why both addresses</summary>
          <p className="faint small-text">
            Visitor traffic arrives on the WAN address; the console stays bound to the LAN address so administration is
            never reachable from the internet. The wizard refuses to continue without both, which is what keeps the
            console off all interfaces.
          </p>
        </details>
        <div className="field"><label>DuckDNS token (optional, stored encrypted)</label><input type="password" value={form.duckdns_token} onChange={(e) => setForm({ ...form, duckdns_token: e.target.value })} /></div>
                  <div className="field"><label>Admin email (ACME and password resets)</label><input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="admin@your-domain.tld" /></div>
        {err && <div className="err-text">{err}</div>}
        <button className="primary mt" style={{ width: "100%" }} disabled={busy} onClick={submit}>
          {busy ? "Creating…" : "Create administrator"}
        </button>
      </div>
    </div>
  );
}

type LoginResult = {
  csrf: string;
  recovery_used?: boolean;
  totp_secret?: string;
  otpauth_url?: string;
};

type LoginView = "login" | "forgot" | "reset" | "recover" | "codes" | "invite" | "invited";

function Login({ onDone }: { onDone: (m: Me) => void }) {
  const [form, setForm] = useState({ username: "", password: "", totp: "", remember: false });
  const [recovery, setRecovery] = useState("");
  const [showRecovery, setShowRecovery] = useState(false);
  const [forgotUser, setForgotUser] = useState("");
  const loginParams = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
  const [inviteToken] = useState(() => (window.location.hash.startsWith("#/invite") ? loginParams.get("token") ?? "" : ""));
  const [resetToken] = useState(() => (window.location.hash.startsWith("#/invite") ? "" : loginParams.get("token") ?? ""));
  const [view, setView] = useState<LoginView>(inviteToken ? "invite" : resetToken ? "reset" : "login");
  const [invite, setInvite] = useState<{ email: string; first_name: string; last_name: string } | null>(null);
  const [inviteForm, setInviteForm] = useState({ username: "", password: "", confirm: "" });
  const [inviteDone, setInviteDone] = useState<{ secret: string; url: string; codes: string[] } | null>(null);
  const [emailAvailable, setEmailAvailable] = useState(false);
  const [sent, setSent] = useState(false);
  const [notice, setNotice] = useState("");
  const [newPassword, setNewPassword] = useState({ next: "", confirm: "" });
  const [pending, setPending] = useState<{ secret: string; url: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get<{ available: boolean }>("/api/password/forgot")
      .then((r) => setEmailAvailable(r.available))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!inviteToken) return;
    api
      .get<{ email: string; first_name: string; last_name: string }>(`/api/invite?token=${encodeURIComponent(inviteToken)}`)
      .then(setInvite)
      .catch((ex) => {
        setErr(errText(ex));
        setView("login");
      });
  }, [inviteToken]);

  // A reset link carries its token in the hash; drop it from the URL once the
  // form is done so a refresh cannot replay it.
  const leaveReset = (message: string) => {
    window.history.replaceState(null, "", window.location.pathname);
    setView("login");
    setNotice(message);
  };

  const enter = async () => {
    try {
      onDone(await api.get<Me>("/api/me"));
    } catch (ex) {
      setErr(errText(ex));
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await api.post<LoginResult>("/api/login", {
        ...form,
        recovery: showRecovery ? recovery : "",
      });
      setCSRF(r.csrf);
      if (r.recovery_used && r.totp_secret) {
        setPending({ secret: r.totp_secret, url: r.otpauth_url ?? "" });
        setView("recover");
        return;
      }
      await enter();
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const sendReset = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.post("/api/password/forgot", { username: forgotUser });
      setSent(true);
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const acceptInvite = async (e: FormEvent) => {
    e.preventDefault();
    if (inviteForm.password !== inviteForm.confirm) {
      setErr("The new passwords do not match");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const r = await api.post<{ totp_secret: string; otpauth_url: string; recovery_codes: string[] }>(
        "/api/invite/accept",
        { token: inviteToken, username: inviteForm.username, password: inviteForm.password },
      );
      setInviteDone({ secret: r.totp_secret, url: r.otpauth_url, codes: r.recovery_codes || [] });
      setView("invited");
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const savePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (newPassword.next !== newPassword.confirm) {
      setErr("The new passwords do not match");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      await api.post("/api/password/reset", { token: resetToken, password: newPassword.next });
      leaveReset("Password changed. Sign in with the new one.");
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const confirmRecoverySetup = async () => {
    if (!pending) return;
    setBusy(true);
    setErr("");
    try {
      const r = await api.post<{ recovery_codes: string[] }>("/api/account/totp/confirm", {
        secret: pending.secret,
        code,
      });
      setCodes(r.recovery_codes || []);
      setView("codes");
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const heading =
    view === "forgot" ? "Reset password" : view === "reset" ? "Choose a new password"
      : view === "recover" ? "Replace your authenticator" : view === "codes" ? "Save your recovery codes"
        : view === "invite" ? "Create your account" : view === "invited" ? "Your account is ready" : "Sign in";

  return (
    <div className="login-split">
      <section className="login-brand">
        <BrandLockup large />
        <div className="login-pitch">
          <h1>Your edge,<br /><span>accounted for.</span></h1>
          <p>A self-hosted web application firewall and reverse proxy. Every request, policy decision and ban in one operational console.</p>
          <div className="login-points">
            <div className="login-point"><Icon name="shield" /><span>WAF, bot filtering and access gates on every hostname</span></div>
            <div className="login-point"><Icon name="activity" /><span>Live traffic, sessions and upstream health</span></div>
            <div className="login-point"><Icon name="lock" /><span>Password + authenticator, audited administrator actions</span></div>
          </div>
        </div>
        <div className="login-meta">
          <span>Self-hosted</span>
          <span>Administrator console</span>
          <span>Restricted access</span>
        </div>
      </section>
      <section className="login-form-side">
        <div className="login-form">
          <div className="login-mobile-brand"><BrandLockup /></div>
          <h2>{heading}</h2>

          {view === "login" && (
            <>
              <p className="sub">Administrator access requires your password and an authenticator code.</p>
              {notice && <div className="banner ok" role="status" style={{ marginBottom: 14 }}>{notice}</div>}
              <form onSubmit={submit}>
                <div className="field">
                  <label>Username</label>
                  <input autoFocus value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="username" />
                </div>
                <div className="field">
                  <label>Password</label>
                  <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="current-password" />
                </div>
                <div className="field">
                  <label>Authenticator code</label>
                  <input value={form.totp} onChange={(e) => setForm({ ...form, totp: e.target.value })} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
                </div>
                {showRecovery ? (
                  <div className="field">
                    <label>Recovery code</label>
                    <input autoFocus value={recovery} onChange={(e) => setRecovery(e.target.value)} autoComplete="off" placeholder="ABCDE-12345" />
                  </div>
                ) : null}
                <label className="checkbox" style={{ marginBottom: 12 }}>
                  <input type="checkbox" checked={form.remember} onChange={(e) => setForm({ ...form, remember: e.target.checked })} />
                  Remember this device for 30 days
                </label>
                <div className="row" style={{ justifyContent: "space-between", gap: 10 }}>
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => setShowRecovery((v) => !v)}
                  >
                    {showRecovery ? "Use the authenticator instead" : "Don't have your authenticator code?"}
                  </button>
                  {emailAvailable ? (
                    <button type="button" className="link-button" onClick={() => { setView("forgot"); setErr(""); setSent(false); }}>
                      Forgot password?
                    </button>
                  ) : null}
                </div>
                {err && <div className="err-text">{err}</div>}
                <button className="primary mt" style={{ width: "100%" }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
              </form>
            </>
          )}

          {view === "forgot" && (
            <>
              <p className="sub">A single-use link is emailed to the address on your administrator profile. It expires in 30 minutes.</p>
              {sent ? (
                <>
                  <div className="banner ok" role="status">
                    If {forgotUser || "that name"} is an administrator here, a reset link is on its way.
                  </div>
                  <button className="mt" style={{ width: "100%" }} onClick={() => setView("login")}>Back to sign in</button>
                </>
              ) : (
                <form onSubmit={sendReset}>
                  <div className="field">
                    <label>Username</label>
                    <input autoFocus value={forgotUser} onChange={(e) => setForgotUser(e.target.value)} autoComplete="username" />
                  </div>
                  {err && <div className="err-text">{err}</div>}
                  <button className="primary mt" style={{ width: "100%" }} disabled={busy || !forgotUser}>{busy ? "Sending…" : "Email me a reset link"}</button>
                  <button type="button" className="link-button mt" style={{ display: "block", margin: "12px auto 0" }} onClick={() => setView("login")}>Back to sign in</button>
                </form>
              )}
            </>
          )}

          {view === "reset" && (
            <form onSubmit={savePassword}>
              <p className="sub">Choose a password of at least 12 characters. Signing in again needs the authenticator unless this device is remembered.</p>
              <div className="field">
                <label>New password</label>
                <input autoFocus type="password" value={newPassword.next} onChange={(e) => setNewPassword({ ...newPassword, next: e.target.value })} autoComplete="new-password" />
              </div>
              <div className="field">
                <label>Repeat new password</label>
                <input type="password" value={newPassword.confirm} onChange={(e) => setNewPassword({ ...newPassword, confirm: e.target.value })} autoComplete="new-password" />
              </div>
              {err && <div className="err-text">{err}</div>}
              <button className="primary mt" style={{ width: "100%" }} disabled={busy || newPassword.next.length < 12}>
                {busy ? "Saving…" : "Set new password"}
              </button>
              <button type="button" className="link-button mt" style={{ display: "block", margin: "12px auto 0" }} onClick={() => setView("login")}>Back to sign in</button>
            </form>
          )}

          {view === "invite" && (
            <form onSubmit={acceptInvite}>
              <p className="sub">
                {invite
                  ? `Welcome${invite.first_name ? `, ${invite.first_name}` : ""}. Create the administrator account for ${invite.email}.`
                  : "Checking this invitation…"}
              </p>
              <div className="field">
                <label>Username</label>
                <input autoFocus value={inviteForm.username} onChange={(e) => setInviteForm({ ...inviteForm, username: e.target.value })} autoComplete="username" />
              </div>
              <div className="field">
                <label>Password (12+ characters)</label>
                <input type="password" value={inviteForm.password} onChange={(e) => setInviteForm({ ...inviteForm, password: e.target.value })} autoComplete="new-password" />
              </div>
              <div className="field">
                <label>Repeat password</label>
                <input type="password" value={inviteForm.confirm} onChange={(e) => setInviteForm({ ...inviteForm, confirm: e.target.value })} autoComplete="new-password" />
              </div>
              {err && <div className="err-text">{err}</div>}
              <button className="primary mt" style={{ width: "100%" }} disabled={busy || !invite?.email || !inviteForm.username || inviteForm.password.length < 12}>
                {busy ? "Creating…" : "Create account"}
              </button>
              <button type="button" className="link-button mt" style={{ display: "block", margin: "12px auto 0" }} onClick={() => leaveReset("")}>Back to sign in</button>
            </form>
          )}

          {view === "invited" && inviteDone && (
            <>
              <p className="sub">
                Add this secret to your authenticator app now; every sign-in asks for the code it
                shows. Store the recovery codes somewhere safe, then sign in with your new
                username and password.
              </p>
              <div className="secret-box">{inviteDone.secret}</div>
              <div className="secret-box" style={{ fontSize: 11.5 }}>{inviteDone.url}</div>
              <label style={{ marginTop: 14 }}>Recovery codes</label>
              <div className="code-list">{inviteDone.codes.map((c) => <div key={c}>{c}</div>)}</div>
              <button className="primary mt" style={{ width: "100%" }} onClick={() => leaveReset("Account created. Sign in with your username, password and authenticator code.")}>
                Continue to sign in
              </button>
            </>
          )}

          {view === "recover" && pending && (
            <>
              <p className="sub">Your recovery code worked, so the old authenticator is no longer trusted. Add this secret to your authenticator app now, or skip and do it later from Account.</p>
              <div className="secret-box">{pending.secret}</div>
              <div className="secret-box" style={{ fontSize: 11.5 }}>{pending.url}</div>
              <div className="field" style={{ marginTop: 12 }}>
                <label>New authenticator code</label>
                <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
              </div>
              {err && <div className="err-text">{err}</div>}
              <button className="primary mt" style={{ width: "100%" }} disabled={busy || code.length !== 6} onClick={confirmRecoverySetup}>
                {busy ? "Confirming…" : "Confirm new authenticator"}
              </button>
              <button type="button" className="link-button mt" style={{ display: "block", margin: "12px auto 0" }} onClick={enter}>
                Later — continue to the console
              </button>
            </>
          )}

          {view === "codes" && (
            <>
              <p className="sub">These replace every earlier recovery code. They are shown once.</p>
              <div className="code-list">{codes.map((c) => <div key={c}>{c}</div>)}</div>
              <button className="primary mt" style={{ width: "100%" }} onClick={enter}>I saved them — continue</button>
            </>
          )}

          <p className="login-foot">
            This console is restricted to administrators. Sessions expire after 12 hours of inactivity.
            {" "}<a href={DOCS_URL} target="_blank" rel="noreferrer">Documentation</a>
            {" · "}<a href={COFFEE_URL} target="_blank" rel="noreferrer">Buy me a coffee</a>
          </p>
        </div>
      </section>
    </div>
  );
}
