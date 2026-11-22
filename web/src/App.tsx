import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api, setCSRF } from "./api";
import { errText } from "./ui";
import { Me, SetupStatus } from "./types";
import { NAV, NAV_GROUPS, NAV_UTILITY, pageFromHash, type NavItem } from "./nav";
import Dashboard from "./pages/Dashboard";
import Statistics from "./pages/Statistics";
import Proxies from "./pages/Proxies";
import Streaming from "./pages/Streaming";
import UpdatesPage from "./pages/Updates";
import AgentPage from "./pages/Agent";
import TailscalePage from "./pages/Tailscale";
import Policies from "./pages/Policies";
import Sources from "./pages/Sources";
import Intel from "./pages/Intel";
import Anomalies from "./pages/Anomalies";
import Certs from "./pages/Certs";
import Access from "./pages/Access";
import Notifications from "./pages/Notifications";
import Logs from "./pages/Logs";
import SettingsPage from "./pages/Settings";
import CrowdSecPage from "./pages/CrowdSec";
import Account from "./pages/Account";

type Phase = "loading" | "setup" | "enrol" | "login" | "app";


type Enrolment = { username: string; secret: string; url: string; codes: string[] };

export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [page, setPage] = useState(() => pageFromHash(window.location.hash));
  const [toast, setToast] = useState("");
  const [enrol, setEnrol] = useState<Enrolment | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [home, setHome] = useState({ lat: 51.5, lon: -0.12 });
  const [navOpen, setNavOpen] = useState(false);

  const notify = (msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast(""), 3500);
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

  // The drawer only exists below 720px; close it when the window grows so it
  // does not reappear open the next time the viewport shrinks.
  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth > 720) setNavOpen(false);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // The active section lives in the URL, so a reload or a shared link opens the
  // same page instead of dropping back to the dashboard.
  useEffect(() => {
    const onHash = () => setPage(pageFromHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

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
    return <div className="auth-wrap"><span className="muted">Loading…</span></div>;
  }

  if (phase === "setup") {
    return <Setup defaults={setupStatus} onDone={(e) => { setEnrol(e); setPhase("enrol"); }} />;
  }

  if (phase === "enrol" && enrol) {
    return (
      <div className="auth-wrap">
        <div className="auth-card">
          <h1>Save your second factor</h1>
          <p className="sub">Scan or paste this secret into an authenticator app. It is shown once.</p>
          <div className="secret-box">{enrol.secret}</div>
          <div className="secret-box" style={{ fontSize: 12 }}>{enrol.url}</div>
          <label style={{ marginTop: 16 }}>Recovery codes</label>
          <div className="code-list">
            {(enrol.codes || []).map((c) => <div key={c}>{c}</div>)}
          </div>
          <button className="primary mt" style={{ width: "100%" }} onClick={() => setPhase("login")}>
            I have saved them — sign in
          </button>
        </div>
      </div>
    );
  }

  if (phase === "login") {
    return (
      <Login
        onDone={(m) => {
          setCSRF(m.csrf);
          setMe(m);
          setPhase("app");
          loadHome();
        }}
      />
    );
  }

  const current = NAV.find((n) => n.id === page) ?? NAV[0];

  const navButton = (n: NavItem) => (
    <button
      key={n.id}
      className={`nav-item ${page === n.id ? "active" : ""}`}
      onClick={() => {
        setPage(n.id);
        setNavOpen(false);
        if (window.location.hash !== `#/${n.id}`) window.location.hash = `#/${n.id}`;
      }}
    >
      <span className="ico">{n.icon}</span>
      {n.label}
    </button>
  );

  return (
    <div className="shell">
      {navOpen && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} />}
      <aside className={`sidebar ${navOpen ? "open" : ""}`}>
        <div className="brand"><img className="brand-mark" src="/favicon.svg" alt="" width={24} height={24} />WAF-Proxy</div>
        {NAV_GROUPS.map((g) => (
          <div className="nav-group" key={g.title}>
            <div className="nav-group-title">{g.title}</div>
            {g.items.map(navButton)}
          </div>
        ))}
        <div className="nav-spacer" />
        <div className="nav-foot">
          {me?.username} · v{me?.version}
        </div>
        {NAV_UTILITY.map(navButton)}
        <button className="nav-item" onClick={logout}><span className="ico">⏻</span>Sign out</button>
        <a
          className="nav-coffee"
          href="https://buymeacoffee.com/kenhermesagent"
          target="_blank"
          rel="noopener noreferrer"
        >
          If you like this tool, you can buy me a coffee at <span>buymeacoffee.com/kenhermesagent</span>
        </a>
      </aside>
      <main className="main">
        <div className="topbar">
          <button
            className="nav-toggle"
            aria-label="Open navigation"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            ≡
          </button>
          <h1>{current.label}</h1>
          <div className="spacer" />
          {me?.base_domain && <span className="badge info">{me.base_domain}</span>}
        </div>
        <div className="content">
          {page === "dashboard" && <Dashboard onError={notify} home={home} />}
          {page === "statistics" && <Statistics onError={notify} />}
          {page === "proxies" && <Proxies onError={notify} onOK={notify} base={me?.base_domain ?? ""} />}
          {page === "streaming" && <Streaming onError={notify} onOK={notify} />}
          {page === "updates" && <UpdatesPage onError={notify} onOK={notify} />}
          {page === "agent" && <AgentPage onError={notify} onOK={notify} />}
          {page === "tailscale" && <TailscalePage onError={notify} onOK={notify} />}
          {page === "policies" && <Policies onError={notify} onOK={notify} />}
          {page === "sources" && <Sources onError={notify} onOK={notify} />}
          {page === "intel" && <Intel onError={notify} onOK={notify} />}
          {page === "anomalies" && <Anomalies onError={notify} onOK={notify} />}
          {page === "crowdsec" && <CrowdSecPage onError={notify} onOK={notify} />}
          {page === "certs" && <Certs onError={notify} onOK={notify} base={me?.base_domain ?? ""} />}
          {page === "access" && <Access onError={notify} onOK={notify} />}
          {page === "notifications" && <Notifications onError={notify} onOK={notify} />}
          {page === "logs" && <Logs onError={notify} />}
          {page === "settings" && <SettingsPage onError={notify} onOK={notify} />}
          {page === "account" && (
            <Account
              onError={notify}
              onOK={notify}
              onSignedOut={() => { setCSRF(""); setMe(null); setPhase("login"); }}
            />
          )}
        </div>
      </main>
      {toast && (
        <div
          role="status"
          aria-live="polite"
          style={{ position: "fixed", bottom: 20, right: 20, background: "#11151c", border: "1px solid #1f2633", padding: "10px 14px", borderRadius: 10, zIndex: 100 }}
        >
          {toast}
        </div>
      )}
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
      <div className="auth-card">
        <h1>Set up WAF-Proxy</h1>
        <p className="sub">Network binding is written to the database, not a config file. Only 443 needs to be forwarded.</p>
        <div className="row grow">
          <div className="field"><label>Admin username</label><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
          <div className="field"><label>Password (12+ characters)</label><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
        </div>
        <div className="field"><label>Base domain</label><input value={form.base_domain} onChange={(e) => setForm({ ...form, base_domain: e.target.value })} placeholder="example.duckdns.org" /></div>
        <div className="row grow">
          <div className="field"><label>WAN IP</label><input value={form.wan_ip} onChange={(e) => setForm({ ...form, wan_ip: e.target.value })} placeholder="192.168.1.2" /></div>
          <div className="field"><label>WAN port</label><input type="number" value={form.wan_port} onChange={(e) => setForm({ ...form, wan_port: Number(e.target.value) })} /></div>
        </div>
        <div className="row grow">
          <div className="field"><label>LAN egress IP</label><input value={form.lan_ip} onChange={(e) => setForm({ ...form, lan_ip: e.target.value })} placeholder="192.168.1.2" /></div>
          <div className="field"><label>GUI port</label><input type="number" value={form.gui_port} onChange={(e) => setForm({ ...form, gui_port: Number(e.target.value) })} /></div>
        </div>
        <p className="sub" style={{ fontSize: 12, marginTop: -4 }}>
          Both addresses must exist on this host. On a single-NIC host enter the same address for WAN and LAN.
        </p>
        <div className="field"><label>DuckDNS token (optional, stored encrypted)</label><input type="password" value={form.duckdns_token} onChange={(e) => setForm({ ...form, duckdns_token: e.target.value })} /></div>
        <div className="field"><label>ACME email</label><input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="admin@your-domain.tld" /></div>
        {err && <div className="err-text">{err}</div>}
        <button className="primary mt" style={{ width: "100%" }} disabled={busy} onClick={submit}>
          {busy ? "Creating…" : "Create administrator"}
        </button>
      </div>
    </div>
  );
}

function Login({ onDone }: { onDone: (m: Me) => void }) {
  const [form, setForm] = useState({ username: "", password: "", totp: "", recovery: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.post("/api/login", form);
      const m = await api.get<Me>("/api/me");
      onDone(m);
    } catch (ex) {
      setErr(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={submit}>
        <h1>Sign in</h1>
        <p className="sub">Administrator access requires a password and an authenticator code.</p>
        <div className="field"><label>Username</label><input autoFocus value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="username" /></div>
        <div className="field"><label>Password</label><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="current-password" /></div>
        <div className="field"><label>Authenticator code</label><input value={form.totp} onChange={(e) => setForm({ ...form, totp: e.target.value })} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" /></div>
        <div className="field"><label>Recovery code (only if the authenticator is lost)</label><input value={form.recovery} onChange={(e) => setForm({ ...form, recovery: e.target.value })} autoComplete="off" placeholder="ABCDE-12345" /></div>
        {err && <div className="err-text">{err}</div>}
        <button className="primary mt" style={{ width: "100%" }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
