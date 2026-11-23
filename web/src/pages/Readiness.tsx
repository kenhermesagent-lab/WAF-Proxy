import { useEffect, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { COFFEE_URL } from "../links";
import { Badge, Card, PageHead, Skeleton, errText, fmtAgo } from "../ui";
import type { Cert, CrowdSecStatus, GeoIPStatus, Me } from "../types";

type Backup = { config: { enabled: boolean }; status: { last_run?: string; last_error?: string } };
type Chain = { ok: boolean; checked: number; problem?: string };
type Notifications = { channels: Record<string, boolean> };
type ProxyRow = { id: number; requests?: number };

type Row = {
  id: string;
  label: string;
  detail: string;
  ready: boolean | null;
  fix: string;
  link: string;
  optional?: boolean;
};

// The rows a first install meets, in the order they matter. The rest are the
// hardening controls an install can live without for a while.
const FIRST_RUN = new Set(["domain", "host", "tls", "traffic", "notify", "mfa", "admins"]);

export default function Readiness({
  me,
  onError,
  head = true,
}: {
  me: Me | null;
  onError: (m: string) => void;
  head?: boolean;
}) {
  const [settings, setSettings] = useState<Record<string, string> | null>(null);
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [proxies, setProxies] = useState<ProxyRow[] | null>(null);
  const [users, setUsers] = useState<unknown[] | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [backup, setBackup] = useState<Backup | null>(null);
  const [notifications, setNotifications] = useState<Notifications | null>(null);
  const [chain, setChain] = useState<Chain | null>(null);
  const [crowdsec, setCrowdsec] = useState<CrowdSecStatus | null>(null);
  const [hideDone, setHideDone] = useState(false);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState<string[]>([]);

  useEffect(() => {
    let alive = true;
    // Every source is independent: one failing endpoint leaves its own row
    // unknown instead of blanking the checklist.
    const fail = (name: string) => {
      if (alive) setFailed((f) => [...f, name]);
    };
    Promise.all([
      api.get<Record<string, string>>("/api/settings")
        .then((v) => alive && setSettings(v))
        .catch((e) => {
          fail("settings");
          onError(errText(e));
        }),
      api.get<{ certs: Cert[] }>("/api/certs").then((v) => alive && setCerts(v.certs ?? [])).catch(() => fail("certs")),
      api.get<{ proxies: ProxyRow[] }>("/api/proxies").then((v) => alive && setProxies(v.proxies ?? [])).catch(() => fail("proxies")),
      api.get<{ users: unknown[] }>("/api/users").then((v) => alive && setUsers(v.users ?? [])).catch(() => fail("users")),
      api.get<GeoIPStatus>("/api/geoip").then((v) => alive && setGeo(v)).catch(() => fail("geoip")),
      api.get<Backup>("/api/backup/schedule").then((v) => alive && setBackup(v)).catch(() => fail("backup")),
      api.get<Notifications>("/api/notifications").then((v) => alive && setNotifications(v)).catch(() => fail("notifications")),
      api.get<Chain>("/api/audit/verify").then((v) => alive && setChain(v)).catch(() => fail("chain")),
      api.get<CrowdSecStatus>("/api/crowdsec/status").then((v) => alive && setCrowdsec(v)).catch(() => fail("crowdsec")),
      api
        .get<Record<string, string>>("/api/me/prefs")
        .then((p) => alive && setHideDone(p["readiness.hide_done"] === "1"))
        .catch(() => undefined),
    ]).finally(() => {
      if (alive) setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  const has = (name: string) => !failed.includes(name);

  const notifyTargets = Object.values(notifications?.channels ?? {}).filter(Boolean).length;
  const served = proxies?.some((p) => (p.requests ?? 0) > 0) ?? false;

  const rows: Row[] = [
    {
      id: "domain",
      label: "Base domain configured",
      detail: settings?.base_domain ? settings.base_domain : "No base domain is set, so ACME and the console hostname are unbound.",
      ready: has("settings") && settings ? !!settings.base_domain : null,
      fix: "Open Settings",
      link: "settings",
    },
    {
      id: "host",
      label: "A hostname is proxied",
      detail: proxies?.length ? `${proxies.length} hostname${proxies.length === 1 ? "" : "s"} configured.` : "No hostname forwards to a backend yet, so nothing can be protected.",
      ready: has("proxies") && proxies ? proxies.length > 0 : null,
      fix: "Open Proxies",
      link: "proxies/sites",
    },
    {
      id: "tls",
      label: "TLS certificate issued",
      detail: certs?.length ? `${certs.filter((c) => c.status === "issued").length} of ${certs.length} certificates issued.` : "No certificate is stored.",
      ready: has("certs") && certs ? certs.some((c) => c.status === "issued") : null,
      fix: "Open Certificates",
      link: "proxies/certs",
    },
    {
      id: "traffic",
      label: "Traffic has arrived",
      detail: served ? "At least one request reached a proxied hostname." : "No request has reached a proxied hostname yet, so the log and counters are empty.",
      ready: has("proxies") && proxies ? served : null,
      fix: "Open Logs",
      link: "logs",
    },
    {
      id: "notify",
      label: "Notification target configured",
      detail: notifyTargets
        ? `${notifyTargets} enabled target${notifyTargets === 1 ? "" : "s"}.`
        : "No enabled notification target, so alerts go nowhere.",
      ready: has("notifications") && notifications ? notifyTargets > 0 : null,
      fix: "Open Notifications",
      link: "notifications",
    },
    {
      id: "mfa",
      label: "Second factor enrolled",
      detail: me?.totp_enabled ? "This account signs in with an authenticator." : "This account signs in with a password only.",
      ready: me ? me.totp_enabled : null,
      fix: "Open Account",
      link: "account",
    },
    {
      id: "admins",
      label: "A second administrator exists",
      detail: users && users.length > 1 ? `${users.length} administrators on this site.` : "One account only, so a lost authenticator means a lockout.",
      ready: has("users") && users ? users.length > 1 : null,
      fix: "Open Team",
      link: "account",
    },
    {
      id: "geoip",
      label: "GeoIP city and ASN databases",
      detail: geo ? (geo.city && geo.asn ? "City and ASN databases loaded." : "A database is missing, so country and ASN rules cannot match.") : "Status unavailable.",
      ready: has("geoip") && geo ? geo.city && geo.asn : null,
      fix: "Open Settings",
      link: "settings",
    },
    {
      id: "kernel",
      label: "Kernel ban enforcement",
      detail:
        settings?.kernel === "active"
          ? "Bans are enforced in the kernel."
          : settings?.kernel
            ? `Bans apply in user space only — ${settings.kernel}.`
            : "Kernel enforcement status is unknown; bans apply in user space.",
      ready: has("settings") && settings ? settings.kernel === "active" : null,
      fix: "Open Settings",
      link: "settings",
    },
    {
      id: "backup",
      label: "Backups scheduled",
      detail: backup?.config.enabled
        ? `Scheduled${backup.status.last_run ? `, last run ${fmtAgo(backup.status.last_run)}` : ", not run yet"}.`
        : "No backup schedule is enabled.",
      ready: has("backup") && backup ? backup.config.enabled : null,
      fix: "Open Settings",
      link: "settings",
    },
    {
      id: "audit",
      label: "Audit chain verified",
      detail: chain ? (chain.ok ? `Intact across ${chain.checked} entries.` : chain.problem || "The chain does not match.") : "Verification unavailable.",
      ready: has("chain") && chain ? chain.ok : null,
      fix: "Open Settings",
      link: "settings",
    },
    {
      id: "crowdsec",
      label: "CrowdSec connected",
      detail: crowdsec?.configured ? `Connected, ${crowdsec.applied} decisions applied.` : "Not connected; the built-in WAF does not need it.",
      ready: has("crowdsec") && crowdsec ? crowdsec.configured : null,
      fix: "Open CrowdSec",
      link: "intel/crowdsec",
      optional: true,
    },
  ];

  const first = rows.filter((r) => FIRST_RUN.has(r.id));
  const hardened = rows.filter((r) => !FIRST_RUN.has(r.id));
  const firstMet = first.filter((r) => r.ready).length;
  const firstUnknown = first.filter((r) => r.ready === null).length;
  const settled = firstMet === first.length && firstUnknown === 0;

  const scored = hardened.filter((r) => !r.optional);
  const met = scored.filter((r) => r.ready).length;
  const unknown = scored.filter((r) => r.ready === null).length;
  const pct = scored.length ? Math.round((met / scored.length) * 100) : 0;
  const tone = settled ? (pct === 100 ? "ok" : pct >= 60 ? "warn" : "bad") : firstMet > 0 ? "warn" : "bad";
  const headline = settled
    ? `${met} of ${scored.length} ready`
    : `${firstMet} of ${first.length} set up`;
  const subline = settled
    ? `${pct}% complete${unknown > 0 ? ` · ${unknown} could not be checked` : ""}`
    : "Finish these and the page switches to the hardening checklist.";
  const verdict = settled ? (pct === 100 ? "hardened" : pct >= 60 ? "partly hardened" : "not hardened") : "setting up";
  const meter = settled ? pct : Math.round((firstMet / Math.max(first.length, 1)) * 100);

  const toggleDone = () => {
    const next = !hideDone;
    setHideDone(next);
    api.put("/api/me/prefs", { key: "readiness.hide_done", value: next ? "1" : "" }).catch(() => undefined);
  };

  const listOf = (list: Row[]) => (
    <div className="grid" style={{ gap: 0 }}>
      {list.map((r) => (
        <div className="bar-row readiness-row" key={r.id}>
          <div style={{ minWidth: 0 }}>
            <div className="row" style={{ gap: 8 }}>
              <span>{r.label}</span>
              {r.optional ? <Badge>optional</Badge> : null}
              {r.ready === null ? <Badge tone="warn">unknown</Badge> : r.ready ? <Badge tone="ok">ready</Badge> : <Badge tone="bad">missing</Badge>}
            </div>
            <div className="faint small-text" style={{ marginTop: 2 }}>{r.detail}</div>
          </div>
          {r.ready === true ? null : <a className="link-button readiness-action" href={`#/${r.link}`}>{r.fix}</a>}
        </div>
      ))}
    </div>
  );

  const firstShown = hideDone ? first.filter((r) => r.ready !== true) : first;

  return (
    <div className="grid" style={{ gap: 14 }}>
      {head && (
        <PageHead sub="What a working install needs next, then what a hardened one has. Every row links to the control that fixes it." />
      )}

      <Card>
        {loading ? (
          <Skeleton kind="line" count={3} />
        ) : (
          <>
            <div className="row between" style={{ alignItems: "baseline" }}>
              <div>
                <div className="kpi-value" style={{ fontSize: 26 }}>{headline}</div>
                <div className="kpi-sub">{subline}</div>
              </div>
              <Badge tone={tone}>{verdict}</Badge>
            </div>
            <div className="kpi-meter" aria-hidden="true" style={{ marginTop: 12 }}>
              <span style={{ width: `${meter}%`, background: `var(--${tone === "bad" ? "danger" : tone})` }} />
            </div>
          </>
        )}
      </Card>

      <Card
        title="Getting started"
        actions={
          firstMet > 0 ? (
            <button className="link-button" onClick={toggleDone}>
              {hideDone ? `Show ${firstMet} done` : `Hide ${firstMet} done`}
            </button>
          ) : null
        }
      >
        {loading ? <Skeleton kind="line" count={4} /> : listOf(firstShown)}
      </Card>

      <Card title="Hardened install">
        {loading ? <Skeleton kind="line" count={6} /> : listOf(hardened)}
      </Card>

      <Card title="Support the project">
        <div className="row between" style={{ gap: 12, flexWrap: "wrap" }}>
          <div>
            <div>WAF-Proxy is built and maintained in the open.</div>
            <div className="faint small-text">If it saves you time, you can buy the maintainer a coffee. Optional, and nothing in the console depends on it.</div>
          </div>
          <a className="link-button" href={COFFEE_URL} target="_blank" rel="noreferrer">
            <Icon name="coffee" size={14} /> Buy me a coffee
          </a>
        </div>
      </Card>
    </div>
  );
}
