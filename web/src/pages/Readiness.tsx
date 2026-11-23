import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, PageHead, Skeleton, errText, fmtAgo } from "../ui";
import type { AgentLink, Cert, CrowdSecStatus, GeoIPStatus, Me } from "../types";

type Backup = { config: { enabled: boolean }; status: { last_run?: string; last_error?: string } };
type Chain = { ok: boolean; checked: number; problem?: string };

type Row = {
  id: string;
  label: string;
  detail: string;
  ready: boolean | null;
  fix: string;
  link: string;
  optional?: boolean;
};

export default function Readiness({ me, onError }: { me: Me | null; onError: (m: string) => void }) {
  const [settings, setSettings] = useState<Record<string, string> | null>(null);
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [backup, setBackup] = useState<Backup | null>(null);
  const [agents, setAgents] = useState<AgentLink[] | null>(null);
  const [chain, setChain] = useState<Chain | null>(null);
  const [crowdsec, setCrowdsec] = useState<CrowdSecStatus | null>(null);
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
      api.get<GeoIPStatus>("/api/geoip").then((v) => alive && setGeo(v)).catch(() => fail("geoip")),
      api.get<Backup>("/api/backup/schedule").then((v) => alive && setBackup(v)).catch(() => fail("backup")),
      api.get<AgentLink[]>("/api/agents").then((v) => alive && setAgents(v)).catch(() => fail("agents")),
      api.get<Chain>("/api/audit/verify").then((v) => alive && setChain(v)).catch(() => fail("chain")),
      api.get<CrowdSecStatus>("/api/crowdsec/status").then((v) => alive && setCrowdsec(v)).catch(() => fail("crowdsec")),
    ]).finally(() => {
      if (alive) setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  const has = (name: string) => !failed.includes(name);

  const notifyTargets = agents?.filter((a) => a.enabled).length ?? 0;

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
      id: "tls",
      label: "TLS certificate issued",
      detail: certs?.length ? `${certs.filter((c) => c.status === "issued").length} of ${certs.length} certificates issued.` : "No certificate is stored.",
      ready: has("certs") && certs ? certs.some((c) => c.status === "issued") : null,
      fix: "Open Certificates",
      link: "certs",
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
      id: "notify",
      label: "Notification target configured",
      detail: notifyTargets
        ? `${notifyTargets} enabled target${notifyTargets === 1 ? "" : "s"}.`
        : "No enabled notification target, so alerts go nowhere.",
      ready: has("agents") && agents ? agents.some((a) => a.enabled) : null,
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
      link: "crowdsec",
      optional: true,
    },
  ];

  const scored = rows.filter((r) => !r.optional);
  const met = scored.filter((r) => r.ready).length;
  const unknown = scored.filter((r) => r.ready === null).length;
  const pct = scored.length ? Math.round((met / scored.length) * 100) : 0;
  const tone = pct === 100 ? "ok" : pct >= 60 ? "warn" : "bad";
  const verdict = pct === 100 ? "hardened" : pct >= 60 ? "partly hardened" : "not hardened";

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead
        title="Readiness"
        sub="What a hardened install has that a working one may not. Every row links to the control that fixes it."
      />

      <Card>
        {loading ? (
          <Skeleton kind="line" count={3} />
        ) : (
          <>
            <div className="row between" style={{ alignItems: "baseline" }}>
              <div>
                <div className="kpi-value" style={{ fontSize: 26 }}>{met} of {scored.length} ready</div>
                <div className="kpi-sub">
                  {pct}% complete{unknown > 0 ? ` · ${unknown} could not be checked` : ""}
                </div>
              </div>
              <Badge tone={tone}>{verdict}</Badge>
            </div>
            <div className="kpi-meter" aria-hidden="true" style={{ marginTop: 12 }}>
              <span style={{ width: `${pct}%`, background: `var(--${tone === "bad" ? "danger" : tone})` }} />
            </div>
          </>
        )}
      </Card>

      <Card title="Checklist">
        {loading ? (
          <Skeleton kind="line" count={6} />
        ) : (
          <div className="grid" style={{ gap: 0 }}>
            {rows.map((r) => (
              <div className="bar-row" key={r.id} style={{ gridTemplateColumns: "minmax(0, 1fr) auto" }}>
                <div style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 8 }}>
                    <span>{r.label}</span>
                    {r.optional ? <Badge>optional</Badge> : null}
                    {r.ready === null ? <Badge tone="warn">unknown</Badge> : r.ready ? <Badge tone="ok">ready</Badge> : <Badge tone="bad">missing</Badge>}
                  </div>
                  <div className="faint small-text" style={{ marginTop: 2 }}>{r.detail}</div>
                </div>
                {r.ready === true ? (
                  <span className="faint small-text">—</span>
                ) : (
                  <a className="link-button" href={`#/${r.link}`}>{r.fix}</a>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
