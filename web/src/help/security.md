## What this page is for
Attacking this node's own published hostnames the way a stranger would, recording what each layer did with every probe, and joining what the WAF missed to public vulnerability data so a patch can be planned.

It is not a penetration test, cannot be aimed at a third party, and never changes anything on the application.

## Concepts
- **Target** — a proxy record this site may read. The run body carries ids; the server resolves the hostname and upstream itself.
- **Path** — `edge` when the response carried a Cloudflare header and the probe appears in the request log, `local` when the request never left this node. A local run measures this node's WAF, not your edge.
- **Verdict** — `blocked-waf`, `blocked-gate`, `reached-backend`, `not-blocked`, `inconclusive`, `not-run`. The last two are shown as **not clean**: a control that was refused or a probe that never ran proves nothing.
- **Posture** — `covered`, `exposed` or `unknown`. A stale KEV or OSV snapshot makes it `unknown`, never `covered`.
- **Finding** — a stable key with a severity, a recommendation, any CVE ids and whether CISA KEV names it. States are `open`, `accepted` and `resolved`.

## First tasks
- Run **Run scan** on one hostname and open **Scans → Evidence** to see what each layer did.
- Read **Findings**, then accept the ones you are compensating for with a reason, or fix them.
- On **Schedule**, choose a cadence and the triggers you want, then save. The scheduler runs on the active node only.
- On **Vulnerability feed**, sync KEV and check that both sources are current.

## Worth knowing
- A run sends about 120 requests; it is capped at 12 a second, at most four hostnames, and at most two gate login failures, so it cannot trip the gate's own ban ladder.
- The probe path is random and preflight has proven it returns the application's `404`; a catch-all route skips body probes instead of sending them.
- Starting a scan needs `security.run`; accepting a finding, saving the schedule and the limits need `security.write`.
- Evidence keeps hashes, statuses and header names, never a credential or a response body.
- **Pause all scanning** refuses manual and scheduled runs; it does not delete findings.
