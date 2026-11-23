package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// incidentReportMarkdown renders the console's Incident report drawer as
// Markdown, so a cron job or runbook can fetch and store a write-up without a
// browser. Timestamps are UTC and counts are comma-grouped; the browser's
// locale-dependent formatting has no server equivalent.
//
// GET /api/ips/{ip}/incident.md?hours=24
func (s *Server) incidentReportMarkdown(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.PathValue("ip"))
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	ip = addr.String()

	f := eventFilterFromQuery(r.URL.Query())
	hours := windowHours(f.From, f.To)
	sum, err := s.st.IPSummary(ip, f.From, f.To)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	events, total, err := s.st.QueryEvents(store.EventFilter{From: f.From, To: f.To, SrcIP: ip, Limit: 100})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	// A role that cannot read the audit log still gets the traffic half, the
	// same bargain the console makes.
	audit, err := s.st.ListAudit(200)
	if err != nil {
		audit = nil
	}
	var ban banInfo
	if s.bans != nil {
		ban = s.banView(ip, s.banIndex())
	}

	body := renderIncidentReport(ip, hours, sum, events, total, audit, ban, time.Now().UTC())
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"incident-%s-%s.md\"", slug(ip), time.Now().UTC().Format("20060102-1504")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func renderIncidentReport(ip string, hours int, sum store.IPSummary, events []model.Event, total int,
	audit []model.AuditEntry, ban banInfo, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Incident report — %s\n\n", ip)
	fmt.Fprintf(&b, "- Window: last %s\n", windowLabel(hours))
	fmt.Fprintf(&b, "- Generated: %s\n\n", reportTime(now))
	b.WriteString("## Summary\n\n")

	country := sum.Country
	if country == "" {
		country = "unknown"
	}
	asn := "?"
	if sum.ASN != 0 {
		asn = strconv.Itoa(sum.ASN)
	}
	share := 0
	if sum.Requests > 0 {
		share = int((sum.Blocked*100 + sum.Requests/2) / sum.Requests)
	}
	fmt.Fprintf(&b, "- Country: %s · AS%s\n", country, asn)
	fmt.Fprintf(&b, "- Requests: %s · blocked %s (%d%%)\n", groupThousands(sum.Requests), groupThousands(sum.Blocked), share)
	fmt.Fprintf(&b, "- Distinct hostnames: %d\n", sum.Hosts)
	fmt.Fprintf(&b, "- First seen %s · last seen %s\n", reportTime(sum.FirstSeen), reportTime(sum.LastSeen))
	if ban.Banned {
		when := "permanent"
		if !ban.Permanent {
			when = "temporary until " + reportTimePtr(ban.BanExpires)
		}
		reason := ban.BanReason
		if reason == "" {
			reason = "no reason recorded"
		}
		fmt.Fprintf(&b, "- Ban: %s · %s\n", when, reason)
	} else {
		b.WriteString("- Ban: none in force\n")
	}

	if len(events) == 0 {
		b.WriteString("\n## No events\n\nNo requests matched this window, so there is nothing further to report.\n")
		fmt.Fprintf(&b, "\nMatching events recorded by the console: %d.", total)
		return b.String()
	}

	// Verdicts counts by stage and action, busiest first; ties keep the order
	// they first appeared in, as the console's Map does.
	type verdict struct{ stage, action string }
	counts := map[verdict]int{}
	var order []verdict
	for _, e := range events {
		key := verdict{orUnknown(e.Stage), orUnknown(e.Action)}
		if _, seen := counts[key]; !seen {
			order = append(order, key)
		}
		counts[key]++
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	b.WriteString("\n## Verdicts\n\n| Stage | Action | Events |\n|---|---|---|\n")
	for _, v := range order {
		fmt.Fprintf(&b, "| %s | %s | %d |\n", cell(v.stage), cell(v.action), counts[v])
	}

	b.WriteString("\n## Timeline (newest first)\n\n| Time | Source | Host | Request | Stage | Rule | Status |\n|---|---|---|---|---|---|---|\n")
	listed := events
	if len(listed) > 50 {
		listed = listed[:50]
	}
	for _, e := range listed {
		rule := e.RuleMsg
		if rule == "" {
			rule = e.RuleID
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			cell(reportTime(e.TS)), cell(e.SrcIP), cell(e.Host), cell(strings.TrimSpace(e.Method+" "+e.Path)),
			cell(e.Stage), cell(rule), cell(strconv.Itoa(e.Status)))
	}
	if len(events) > 50 {
		fmt.Fprintf(&b, "\nThe newest 50 of %d events fetched for this report are listed.", len(events))
	}
	if total > len(events) {
		fmt.Fprintf(&b, "\n\nThe console holds %s matching events for this window.", groupThousands(int64(total)))
	}

	needle := strings.ToLower(ip)
	mentions := []model.AuditEntry{}
	for _, a := range audit {
		if strings.Contains(strings.ToLower(a.Detail+" "+a.Action), needle) {
			mentions = append(mentions, a)
		}
	}
	b.WriteString("\n\n## Actions taken\n\n")
	if len(mentions) == 0 {
		b.WriteString("No administrator action mentioning this subject was recorded in the exported window.")
		return b.String()
	}
	b.WriteString("| Time | Actor | Action | Detail |\n|---|---|---|---|\n")
	if len(mentions) > 30 {
		mentions = mentions[:30]
	}
	for _, a := range mentions {
		actor := a.User
		if actor == "" {
			actor = "system"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", cell(reportTime(a.TS)), cell(actor), cell(a.Action), cell(a.Detail))
	}
	return b.String()
}

func windowHours(from, to time.Time) int {
	return int(to.Sub(from).Hours())
}

func windowLabel(hours int) string {
	switch hours {
	case 1:
		return "1h"
	case 24:
		return "24h"
	case 168:
		return "7d"
	case 720:
		return "30d"
	}
	return strconv.Itoa(hours) + "h"
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// reportTime prints a UTC timestamp; a zero time is a value the report does
// not know and says so.
func reportTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func reportTimePtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return reportTime(*t)
}

// cell keeps a value from breaking a Markdown table.
func cell(v string) string {
	if v == "" {
		return "—"
	}
	return strings.ReplaceAll(v, "|", `\|`)
}

// groupThousands matches the console's en-US grouping, e.g. 1459 -> "1,459".
func groupThousands(n int64) string {
	raw := strconv.FormatInt(n, 10)
	sign := ""
	if strings.HasPrefix(raw, "-") {
		sign, raw = "-", raw[1:]
	}
	var out []byte
	for i, c := range []byte(raw) {
		if i > 0 && (len(raw)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return sign + string(out)
}

// slug matches the console's download filename stem.
func slug(text string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(text) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "console"
	}
	return out
}
