package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

// crowdsecBlocklistRow is one aggregated decision group reported by the engine.
type crowdsecBlocklistRow struct {
	Reason string `json:"reason"`
	Origin string `json:"origin"`
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// crowdsecBlocklists is the read-only view the Threat Intel page shows. The
// console owns these subscriptions: the engine pulls and enforces them, and the
// only place to change them is app.crowdsec.net.
type crowdsecBlocklists struct {
	Available bool                   `json:"available"`
	Reason    string                 `json:"reason,omitempty"`
	Rows      []crowdsecBlocklistRow `json:"rows"`
	Total     int                    `json:"total"`
	Raw       string                 `json:"raw,omitempty"`
}

// consoleManagedOrigins are the decision origins the CrowdSec console controls:
// blocklists pulled for a subscribed engine ("lists"), the community blocklist
// ("CAPI") and decisions pushed from the console ("console").
var consoleManagedOrigins = map[string]bool{"lists": true, "capi": true, "console": true}

// getCrowdSecBlocklists reports what the Security Engine is pulling and
// enforcing, including console-subscribed blocklists. It is deliberately
// read-only: there is no edit endpoint behind it.
func (s *Server) getCrowdSecBlocklists(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "CrowdSec") {
		return
	}
	out := crowdsecBlocklists{Rows: []crowdsecBlocklistRow{}}
	if _, err := csLookPath("cscli"); err != nil {
		out.Reason = "CrowdSec is not installed on this host."
		writeJSON(w, http.StatusOK, out)
		return
	}
	raw, err := s.crowdsecDecisionMetrics(r.Context())
	if err != nil {
		out.Reason = helperMessage(err.Error())
		writeJSON(w, http.StatusOK, out)
		return
	}
	parsed := parseDecisionTable(raw)
	out.Available = true
	for _, row := range parsed {
		if consoleManagedOrigins[strings.ToLower(row.Origin)] {
			out.Rows = append(out.Rows, row)
			out.Total += row.Count
		}
	}
	if len(parsed) == 0 && strings.TrimSpace(raw) != "" {
		out.Raw = tail(raw, 4000)
	}
	writeJSON(w, http.StatusOK, out)
}

// crowdsecDecisionMetrics runs `cscli metrics show decisions` through the root
// helper, which aggregates active decisions by reason, origin and action.
func (s *Server) crowdsecDecisionMetrics(ctx context.Context) (string, error) {
	if !s.updates.HelperReady() {
		return "", errors.New("the privileged host helper is not running")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{Action: updatepkg.HelperActionCrowdSecDecisions})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", errors.New(resp.Error)
	}
	return resp.Output, nil
}

// parseDecisionTable reads the box table `cscli metrics show decisions` prints:
//
//	╭────────┬────────┬────────┬───────╮
//	│ Reason │ Origin │ Action │ Count │
//	├────────┼────────┼────────┼───────┤
//	│ free_proxies │ lists │ captcha │ 12668 │
//
// Columns are located by header name so a version that adds a column still
// parses. ASCII tables from older engines are accepted too.
func parseDecisionTable(out string) []crowdsecBlocklistRow {
	var (
		cols  map[string]int
		rows  []crowdsecBlocklistRow
		badge = func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	)
	for _, line := range strings.Split(out, "\n") {
		cells, ok := tableCells(line)
		if !ok {
			continue
		}
		if cols == nil {
			index := map[string]int{}
			for i, c := range cells {
				index[badge(c)] = i
			}
			if _, hasReason := index["reason"]; hasReason {
				if _, hasCount := index["count"]; hasCount {
					cols = index
				}
			}
			continue
		}
		get := func(name string) string {
			if i, ok := cols[name]; ok && i < len(cells) {
				return strings.TrimSpace(cells[i])
			}
			return ""
		}
		count, err := strconv.Atoi(strings.ReplaceAll(get("count"), " ", ""))
		if err != nil {
			continue
		}
		rows = append(rows, crowdsecBlocklistRow{
			Reason: get("reason"),
			Origin: get("origin"),
			Action: get("action"),
			Count:  count,
		})
	}
	return rows
}

// tableCells splits one row of a box or ASCII table, dropping the borders.
func tableCells(line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	var parts []string
	switch {
	case strings.Contains(trimmed, "│"):
		parts = strings.Split(trimmed, "│")
	case strings.HasPrefix(trimmed, "|"):
		parts = strings.Split(trimmed, "|")
	default:
		return nil, false
	}
	if len(parts) < 4 {
		return nil, false // fewer than two cells between the borders
	}
	cells := parts[1 : len(parts)-1]
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	// Skip separators such as +-----+ or ├─────┤.
	for _, c := range cells {
		if strings.Trim(c, "-─+= ") != "" {
			return cells, true
		}
	}
	return nil, false
}
