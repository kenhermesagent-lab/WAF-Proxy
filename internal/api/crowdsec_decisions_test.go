package api

import "testing"

func TestParseDecisionTableReadsBoxTable(t *testing.T) {
	out := "Local API Decisions:\n" +
		" ╭────────────────────────────────────────────┬──────────┬─────────┬───────╮\n" +
		" │                   Reason                   │  Origin  │ Action  │ Count │\n" +
		" ├────────────────────────────────────────────┼──────────┼─────────┼───────┤\n" +
		" │ free_proxies                               │ lists    │ captcha │  12668 │\n" +
		" │ crowdsecurity/http-probing                 │ CAPI     │ ban     │  1805 │\n" +
		" │ crowdsecurity/nginx-req-limit-exceeded     │ CAPI     │ ban     │  130  │\n" +
		" ╰────────────────────────────────────────────┴──────────┴─────────┴───────╯\n"
	rows := parseDecisionTable(out)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}
	if rows[0].Reason != "free_proxies" || rows[0].Origin != "lists" || rows[0].Count != 12668 {
		t.Errorf("first row = %+v, want free_proxies/lists/12668", rows[0])
	}
	if rows[1].Action != "ban" || rows[1].Count != 1805 {
		t.Errorf("second row = %+v, want a CAPI ban of 1805", rows[1])
	}
}

func TestParseDecisionTableAcceptsASCIITable(t *testing.T) {
	out := "+------------------+--------+--------+-------+\n" +
		"|      Reason      | Origin | Action | Count |\n" +
		"+------------------+--------+--------+-------+\n" +
		"| tor-exit-nodes   | lists  | ban    | 42    |\n" +
		"+------------------+--------+--------+-------+\n"
	rows := parseDecisionTable(out)
	if len(rows) != 1 || rows[0].Reason != "tor-exit-nodes" || rows[0].Count != 42 {
		t.Fatalf("rows = %+v, want one tor-exit-nodes row of 42", rows)
	}
}

func TestParseDecisionTableIgnoresUnrelatedOutput(t *testing.T) {
	for _, out := range []string{
		"",
		"time=2026-11-21 level=info msg=starting\n",
		" │ Not a table │\n",
	} {
		if rows := parseDecisionTable(out); len(rows) != 0 {
			t.Errorf("%q produced %+v, want nothing", out, rows)
		}
	}
}
