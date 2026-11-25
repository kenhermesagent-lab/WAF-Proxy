package scan

import (
	"bytes"
	"strings"
	"testing"
)

func TestDifferentialMarksInconclusiveOnDynamicBody(t *testing.T) {
	page := "Welcome. Serving requests since 2019. Contact us. " + strings.Repeat("filler ", 20)
	first := answer{status: 200, body: []byte(page + "generated 12:00:00")}
	second := answer{status: 200, body: []byte(page + "generated 12:00:07")}

	if v, sim := verdictFor(first, first); v != ReachedBackend || sim != 1 {
		t.Fatalf("identical answers = %q (%.2f), want reached-backend", v, sim)
	}
	if v, sim := verdictFor(first, second); v != Inconclusive || sim >= similarityThreshold {
		t.Fatalf("drifting answers = %q (%.2f), want inconclusive", v, sim)
	}
	blocked := answer{status: 403, body: []byte("request blocked by the edge")}
	if v, _ := verdictFor(blocked, first); v != BlockedWAF {
		t.Fatalf("403 over 200 = %q, want blocked-waf", v)
	}
	if v, _ := verdictFor(first, blocked); v != Inconclusive {
		t.Fatalf("200 over 403 = %q, want inconclusive", v)
	}
}

// The gate's challenge page is a compensating control, not a WAF block.
func TestGatePageIsABlockNotAFailure(t *testing.T) {
	up := answer{status: 200, body: []byte("hello from the app")}
	wan := answer{status: 200, body: []byte(`<html><form method="post" action="/__wafproxy/gate">`)}
	if v, _ := verdictFor(wan, up); v != BlockedGate {
		t.Fatalf("gate challenge = %q, want blocked-gate", v)
	}
}

func TestSimilarityIgnoresOneChangedBlock(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 1280)
	changed := bytes.Replace(body, []byte("aaaaaaaa"), []byte("bbbbbbbb"), 1)
	if sim := similarity(body, changed); sim < similarityThreshold {
		t.Fatalf("one changed block scored %.2f, want above %.1f", sim, similarityThreshold)
	}
}
