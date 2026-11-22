package perf

import (
	"log/slog"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// The mix is only a useful measurement if every case still does what its name
// says: a benign request the rule set blocks, or an attack it lets through,
// would make the numbers meaningless.
func TestMixHoldsItsExpectations(t *testing.T) {
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	set := waf.NewSet([]model.Profile{{ID: 1, Name: "bench", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, log)
	id := int64(1)
	engine := set.For(&id)
	if engine == nil {
		t.Skip("WAF engine unavailable")
	}
	addr := netip.MustParseAddr("198.51.100.20")
	cases := Mix()
	if len(cases) < 200 {
		t.Fatalf("mix holds %d requests, want at least 200", len(cases))
	}
	for _, c := range cases {
		r, err := http.NewRequest(c.Method, "https://app.example.com"+c.Target, strings.NewReader(c.Body))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		r.Header.Set("User-Agent", c.UA)
		if c.Type != "" {
			r.Header.Set("Content-Type", c.Type)
		}
		res := engine.Inspect(r, []byte(c.Body), addr)
		if res.Blocked != c.Blocked {
			t.Errorf("%s (%s): blocked=%v, want %v (rule %d %s)", c.Name, c.Target, res.Blocked, c.Blocked, res.RuleID, res.Message)
		}
	}
}

func TestMixIsDeterministic(t *testing.T) {
	if !reflect.DeepEqual(Mix(), Mix()) {
		t.Fatal("two calls produced different request mixes")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
