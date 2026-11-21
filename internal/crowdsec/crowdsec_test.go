package crowdsec

import (
	"io"
	"log/slog"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
)

func TestManagerCanBeConfiguredAtRuntime(t *testing.T) {
	m := New("", "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if m != nil {
		t.Fatal("a manager without a ban engine should be nil")
	}
	m = New("", "", &banEngineForTest{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if m == nil {
		t.Fatal("disabled manager should still allow later configuration")
	}
	if configured := m.Status()["configured"]; configured != false {
		t.Fatalf("configured = %v", configured)
	}
	m.SetConfig("http://127.0.0.1:8081/", "key")
	if configured := m.Status()["configured"]; configured != true {
		t.Fatalf("configured = %v", configured)
	}
	if lapi := m.Status()["lapi"]; lapi != "http://127.0.0.1:8081" {
		t.Fatalf("lapi = %v", lapi)
	}
	m.SetConfig("", "")
	if configured := m.Status()["configured"]; configured != false {
		t.Fatalf("configured after disable = %v", configured)
	}
}

type banEngineForTest = ban.Engine

func TestDecisionCIDR(t *testing.T) {
	cases := []struct {
		d    Decision
		want string
		ok   bool
	}{
		{Decision{Scope: "Ip", Value: "203.0.113.7"}, "203.0.113.7/32", true},
		{Decision{Scope: "Ip", Value: "2001:db8::1"}, "2001:db8::1/128", true},
		{Decision{Scope: "Range", Value: "203.0.113.0/24"}, "203.0.113.0/24", true},
		{Decision{Scope: "Country", Value: "RU"}, "", false},
		{Decision{Scope: "Ip", Value: "nonsense"}, "", false},
	}
	for _, c := range cases {
		got, ok := decisionCIDR(c.d)
		if ok != c.ok || got != c.want {
			t.Fatalf("%+v: got %q ok=%v want %q ok=%v", c.d, got, ok, c.want, c.ok)
		}
	}
}
