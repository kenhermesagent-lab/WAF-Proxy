package acme

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestTunnelledRefusesChallengesThatNeedThisHost(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetSettings(map[string]string{
		cloudflared.KeyPublished: cloudflared.EncodePublished([]string{"app.example.com"}),
	}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{st: st}
	cases := []struct {
		name      string
		domains   string
		challenge string
		want      string
	}{
		{"published http", "app.example.com", model.CertChallengeHTTP, "app.example.com"},
		{"published alpn", "app.example.com", model.CertChallengeTLSALPN, "app.example.com"},
		{"published wildcard", "*.app.example.com", model.CertChallengeHTTP, "app.example.com"},
		{"published dns still works", "app.example.com", model.CertChallengeDNS, ""},
		{"unpublished host", "other.example.com", model.CertChallengeHTTP, ""},
	}
	for _, tc := range cases {
		if got := m.Tunnelled(tc.domains, tc.challenge); got != tc.want {
			t.Errorf("%s: Tunnelled(%q, %q) = %q, want %q", tc.name, tc.domains, tc.challenge, got, tc.want)
		}
	}
}
