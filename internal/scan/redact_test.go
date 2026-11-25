package scan

import (
	"net/http"
	"strings"
	"testing"
)

func TestEvidenceRedactsSecrets(t *testing.T) {
	p := Probe{
		Method: http.MethodGet,
		Path:   "/.wafscan/412-01",
		Query:  "id=1&token=supersecretvalue",
		Header: http.Header{
			"Authorization": {"Bearer sk-live-abcdef"},
			"Cookie":        {"__wfp_gate=c0ffee"},
			"X-Scan-Probe":  {"412-01"},
		},
	}
	out := RedactRequest(p)
	for _, secret := range []string{"supersecretvalue", "sk-live-abcdef", "c0ffee"} {
		if strings.Contains(out, secret) {
			t.Fatalf("evidence kept the credential %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "Authorization: REDACTED") {
		t.Fatalf("the authorization header is not named: %s", out)
	}
	if !strings.Contains(out, "X-Scan-Probe: 412-01") {
		t.Fatalf("the probe token was lost: %s", out)
	}
	if !strings.Contains(out, "token=REDACTED") {
		t.Fatalf("the credential query parameter was not replaced: %s", out)
	}
}
