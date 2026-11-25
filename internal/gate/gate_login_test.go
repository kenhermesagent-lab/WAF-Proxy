package gate

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// An unknown account must cost one password hash, so the login form cannot be
// used to learn which gate usernames exist from response timing.
func TestGateLoginHashesForAnUnknownAccount(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{
		st: st, box: box, limiter: auth.NewLimiter(), now: time.Now,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	p := &model.Proxy{ID: 1, Hostname: "app.example.com", GateMode: "accounts"}

	hashed := 0
	prev := dummyVerify
	dummyVerify = func(string) { hashed++ }
	defer func() { dummyVerify = prev }()

	r := httptest.NewRequest(http.MethodPost, "http://app.example.com"+LoginPath,
		strings.NewReader("username=admin&password=wrong&next=%2F"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if !g.Handle(rec, r, p, netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("the gate did not handle a login post")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if hashed != 1 {
		t.Fatalf("argon2 ran %d times for an unknown account, want 1", hashed)
	}
}
