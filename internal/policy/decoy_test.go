package policy

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A whitelisted source is still a scanner's source. The honeypot must fire for
// it, otherwise a compromised friendly host can probe decoy paths freely.
func TestWhitelistDoesNotBypassDecoy(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyIPWhitelist, Value: "203.0.113.7", Action: "allow", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyDecoy, Value: "/secret-admin", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	v := screen(pol, "203.0.113.7", "/secret-admin")
	if v.Action != "ban" || v.Stage != "decoy" {
		t.Fatalf("whitelisted address bypassed the decoy honeypot: %+v", v)
	}
}

// Upstreams route "/./.env", "//.env" and "/x/../.env" to the same file, so the
// decoy comparison has to see the canonical path or the honeypot is trivial to
// sidestep.
func TestDecoyMatchesCanonicalPaths(t *testing.T) {
	pol, st, _ := newEngine(t)
	if _, err := st.CreatePolicy(&model.Policy{
		Scope: "global", Kind: model.PolicyDecoy, Value: "/.env", Action: "block", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/.env", "/./.env", "//.env", "/x/../.env", "/.env/", "/././.env", "/.ENV"} {
		if v := screen(pol, "203.0.113.7", path); v.Action != "ban" {
			t.Errorf("%q did not trigger the decoy: %+v", path, v)
		}
	}
	// A decoy must not swallow unrelated paths that merely share a prefix.
	for _, path := range []string{"/.environment", "/", "/safe/.env.example"} {
		if v := screen(pol, "203.0.113.7", path); v.Action == "ban" {
			t.Errorf("%q matched the decoy but should not: %+v", path, v)
		}
	}
}

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"":                 "/",
		"/":                "/",
		"/./.env":          "/.env",
		"//.env":           "/.env",
		"/x/../.env":       "/.env",
		"/.env/":           "/.env",
		"/Secret-Admin":    "/secret-admin",
		"/a//b/./c/../d/":  "/a/b/d",
		"/..":              "/",
		"/trailing/slash/": "/trailing/slash",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}
