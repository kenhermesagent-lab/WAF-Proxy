package updates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogIsFixedAndValid(t *testing.T) {
	names := CatalogNames()
	if len(names) != 8 {
		t.Fatalf("catalog names = %v, want 8 entries", names)
	}
	want := map[string]bool{
		"ca-certificates": true, "nftables": true, "tzdata": true,
		"curl": true, "openssl": true, "git": true, "crowdsec": true, "tailscale": true,
	}
	for _, name := range names {
		if !want[name] {
			t.Fatalf("unexpected catalog package %q", name)
		}
		if !validPackageName(name) {
			t.Fatalf("catalog package %q failed validation", name)
		}
	}
	if managed("nginx") {
		t.Fatal("nginx must not be accepted by the fixed catalog")
	}
	if validPackageName("-o") || validPackageName("../x") || validPackageName("Pkg") {
		t.Fatal("package validation accepted an unsafe name")
	}
}

func TestParseAptPolicy(t *testing.T) {
	out := `nftables:
  Installed: 1.0.9-1
  Candidate: 1.0.9-1+deb12u1
  Version table:
     1.0.9-1+deb12u1 500
        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages
 *** 1.0.9-1 100
        100 /var/lib/dpkg/status
`
	candidate, security := parseAptPolicy(out)
	if candidate != "1.0.9-1+deb12u1" || !security {
		t.Fatalf("parseAptPolicy = %q, %v", candidate, security)
	}
	normal := `tzdata:
  Installed: 2024a-0+deb12u1
  Candidate: 2024b-0+deb12u1
  Version table:
     2024b-0+deb12u1 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
 *** 2024a-0+deb12u1 100
        100 /var/lib/dpkg/status
`
	candidate, security = parseAptPolicy(normal)
	if candidate != "2024b-0+deb12u1" || security {
		t.Fatalf("normal policy = %q, %v", candidate, security)
	}
	if candidate, _ := parseAptPolicy("pkg:\n  Candidate: (none)\n"); candidate != "" {
		t.Fatalf("none candidate = %q", candidate)
	}
}

func TestCVSSv3Score(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H", 6.5},
	}
	for _, tc := range cases {
		got, ok := CVSSv3Score(tc.vector)
		if !ok || got != tc.want {
			t.Errorf("CVSSv3Score(%q) = %v, %v; want %v", tc.vector, got, ok, tc.want)
		}
	}
	if _, ok := CVSSv3Score("not-a-vector"); ok {
		t.Fatal("invalid vector was accepted")
	}
}

func TestHighestSeverityUsesCVSSAndUbuntuPriority(t *testing.T) {
	sev, score := highestSeverity(osvVuln{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}})
	if sev != "critical" || score != "9.8" {
		t.Fatalf("cvss severity = %q, %q", sev, score)
	}
	sev, _ = highestSeverity(osvVuln{Severity: []osvSeverity{{Type: "Ubuntu", Score: "high"}}})
	if sev != "high" {
		t.Fatalf("ubuntu severity = %q", sev)
	}
}

func TestSnapshotBuildsInventoryAndHighAdvisories(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			t.Errorf("unexpected OSV path %s", r.URL.Path)
		}
		var body struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		}
		_ = readJSON(r, &body)
		vulns := []map[string]any{}
		if body.Package.Name == "nftables" {
			vulns = append(vulns, map[string]any{
				"id":      "DEBIAN-CVE-2026-9999",
				"summary": "A high severity issue",
				"severity": []map[string]string{{
					"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				}},
			})
		}
		_ = writeJSON(w, map[string]any{"vulns": vulns})
	}))
	defer osv.Close()

	m := &Manager{
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		host:         hostInfo{available: true, platform: "Debian 12", ecosystem: "Debian:12"},
		helperSocket: filepath.Join(t.TempDir(), "missing.sock"),
		osvBase:      osv.URL,
		client:       osv.Client(),
		now:          func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "dpkg-query":
				return []byte("ca-certificates\t1.0\ntimezone\tnever\nnftables\t1.0\ntzdata\t1.0\n"), nil
			case "apt-cache":
				return []byte("  Installed: 1.0\n  Candidate: 1.1\n  Version table:\n     1.1 500\n        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages\n *** 1.0 100\n        100 /var/lib/dpkg/status\n"), nil
			case "dpkg":
				return nil, nil
			}
			return nil, nil
		},
	}
	snap := m.Snapshot(context.Background())
	if !snap.Available || snap.CheckedAt == "" {
		t.Fatalf("snapshot not available: %+v", snap)
	}
	// Every catalog entry is reported; packages dpkg does not know are shown as
	// missing rather than silently omitted.
	if len(snap.Packages) != len(Catalog()) {
		t.Fatalf("packages = %d, want %d", len(snap.Packages), len(Catalog()))
	}
	first := snap.Packages[0]
	if first.Name != "nftables" || first.Status != "security" || first.Severity != "high" {
		t.Fatalf("first package = %+v", first)
	}
	if len(first.Advisories) != 1 || first.Advisories[0].ID != "DEBIAN-CVE-2026-9999" {
		t.Fatalf("advisories = %+v", first.Advisories)
	}
	if first.CanUpdate {
		t.Fatal("package cannot be updated without a running helper")
	}
	if !strings.Contains(first.Note, "helper") {
		t.Fatalf("note = %q", first.Note)
	}
}

func TestSnapshotRefusesContainer(t *testing.T) {
	m := &Manager{
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		host: hostInfo{container: true, reason: "container"},
		now:  time.Now,
	}
	snap := m.Snapshot(context.Background())
	if snap.Available {
		t.Fatal("container snapshot must be unavailable")
	}
	if !snap.Container || snap.Reason != "container" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func readJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func TestCheckAndApplyUseTheHelperSocket(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "updates.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	requests := make(chan HelperRequest, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req HelperRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}
			requests <- req
			_ = json.NewEncoder(conn).Encode(HelperResponse{OK: true, Output: "done " + req.Action})
			_ = conn.Close()
		}
	}()

	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = writeJSON(w, map[string]any{"vulns": []any{}})
	}))
	defer osv.Close()

	m := &Manager{
		host:         hostInfo{available: true, platform: "Debian 12", ecosystem: "Debian:12"},
		helperSocket: socket,
		osvBase:      osv.URL,
		client:       osv.Client(),
		now:          func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
		run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			switch name {
			case "dpkg-query":
				return []byte("ca-certificates\t1.0\nnftables\t1.0\ntzdata\t1.0\n"), nil
			case "apt-cache":
				return []byte("  Candidate: 1.0\n  Version table:\n *** 1.0 100\n"), nil
			}
			return nil, nil
		},
	}

	if _, err := m.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if req := <-requests; req.Action != HelperActionCheck {
		t.Fatalf("check request = %+v", req)
	}
	res, err := m.Apply(context.Background(), "nftables")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if req := <-requests; req.Action != HelperActionApply || req.Package != "nftables" {
		t.Fatalf("apply request = %+v", req)
	}
	if res.Output != "done apply" {
		t.Fatalf("apply output = %q", res.Output)
	}
	if _, err := m.Apply(context.Background(), "nginx"); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("unmanaged apply error = %v", err)
	}
}
