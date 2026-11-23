package canary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunNamesTheFailingStage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		failed string
	}{
		{"healthy", http.StatusOK, ""},
		{"waf block", http.StatusForbidden, "waf"},
		{"rate limit", http.StatusTooManyRequests, "waf"},
		{"routing", http.StatusMisdirectedRequest, "route"},
		{"upstream down", http.StatusBadGateway, "upstream"},
		{"upstream error", http.StatusInternalServerError, "upstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != Path {
					t.Errorf("probe path = %q", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("canary"))
			}))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "http://")
			res := Prober{Scheme: "http"}.Run(context.Background(), host)
			if res.Failed != tc.failed {
				t.Fatalf("failed stage = %q, want %q (%+v)", res.Failed, tc.failed, res.Stages)
			}
			if res.OK != (tc.failed == "") {
				t.Fatalf("ok = %v for %q", res.OK, tc.name)
			}
			if tc.failed != "" {
				last := res.Stages[len(res.Stages)-1]
				if last.Name != tc.failed || last.OK {
					t.Fatalf("last stage = %+v, want failed %q", last, tc.failed)
				}
			}
		})
	}
}

func TestRunFailsAtConnectWhenNothingListens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	res := Prober{Scheme: "http"}.Run(context.Background(), host)
	if res.OK || res.Failed != "connect" {
		t.Fatalf("result = %+v, want connect failure", res)
	}
}

func TestRunRejectsAnEmptyHost(t *testing.T) {
	res := Prober{}.Run(context.Background(), "  ")
	if res.Failed != "config" {
		t.Fatalf("failed stage = %q, want config", res.Failed)
	}
}

func testCert(t *testing.T, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "canary.test"},
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}
}

func tlsProbe(t *testing.T, cert tls.Certificate) (*httptest.Server, Prober) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return srv, Prober{Scheme: "https", RootCAs: pool}
}

func TestRunFailsAtTLSForAnExpiredCertificate(t *testing.T) {
	cert := testCert(t, []string{"canary.test"}, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	srv, probe := tlsProbe(t, cert)
	defer srv.Close()
	res := probe.Run(context.Background(), srv.Listener.Addr().String())
	if res.Failed != "tls" {
		t.Fatalf("failed stage = %q, want tls (%+v)", res.Failed, res.Stages)
	}
	last := res.Stages[len(res.Stages)-1]
	if !strings.Contains(last.Detail, "certificate expired") {
		t.Fatalf("expiry not reported: %q", last.Detail)
	}
	if res.CertExpiresAt == "" {
		t.Fatal("certificate expiry was not recorded")
	}
}

func TestRunFailsAtTLSForAWrongHostCertificate(t *testing.T) {
	cert := testCert(t, []string{"other.example.com"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	srv, _ := tlsProbe(t, cert)
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(parsed)
	probe := Prober{Scheme: "https", RootCAs: pool,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}
	res := probe.Run(context.Background(), "localhost:"+strconv.Itoa(port))
	if res.Failed != "tls" {
		t.Fatalf("failed stage = %q, want tls (%+v)", res.Failed, res.Stages)
	}
	last := res.Stages[len(res.Stages)-1]
	if !strings.Contains(last.Detail, "other.example.com") {
		t.Fatalf("hostname mismatch not reported: %q", last.Detail)
	}
}

func TestRunPassesTLSAgainstAMatchingCertificate(t *testing.T) {
	cert := testCert(t, []string{"canary.test"}, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	srv, probe := tlsProbe(t, cert)
	defer srv.Close()
	res := probe.Run(context.Background(), srv.Listener.Addr().String())
	if !res.OK {
		t.Fatalf("probe failed: %+v", res)
	}
	var tlsStage *Stage
	for i := range res.Stages {
		if res.Stages[i].Name == "tls" {
			tlsStage = &res.Stages[i]
		}
	}
	if tlsStage == nil || !tlsStage.OK || !strings.Contains(tlsStage.Detail, "expires in") {
		t.Fatalf("tls stage = %+v", tlsStage)
	}
}

func TestProberReportsEmptyResolutionAsDNSStage(t *testing.T) {
	p := Prober{Resolve: func(context.Context, string) ([]string, error) { return nil, nil }}
	res := p.Run(context.Background(), "app.example.com")
	if res.OK || res.Failed != "dns" {
		t.Fatalf("empty resolution = %+v", res)
	}
	last := res.Stages[len(res.Stages)-1]
	if last.Name != "dns" || !strings.Contains(last.Detail, "no addresses") {
		t.Fatalf("dns stage = %+v", last)
	}
}
