package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// The saved rate applies to every run, and an out-of-range value falls back to
// the default rather than reaching the runner.
func TestProbesPerSecondReadsTheSiteSetting(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if got := ProbesPerSecond(st); got != DefaultPerSecond {
		t.Fatalf("unset = %d, want %d", got, DefaultPerSecond)
	}
	if err := st.SetSetting("security_probes_per_second", "5"); err != nil {
		t.Fatal(err)
	}
	if got := ProbesPerSecond(st); got != 5 {
		t.Fatalf("saved = %d, want 5", got)
	}
	if err := st.SetSetting("security_probes_per_second", "500"); err != nil {
		t.Fatal(err)
	}
	if got := ProbesPerSecond(st); got != DefaultPerSecond {
		t.Fatalf("out of range = %d, want the default", got)
	}
}

// A successful run that used the listener fallback keeps the failed hostname
// and the endpoint it dialled as its first evidence row, so the page can show
// which path was actually taken.
func TestExecuteRecordsTheListenerFallback(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fallback.Close()
	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: fallback.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}

	run, err := Execute(context.Background(), ExecuteDeps{
		Store:       st,
		OSV:         fakeAdvisories{},
		WANBase:     func(string) string { return "https://127.0.0.1:1" },
		WANFallback: func(string) string { return fallback.URL },
	}, *proxy, TriggerManual, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if run.Skipped != "" || run.Path != PathLocal {
		t.Fatalf("run = %+v, want a local run that was not skipped", run)
	}
	evidence, err := st.ListScanEvidence(run.ID)
	if err != nil || len(evidence) == 0 {
		t.Fatalf("evidence = %d rows, %v; want the endpoint row", len(evidence), err)
	}
	row := evidence[0]
	if row.Stage != StagePreflight || row.Class != "endpoint" || row.Method != configMethod {
		t.Fatalf("first row = %+v, want the preflight endpoint row", row)
	}
	for _, want := range []string{fallback.URL + " (Host: app.example.com)", "https://127.0.0.1:1", "did not answer"} {
		if !strings.Contains(row.Note, want) {
			t.Fatalf("endpoint note = %q; want it to contain %q", row.Note, want)
		}
	}
}

// assertEdgeThenFallback runs one site while the fronting proxy answers and
// again once it stops. The first run must record `edge` with no fallback row;
// the second must record `local` with the endpoint row naming the listener that
// answered and the hostname that did not. seen reports the probes the listener
// received through the proxy and whether the site hostname reached it as Host.
func assertEdgeThenFallback(t *testing.T, st *store.Store, rec model.Proxy, deps ExecuteDeps, edgeURL, listenerURL string, stop func(), seen func() (int, bool)) {
	t.Helper()

	run, err := Execute(context.Background(), deps, rec, TriggerManual, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if run.Path != PathEdge {
		t.Fatalf("path = %q, want %q while the proxy answers with CF-Ray", run.Path, PathEdge)
	}
	evidence, err := st.ListScanEvidence(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range evidence {
		if row.Class == "endpoint" {
			t.Fatalf("edge run recorded a listener-fallback row: %+v", row)
		}
	}
	probes, siteHost := seen()
	if probes == 0 {
		t.Fatal("no probe reached the listener through the proxy")
	}
	if !siteHost {
		t.Fatal("the proxy never forwarded the site hostname as Host")
	}

	// The same site with the proxy stopped: the published hostname no longer
	// answers, so the run falls back and says so in its first evidence row.
	stop()
	run, err = Execute(context.Background(), deps, rec, TriggerManual, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if run.Path != PathLocal {
		t.Fatalf("path = %q, want %q once the proxy is stopped", run.Path, PathLocal)
	}
	evidence, err = st.ListScanEvidence(run.ID)
	if err != nil || len(evidence) == 0 {
		t.Fatalf("evidence = %d rows, %v; want the endpoint row", len(evidence), err)
	}
	row := evidence[0]
	if row.Stage != StagePreflight || row.Class != "endpoint" || row.Method != configMethod {
		t.Fatalf("first row = %+v, want the preflight endpoint row", row)
	}
	for _, want := range []string{listenerURL + " (Host: app.example.com)", edgeURL, "did not answer"} {
		if !strings.Contains(row.Note, want) {
			t.Fatalf("endpoint note = %q; want it to contain %q", row.Note, want)
		}
	}
}

// A proxy in front of the listener that adds CF-Ray is the thing the edge path
// claims to test, so the same site must record `edge` while that proxy answers
// and `local` with the endpoint row once it stops.
func TestExecuteRecordsTheEdgePathAndTheFallbackWhenTheProxyStops(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var mu sync.Mutex
	var hosts, paths []string
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer listener.Close()

	// The throwaway proxy: it answers for the site's hostname, adds the header
	// Cloudflare's edge adds, and forwards each request to the listener.
	target, err := url.Parse(listener.URL)
	if err != nil {
		t.Fatal(err)
	}
	edgeHandler := httputil.NewSingleHostReverseProxy(target)
	edgeHandler.ModifyResponse = func(res *http.Response) error {
		res.Header.Set("CF-Ray", "8a1b2c3d4e5f6a7b-AMS")
		return nil
	}
	edge := httptest.NewServer(edgeHandler)
	defer edge.Close()

	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: listener.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}
	deps := ExecuteDeps{
		Store:       st,
		OSV:         fakeAdvisories{},
		WANBase:     func(string) string { return edge.URL },
		WANFallback: func(string) string { return listener.URL },
	}
	seen := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		probes, siteHost := 0, false
		for i, p := range paths {
			if strings.HasPrefix(p, ProbePathPrefix) {
				probes++
			}
			if strings.EqualFold(hosts[i], "app.example.com") {
				siteHost = true
			}
		}
		return probes, siteHost
	}
	assertEdgeThenFallback(t, st, *proxy, deps, edge.URL, listener.URL, edge.Close, seen)
}

// tlsEdgeCert mints a CA and one certificate for the site hostname, the pair
// the demo edge used. The scan is given the CA through WANRoots, so it must
// verify both the proxy's certificate and the listener's.
func tlsEdgeCert(t *testing.T, host string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scan test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
}

// The TLS variant covers the certificate shape an edge actually presents: the
// scan trusts a locally generated CA, so it verifies the proxy's certificate
// for the site hostname and records `edge`, then falls back to the listener's
// certificate from the same CA once the proxy stops.
func TestExecuteRecordsTheEdgePathOverTLSAndTheFallbackWhenTheProxyStops(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	roots, cert := tlsEdgeCert(t, "app.example.com")
	var mu sync.Mutex
	var hosts, paths []string
	record := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}
	// The node's WAN listener, presenting a certificate from the test CA.
	listener := httptest.NewUnstartedServer(http.HandlerFunc(record))
	listener.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	listener.StartTLS()
	defer listener.Close()

	// The application behind the node, so the upstream half has an answer.
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer app.Close()

	// The throwaway edge: TLS for the site hostname, Cloudflare's header on
	// every answer, and a TLS forward to the listener that trusts the same CA.
	target, err := url.Parse(listener.URL)
	if err != nil {
		t.Fatal(err)
	}
	edgeHandler := httputil.NewSingleHostReverseProxy(target)
	edgeHandler.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "app.example.com",
	}}
	edgeHandler.ModifyResponse = func(res *http.Response) error {
		res.Header.Set("CF-Ray", "8a1b2c3d4e5f6a7b-AMS")
		return nil
	}
	edge := httptest.NewUnstartedServer(edgeHandler)
	edge.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	edge.StartTLS()
	defer edge.Close()

	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: app.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}
	deps := ExecuteDeps{
		Store:       st,
		OSV:         fakeAdvisories{},
		WANBase:     func(string) string { return edge.URL },
		WANFallback: func(string) string { return listener.URL },
		WANRoots:    roots,
	}
	seen := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		probes, siteHost := 0, false
		for i, p := range paths {
			if strings.HasPrefix(p, ProbePathPrefix) {
				probes++
			}
			if strings.EqualFold(hosts[i], "app.example.com") {
				siteHost = true
			}
		}
		return probes, siteHost
	}
	assertEdgeThenFallback(t, st, *proxy, deps, edge.URL, listener.URL, edge.Close, seen)
}

// The shared run path records the run, its evidence and its verdict counts, and
// the endpoints it uses come from the proxy record, not the request.
func TestExecuteRecordsARun(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{
		{ProxyID: id, URL: upstream.URL, Weight: 1, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := st.GetProxy(id)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	run, err := Execute(ctx, ExecuteDeps{
		Store:   st,
		OSV:     fakeAdvisories{},
		WANBase: func(string) string { return upstream.URL },
	}, *proxy, TriggerManual, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == 0 || run.EndedAt == nil {
		t.Fatalf("run = %+v, want a finished run", run)
	}
	if run.Path != PathLocal {
		t.Fatalf("path = %q, want local for a listener without CF-Ray", run.Path)
	}
	// The path is proved after the row exists, so finish must persist it, and
	// the end time must be the end rather than the start.
	runs, err := st.ListScanRuns(5)
	if err != nil || len(runs) != 1 {
		t.Fatalf("stored runs = %+v, %v", runs, err)
	}
	if runs[0].Path != PathLocal {
		t.Fatalf("stored path = %q, want it saved at finish", runs[0].Path)
	}
	if runs[0].EndedAt == nil || runs[0].EndedAt.Before(runs[0].StartedAt) {
		t.Fatalf("started %v ended %v, want the end not before the start", runs[0].StartedAt, runs[0].EndedAt)
	}
	if run.Verdicts == "" {
		t.Fatal("the run recorded no verdict counts")
	}
	evidence, err := st.ListScanEvidence(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) < 10 {
		t.Fatalf("evidence rows = %d, want the catalogue, gate and backend stages", len(evidence))
	}
	for i, row := range evidence {
		if row.Seq != i {
			t.Fatalf("evidence seq %d = %d, want a unique sequence", i, row.Seq)
		}
	}
}
