package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/anomaly"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

type nopNotifier struct{}

func (nopNotifier) Enqueue(string, string, string, bool) {}

func TestAnomalySettingsAndEvents(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.SetAnomaly(anomaly.New(st, metrics.New("", ""), nopNotifier{}, slog.New(slog.NewTextHandler(io.Discard, nil))))

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/anomaly/settings", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := put(`{"enabled":true,"egress_mb":0,"egress_factor":4,"rate_rps":200,"rate_factor":3,"auth_burst":20}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid threshold was accepted: %d %s", rec.Code, rec.Body)
	}
	rec := put(`{"enabled":true,"egress_mb":8,"egress_factor":5,"rate_rps":150,"rate_factor":2.5,"auth_burst":25}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/anomaly", nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	grec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("read failed: %d", grec.Code)
	}
	var out struct {
		Events []any `json:"events"`
		Config struct {
			EgressMB int `json:"egress_mb"`
		} `json:"config"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Config.EgressMB != 8 || len(out.Events) != 0 {
		t.Fatalf("unexpected read: %s", grec.Body)
	}
}

// The slide-over lists a site's upstreams and the sources its whitelists allow,
// and muting either kind stops its outbound spikes while acknowledging what it
// raised.
func TestAnomalyDestinationAndMute(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.SetAnomaly(anomaly.New(st, metrics.New("", ""), nopNotifier{}, slog.New(slog.NewTextHandler(io.Discard, nil))))
	proxyID, err := st.CreateProxy(&model.Proxy{Hostname: "files.example.com", Enabled: true, GateMode: "off"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(proxyID, []model.Upstream{{ProxyID: proxyID, URL: "http://10.1.2.3:8080", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePolicy(&model.Policy{Scope: "global", Kind: model.PolicyIPWhitelist, Value: "10.0.0.0/8", Action: "allow", Enabled: true, Note: "lan"}); err != nil {
		t.Fatal(err)
	}
	eventID, err := st.CreateAnomalyEvent(&model.AnomalyEvent{Kind: "egress_spike", ProxyID: proxyID, ProxyHost: "files.example.com", Detail: "12.0 MB out in one minute", Value: 12 << 20})
	if err != nil {
		t.Fatal(err)
	}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := call(http.MethodGet, "/api/anomaly/events/"+strconv.FormatInt(eventID, 10), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d %s", rec.Code, rec.Body)
	}
	var detail struct {
		Destinations []struct {
			Address string `json:"address"`
			Muted   bool   `json:"muted"`
		} `json:"destinations"`
		Sources []struct {
			Address string `json:"address"`
			Label   string `json:"label"`
			Muted   bool   `json:"muted"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Destinations) != 1 || detail.Destinations[0].Address != "10.1.2.3" {
		t.Fatalf("destinations = %s", rec.Body)
	}
	if len(detail.Sources) != 1 || detail.Sources[0].Address != "10.0.0.0/8" || detail.Sources[0].Label != "lan" {
		t.Fatalf("sources = %s", rec.Body)
	}

	if rec := call(http.MethodPost, "/api/anomaly/events/"+strconv.FormatInt(eventID, 10)+"/mute", `{"address":"10.1.2.3"}`); rec.Code != http.StatusOK {
		t.Fatalf("mute = %d %s", rec.Code, rec.Body)
	}
	ev, err := st.GetAnomalyEvent(eventID)
	if err != nil || ev.State != "acknowledged" {
		t.Fatalf("event after mute = %+v, err = %v", ev, err)
	}
	rec = call(http.MethodGet, "/api/anomaly/events/"+strconv.FormatInt(eventID, 10), "")
	if !strings.Contains(rec.Body.String(), `"muted":true`) {
		t.Fatalf("muted flag missing: %s", rec.Body)
	}

	rec = call(http.MethodDelete, "/api/anomaly/mutes?proxy_id="+strconv.FormatInt(proxyID, 10)+"&address=10.1.2.3", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"address"`) {
		t.Fatalf("unmute = %d %s", rec.Code, rec.Body)
	}

	// A whitelisted source can be muted instead of the backend it uploads to.
	path := "/api/anomaly/events/" + strconv.FormatInt(eventID, 10) + "/mute"
	if rec := call(http.MethodPost, path, `{"kind":"source","address":"198.51.100.9"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an address off the whitelist was muted: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodPost, path, `{"kind":"nonsense","address":"10.0.0.0/8"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown mute kind was accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodPost, path, `{"kind":"source","address":"10.0.0.0/8"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kind":"source"`) {
		t.Fatalf("source mute = %d %s", rec.Code, rec.Body)
	}
	rec = call(http.MethodGet, "/api/anomaly/events/"+strconv.FormatInt(eventID, 10), "")
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if !detail.Sources[0].Muted {
		t.Fatalf("the source was not reported muted: %s", rec.Body)
	}
	if rec := call(http.MethodDelete, "/api/anomaly/mutes?proxy_id="+strconv.FormatInt(proxyID, 10)+"&kind=source&address=10.0.0.0/8", ""); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"address"`) {
		t.Fatalf("source unmute = %d %s", rec.Code, rec.Body)
	}
}
