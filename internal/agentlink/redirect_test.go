package agentlink

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The endpoint is checked when it is saved, so a redirect is the way around
// that check. A 3xx must be reported as a failed delivery, never followed.
func TestDeliveryDoesNotFollowRedirects(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/metadata", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	d, st, _ := newDispatcher(t)
	id, err := st.CreateAgentLink(&model.AgentLink{Name: "collector", Endpoint: redirector.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	link, err := st.GetAgentLink(id)
	if err != nil {
		t.Fatal(err)
	}
	err = d.SendTest(context.Background(), *link)
	if err == nil {
		t.Fatal("a redirecting agent was treated as a successful delivery")
	}
	if reached.Load() != 0 {
		t.Fatalf("the redirect target was contacted %d times", reached.Load())
	}
	// The failure is recorded so the console shows it rather than retrying blind.
	del, err := st.DeliveriesForLink(id, 1)
	if err != nil || len(del) == 0 {
		t.Fatalf("delivery row missing: %v", err)
	}
	if del[0].LastStatus/100 != 3 {
		t.Fatalf("recorded status = %d, want the 3xx the agent returned", del[0].LastStatus)
	}
}
