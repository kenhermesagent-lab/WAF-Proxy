package store

import (
	"fmt"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A detector firing against a dead agent must not grow the table without
// bound: the oldest pending payloads are dropped and the drop is reported.
func TestEnqueueDeliveryCapsPendingQueue(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	link := &model.AgentLink{Name: "collector", Endpoint: "http://10.0.0.5:9000/hook", Enabled: true}
	id, err := st.CreateAgentLink(link)
	if err != nil {
		t.Fatal(err)
	}

	total := 0
	for i := 0; i < MaxPendingPerLink+5; i++ {
		_, dropped, err := st.EnqueueDelivery(id, 0, "anomaly", fmt.Sprintf(`{"n":%d}`, i))
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		total += dropped
	}
	if total != 5 {
		t.Fatalf("dropped %d payloads, want 5", total)
	}
	var pending int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM agent_deliveries WHERE state = 'pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != MaxPendingPerLink {
		t.Fatalf("pending rows = %d, want %d", pending, MaxPendingPerLink)
	}
	// The newest payload survives; the oldest ones are the ones that went.
	var newest string
	if err := st.db.QueryRow(`SELECT body FROM agent_deliveries ORDER BY id DESC LIMIT 1`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf(`{"n":%d}`, MaxPendingPerLink+4); newest != want {
		t.Fatalf("newest payload = %q, want %q", newest, want)
	}
}
