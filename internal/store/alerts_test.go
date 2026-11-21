package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// The Notifications page reads recent deliveries from /api/notifications and
// expects lowercase JSON keys. Untagged struct fields serialise as "Channel"
// and "CreatedAt", which left every cell in the table blank.
func TestRecentAlertsSerializeWithLowercaseKeys(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.EnqueueAlert("telegram", "ban", "dedupe-1", "203.0.113.9 banned"); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkAlert(1, "sent", 1); err != nil {
		t.Fatal(err)
	}
	alerts, err := st.RecentAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	body, err := json.Marshal(alerts[0])
	if err != nil {
		t.Fatal(err)
	}
	raw := string(body)
	for _, key := range []string{`"id":`, `"channel":`, `"kind":`, `"payload":`, `"state":`, `"created_at":`} {
		if !strings.Contains(raw, key) {
			t.Errorf("serialized alert %s is missing %s", raw, key)
		}
	}
	if strings.Contains(raw, `"CreatedAt"`) || strings.Contains(raw, `"Channel"`) {
		t.Errorf("serialized alert still uses Go field names: %s", raw)
	}
}
