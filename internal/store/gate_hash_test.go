package store

import (
	"bytes"
	"testing"
	"time"
)

func TestGateSessionTokenIsHashed(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSessionKey(bytes.Repeat([]byte{9}, 32))

	const token = "visitor-token-value"
	if err := st.CreateGateSession(token, 0, "alice", "203.0.113.9", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := st.db.QueryRow(`SELECT id FROM gate_sessions LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id == token || bytes.Contains([]byte(id), []byte(token)) {
		t.Fatalf("gate session stored the raw token: %q", id)
	}
	if user, ok := st.LookupGateSession(token, 0); !ok || user != "alice" {
		t.Fatalf("LookupGateSession = %q, %v; want alice, true", user, ok)
	}
	if _, ok := st.LookupGateSession("wrong-token", 0); ok {
		t.Fatal("a different token resolved a session")
	}
	if err := st.DeleteGateSession(token); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.LookupGateSession(token, 0); ok {
		t.Fatal("session survived DeleteGateSession")
	}
}

func TestGateAndAdminDigestsDiffer(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSessionKey(bytes.Repeat([]byte{3}, 32))
	if st.sessionID("same") == st.gateID("same") {
		t.Fatal("admin and gate digests collide for the same token")
	}
}
