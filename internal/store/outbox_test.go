package store

import (
	"testing"
	"time"
)

func captureStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	st.SetNodeID("node-a")
	return st
}

func outboxCount(t *testing.T, st *Store) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM ha_outbox`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOutboxCapturesSessionLifecycle(t *testing.T) {
	st := captureStore(t)
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("cookie-token", userID, "csrf", "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, err := st.OutboxEntries(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("outbox after login = %d entries, want 1", len(entries))
	}
	if entries[0].Kind != "sessions" || entries[0].Op != "upsert" || entries[0].Origin != "node-a" {
		t.Fatalf("outbox entry = %+v", entries[0])
	}
	if entries[0].OriginSeq != entries[0].Seq {
		t.Fatalf("origin seq %d != stream seq %d", entries[0].OriginSeq, entries[0].Seq)
	}
	// An idle-expiry touch is deliberately not replicated: it fires on every
	// request and the standby's row has the same idle window.
	if err := st.TouchSession("cookie-token", time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := outboxCount(t, st); n != 1 {
		t.Fatalf("a touch wrote %d outbox rows", n-1)
	}
	if err := st.DeleteSession("cookie-token"); err != nil {
		t.Fatal(err)
	}
	entries, err = st.OutboxEntries(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].Op != "delete" {
		t.Fatalf("outbox after logout = %+v", entries)
	}
}

func TestOutboxCommitsWithTheChange(t *testing.T) {
	st := captureStore(t)
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	key := st.sessionID("rolled-back")
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions(id, user_id, csrf, created_at, expires_at) VALUES(?, ?, '', ?, ?)`,
		key, userID, stamp(time.Now()), stamp(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := st.captureRow(tx, "sessions", []string{"id"}, []any{key}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n := outboxCount(t, st); n != 0 {
		t.Fatalf("a rolled-back change left %d outbox rows", n)
	}

	tx, err = st.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions(id, user_id, csrf, created_at, expires_at) VALUES(?, ?, '', ?, ?)`,
		key, userID, stamp(time.Now()), stamp(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := st.captureRow(tx, "sessions", []string{"id"}, []any{key}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := outboxCount(t, st); n != 1 {
		t.Fatalf("a committed change left %d outbox rows", n)
	}
}

func TestOutboxApplyIsOrderedAndIdempotent(t *testing.T) {
	src := captureStore(t)
	userID, err := src.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.CreateSession("keep-me", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := src.CreateSession("drop-me", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := src.DeleteSession("drop-me"); err != nil {
		t.Fatal(err)
	}
	entries, err := src.OutboxEntries(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("source outbox = %d entries, want 3", len(entries))
	}

	dst := captureStore(t)
	dst.SetNodeID("")
	if _, err := dst.CreateUser("admin", "hash", "", "", false); err != nil {
		t.Fatal(err)
	}
	dst.SetSessionKey(src.sessionKey)
	res, err := dst.ApplyOutbox(entries)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 3 || res.LastSeq != entries[2].Seq {
		t.Fatalf("apply result = %+v", res)
	}
	if _, err := dst.LookupSession("keep-me"); err != nil {
		t.Fatalf("applied session is missing: %v", err)
	}
	if _, err := dst.LookupSession("drop-me"); err == nil {
		t.Fatal("a deleted session was resurrected")
	}
	// A redelivery of the same page must change nothing.
	again, err := dst.ApplyOutbox(entries)
	if err != nil {
		t.Fatal(err)
	}
	if again.Applied != 0 {
		t.Fatalf("a redelivered page applied %d changes", again.Applied)
	}
}

func TestOutboxRefusesConfigurationTables(t *testing.T) {
	st := captureStore(t)
	entry := OutboxEntry{
		Seq: 1, Origin: "node-b", OriginSeq: 1, Kind: "proxies", Op: "upsert",
		Payload: []byte(`{"columns":["id"],"row":[{"k":"int","i":1}],"key":["id"]}`),
	}
	if _, err := st.ApplyOutbox([]OutboxEntry{entry}); err == nil {
		t.Fatal("the outbox applied a configuration table")
	}
}

func TestOutboxStatsAckAndPrune(t *testing.T) {
	st := captureStore(t)
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := st.CreateSession(string(rune('a'+i)), userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := st.OutboxStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Depth != 3 || stats.Pending["sessions"] != 3 || stats.Oldest == "" {
		t.Fatalf("stats = %+v", stats)
	}
	if err := st.AckPeer("peer-fingerprint", 2); err != nil {
		t.Fatal(err)
	}
	seq, at, err := st.PeerAck("peer-fingerprint")
	if err != nil || seq != 2 || at.IsZero() {
		t.Fatalf("ack = %d, %v, %v", seq, at, err)
	}
	if err := st.PruneOutbox(2); err != nil {
		t.Fatal(err)
	}
	stats, err = st.OutboxStats()
	if err != nil || stats.Depth != 1 || stats.MinSeq != 3 {
		t.Fatalf("after prune = %+v, %v", stats, err)
	}
}

func TestOutboxOverflowIsBoundedBySize(t *testing.T) {
	st := captureStore(t)
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("one", userID, "", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stats, err := st.OutboxStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Bytes == 0 || stats.Bytes > MaxOutboxBytes {
		t.Fatalf("a single change is %d bytes; the 100 MiB ceiling cannot be tested by size", stats.Bytes)
	}
}

func TestAuditCanBeDisabledForStandby(t *testing.T) {
	st := captureStore(t)
	st.SetAuditEnabled(false)
	st.AddAudit("admin", "test", "detail", "127.0.0.1")
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a standby wrote %d local audit rows", n)
	}
	st.SetAuditEnabled(true)
	st.AddAudit("admin", "test", "detail", "127.0.0.1")
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the active wrote %d audit rows, want 1", n)
	}
	if _, problem, err := st.VerifyAuditChain(); err != nil || problem != "" {
		t.Fatalf("audit chain = %q, %v", problem, err)
	}
}

func TestSchema25KeepsSessions(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	userID, err := st.CreateUser("admin", "hash", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession("existing", userID, "csrf", "", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Pretend the row was written by the previous schema level, then reopen.
	if _, err := st.db.Exec(`UPDATE schema_meta SET value = '24' WHERE key = 'version'`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	if _, err := reopened.LookupSession("existing"); err != nil {
		t.Fatalf("schema 24 to 25 signed a session out: %v", err)
	}
}
