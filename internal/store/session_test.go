package store

import (
	"strings"
	"testing"
	"time"
)

// A database copy must not be a credential. The table keeps a digest of the
// cookie, never the cookie itself.
func TestSessionCookieIsNotStored(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSessionKey([]byte(strings.Repeat("k", 32)))

	uid, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	const token = "cookie-value-that-must-not-be-in-the-file"
	if err := st.CreateSession(token, uid, "csrf", "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := st.db.QueryRow(`SELECT id FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || strings.Contains(stored, token) {
		t.Fatalf("the cookie value is stored in the clear: %q", stored)
	}
	if len(stored) != 64 {
		t.Fatalf("stored session id = %q, want a 64-character digest", stored)
	}

	// The token the browser holds still resolves, and callers get it back.
	sess, err := st.LookupSession(token)
	if err != nil {
		t.Fatalf("lookup with the cookie failed: %v", err)
	}
	if sess.ID != token || sess.UserID != uid {
		t.Fatalf("session = %+v, want token %q for user %d", sess, token, uid)
	}
	if err := st.TouchSession(token, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSession(token); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LookupSession(token); err == nil {
		t.Fatal("a deleted session still resolves")
	}
}

// "Sign out everywhere else" has to compare digests, or it either keeps the
// current browser out or deletes every session including the caller's.
func TestDeleteOtherSessionsKeepsCurrent(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	uid, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"keep-me", "drop-me"} {
		if err := st.CreateSession(tok, uid, "csrf", "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteOtherSessions(uid, "keep-me"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LookupSession("keep-me"); err != nil {
		t.Fatalf("the current session was deleted: %v", err)
	}
	if _, err := st.LookupSession("drop-me"); err == nil {
		t.Fatal("the other session survived")
	}
}

// The signed-in list has to show who is online without handing out a session
// identifier, mark the caller's own row, and leave expired sessions out.
func TestActiveAdminSessionsMarksCaller(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetSessionKey([]byte(strings.Repeat("k", 32)))
	adminID, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	viewerID, err := st.CreateUser("viewer", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		token   string
		userID  int64
		ip      string
		expires time.Time
	}{
		{"caller", adminID, "10.0.0.10", time.Now().Add(2 * time.Hour)},
		{"other", viewerID, "10.0.0.11", time.Now().Add(time.Hour)},
		{"gone", adminID, "10.0.0.12", time.Now().Add(-time.Minute)},
	} {
		if err := st.CreateSession(s.token, s.userID, "csrf", s.ip, "test", s.expires); err != nil {
			t.Fatal(err)
		}
	}

	list, err := st.ActiveAdminSessions("caller")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("active sessions = %d, want 2: %+v", len(list), list)
	}
	if !list[0].Current || list[0].Username != "admin" || list[0].IP != "10.0.0.10" {
		t.Fatalf("first row = %+v, want the caller's admin session", list[0])
	}
	if list[1].Current || list[1].Username != "viewer" || list[1].IP != "10.0.0.11" {
		t.Fatalf("second row = %+v, want the viewer's session", list[1])
	}
	if list[0].Role == "" {
		t.Fatal("the session list did not resolve the role")
	}
}

// Sessions written before schema 13 held the cookie as the key; they cannot be
// converted, so the upgrade clears them instead of leaving dead rows.
func TestUpgradeDropsLegacySessions(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateFirstUser("admin", "hash", "secret", "codes", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO sessions(id, user_id, csrf, created_at, expires_at)
		VALUES('legacy-cookie', ?, 'csrf', ?, ?)`, uid, stamp(time.Now()), stamp(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_meta SET value = '12' WHERE key = 'version'`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	var n int
	if err := again.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d legacy sessions survived the upgrade", n)
	}
}
