package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestBackupScheduleHidesPassphrase(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	const pass = "a-16-character-passphrase"
	body := `{"enabled":false,"transport":"local","local_dir":"/tmp/wafproxy-backups","keep":7,` +
		`"schedule":"daily","time":"03:00","encrypt":true,"passphrase":"` + pass + `"}`

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/backup/schedule", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), pass) {
		t.Fatal("the save response echoed the passphrase")
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/backup/schedule", "")
	var got struct {
		Config struct {
			Encrypt       bool   `json:"encrypt"`
			HasPassphrase bool   `json:"has_passphrase"`
			Passphrase    string `json:"passphrase"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Config.Encrypt || !got.Config.HasPassphrase || got.Config.Passphrase != "" {
		t.Fatalf("backup config = %+v", got.Config)
	}
}
