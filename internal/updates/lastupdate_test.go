package updates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLastAppUpdate(t *testing.T) {
	cases := []struct {
		name string
		line string
		want *LastAppUpdate
	}{
		{
			name: "success",
			line: "ok|2026-11-22T10:00:00Z|installed 1.15.0 from abc1234\n",
			want: &LastAppUpdate{Status: "ok", At: "2026-11-22T10:00:00Z", Message: "installed 1.15.0 from abc1234"},
		},
		{
			name: "rollback keeps the guidance",
			line: "failed|2026-11-22T10:00:00Z|1.15.0 did not start; the previous version was restored. Run sudo /srv/src/deploy/install.sh",
			want: &LastAppUpdate{
				Status:  "failed",
				At:      "2026-11-22T10:00:00Z",
				Message: "1.15.0 did not start; the previous version was restored. Run sudo /srv/src/deploy/install.sh",
			},
		},
		{
			name: "pipes inside the message survive",
			line: "failed|2026-11-22T10:00:00Z|a|b",
			want: &LastAppUpdate{Status: "failed", At: "2026-11-22T10:00:00Z", Message: "a|b"},
		},
		{name: "garbage", line: "not a record\n", want: nil},
		{name: "empty status", line: "|2026-11-22T10:00:00Z|x\n", want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, lastAppUpdateFile), []byte(tc.line), 0o644); err != nil {
				t.Fatal(err)
			}
			got := readLastAppUpdate(dir)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			if got == nil || *got != *tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestReadLastAppUpdateMissingFile(t *testing.T) {
	if got := readLastAppUpdate(t.TempDir()); got != nil {
		t.Fatalf("got %+v, want nil for a host that never ran an update", got)
	}
}
