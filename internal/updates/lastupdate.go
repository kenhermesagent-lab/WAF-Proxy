package updates

import (
	"os"
	"path/filepath"
	"strings"
)

// LastAppUpdate is the outcome of the last application update. The root updater
// writes it into the data directory because every update ends with a restart:
// the console reporting the result is a new process, and after a rollback it is
// the previous build, so the message cannot live in memory.
type LastAppUpdate struct {
	Status  string `json:"status"`
	At      string `json:"at,omitempty"`
	Message string `json:"message,omitempty"`
}

const lastAppUpdateFile = "last-app-update"

// readLastAppUpdate parses the line the updater leaves behind: status|time|message.
func readLastAppUpdate(dataDir string) *LastAppUpdate {
	data, err := os.ReadFile(filepath.Join(dataDir, lastAppUpdateFile))
	if err != nil {
		return nil
	}
	line, _, _ := strings.Cut(string(data), "\n")
	parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
	if len(parts) < 2 || parts[0] == "" {
		return nil
	}
	out := &LastAppUpdate{Status: parts[0], At: parts[1]}
	if len(parts) == 3 {
		out.Message = parts[2]
	}
	return out
}
