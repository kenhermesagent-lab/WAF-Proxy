package updates

import (
	"os"
	"strconv"
	"strings"
)

// DefaultProgressFile is where the fixed self-update script writes its stage.
// It sits beside the helper socket because the helper runs on the host, which
// is the only place the file exists when the console runs in a container.
const DefaultProgressFile = "/run/wafproxy-updates/progress"

// ProgressFile returns the configured progress path.
func ProgressFile() string {
	if v := strings.TrimSpace(osGetenv("WAFPROXY_UPDATE_PROGRESS")); v != "" {
		return v
	}
	return DefaultProgressFile
}

// ReadAppProgress parses the line the updater wrote, "<percent>|<stage>". A
// missing or malformed file reads as zero, which is what the first poll of a
// run looks like before the script has reached its first stage.
func ReadAppProgress() (int, string) {
	raw, err := os.ReadFile(ProgressFile())
	if err != nil {
		return 0, ""
	}
	percent, stage, ok := parseProgress(string(raw))
	if !ok {
		return 0, ""
	}
	return percent, stage
}

// ClearAppProgress forgets a finished run, so the first poll of the next one
// cannot show the previous run's 100%.
func ClearAppProgress() { _ = os.Remove(ProgressFile()) }

func parseProgress(text string) (int, string, bool) {
	rawPercent, stage, found := strings.Cut(strings.TrimSpace(text), "|")
	if !found {
		return 0, "", false
	}
	percent, err := strconv.Atoi(strings.TrimSpace(rawPercent))
	if err != nil || percent < 0 || percent > 100 {
		return 0, "", false
	}
	return percent, strings.TrimSpace(stage), true
}
