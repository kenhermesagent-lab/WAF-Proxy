package streaming

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Every preset must be usable as it ships: a valid group and protocol, a range
// that fits in a port number, and a note so the card explains itself.
func TestCatalogInvariants(t *testing.T) {
	seen := map[string]bool{}
	for _, def := range Catalog {
		if def.ID == "" || seen[def.ID] {
			t.Errorf("catalog id %q is empty or duplicated", def.ID)
		}
		seen[def.ID] = true
		switch def.Group {
		case GroupMedia, GroupGame, GroupCustom:
		default:
			t.Errorf("%s: group %q is not media, game or custom", def.ID, def.Group)
		}
		switch def.Protocol {
		case "tcp", "udp", "both":
		default:
			t.Errorf("%s: protocol %q is not tcp, udp or both", def.ID, def.Protocol)
		}
		if def.PortCount < 1 || def.PortCount > maxPortCount {
			t.Errorf("%s: port count %d is outside 1-%d", def.ID, def.PortCount, maxPortCount)
		}
		if def.Label == "" || def.Notes == "" {
			t.Errorf("%s: label or notes missing", def.ID)
		}
		if def.Group == GroupCustom {
			continue // the custom card has no fixed port
		}
		if def.DefaultPort < 1 || def.DefaultPort+def.PortCount-1 > 65535 {
			t.Errorf("%s: port range %d + %d does not fit in 1-65535", def.ID, def.DefaultPort, def.PortCount)
		}
		// The seed must survive its own validation, so a freshly enabled card
		// does not open with an error the operator has to fix.
		_, err := Config{
			Protocol: def.Protocol, Port: def.DefaultPort, PortCount: def.PortCount,
			Upstream: fmt.Sprintf("10.0.0.10:%d", def.DefaultPort),
		}.Normalize(def)
		if err != nil {
			t.Errorf("%s: its own preset does not normalize: %v", def.ID, err)
		}
	}
}

// presetPorts renders a preset's range the way the install guide's table does.
func presetPorts(def Service) string {
	if def.PortCount <= 1 {
		return strconv.Itoa(def.DefaultPort)
	}
	return fmt.Sprintf("%d-%d", def.DefaultPort, def.DefaultPort+def.PortCount-1)
}

// The install guide repeats the game presets, so a change here has to be made
// there too. This reads the Markdown table and compares the id, protocol and
// ports, which is what the operator copies.
func TestGamePresetsMatchTheDocsTable(t *testing.T) {
	const doc = "../../docs/install/04-crowdsec-and-streaming.md"
	raw, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("read %s: %v", doc, err)
	}

	type row struct{ protocol, ports string }
	rows := map[string]row{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 6 {
			continue
		}
		idCell := strings.TrimSpace(cells[2])
		if !strings.HasPrefix(idCell, "`") {
			continue // header and separator rows
		}
		rows[strings.Trim(idCell, "`")] = row{
			protocol: strings.TrimSpace(cells[3]),
			ports:    strings.TrimSpace(cells[4]),
		}
	}

	presets := 0
	for _, def := range Catalog {
		if def.Group != GroupGame {
			continue
		}
		presets++
		got, ok := rows[def.ID]
		if !ok {
			t.Errorf("preset %s is missing from the table in %s", def.ID, doc)
			continue
		}
		if want := def.Protocol; got.protocol != want {
			t.Errorf("%s: the table says %q, the catalog says %q", def.ID, got.protocol, want)
		}
		if want := presetPorts(def); got.ports != want {
			t.Errorf("%s: the table says %q, the catalog says %q", def.ID, got.ports, want)
		}
	}
	if len(rows) != presets {
		t.Errorf("the table in %s lists %d presets, the catalog has %d", doc, len(rows), presets)
	}
}
