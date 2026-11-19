//go:build linux

package ban

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// Kernel mirrors bans into an nftables set so blocked packets are dropped in the
// kernel without reaching the proxy. It degrades to a no-op when nft is missing
// or the container lacks NET_ADMIN.
type Kernel struct {
	mu        sync.Mutex
	log       *slog.Logger
	bin       string
	available bool
	reason    string
	lastErr   string
	stealth   bool
	wanIface  string
	records   []Record
}

// NewKernel probes nftables support.
func NewKernel(log *slog.Logger) *Kernel {
	k := &Kernel{log: log}
	path, err := exec.LookPath("nft")
	if err != nil {
		k.reason = "nft binary not found"
		return k
	}
	k.bin = path
	if out, err := exec.Command(path, "list", "tables").CombinedOutput(); err != nil {
		k.reason = "nftables unavailable: " + firstLine(string(out), err.Error())
		return k
	}
	k.available = true
	return k
}

func firstLine(out, fallback string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return fallback
	}
	if i := strings.IndexByte(out, '\n'); i > 0 {
		out = out[:i]
	}
	if len(out) > 160 {
		out = out[:160]
	}
	return out
}

// Status reports whether kernel enforcement is active.
func (k *Kernel) Status() (bool, string) {
	if k == nil {
		return false, "disabled"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.available {
		if k.lastErr != "" {
			return false, k.lastErr
		}
		return true, "nftables"
	}
	return false, k.reason
}

// Sync replaces the whole kernel set with the given records.
func (k *Kernel) Sync(records []Record) error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.records = append([]Record(nil), records...)
	return k.rebuildLocked()
}

// SetStealth toggles ICMP echo dropping on the WAN interface.
func (k *Kernel) SetStealth(ignorePing bool, wanIface string) error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stealth = ignorePing
	k.wanIface = wanIface
	return k.rebuildLocked()
}

func (k *Kernel) rebuildLocked() error {
	if !k.available {
		return fmt.Errorf("%s", k.reason)
	}
	script := k.buildScript()
	cmd := exec.Command(k.bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		k.lastErr = "nft apply: " + firstLine(stderr.String(), err.Error())
		return fmt.Errorf("%s", k.lastErr)
	}
	k.lastErr = ""
	return nil
}

func (k *Kernel) buildScript() string {
	var b strings.Builder
	b.WriteString("add table inet wafproxy\n")
	b.WriteString("flush table inet wafproxy\n")
	b.WriteString("table inet wafproxy {\n")
	// auto-merge is required: threat feeds contain overlapping prefixes and an
	// interval set without it rejects the second overlapping element.
	b.WriteString("  set block4 { type ipv4_addr; flags interval; auto-merge; }\n")
	b.WriteString("  set block6 { type ipv6_addr; flags interval; auto-merge; }\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook prerouting priority -300; policy accept;\n")
	b.WriteString("    ip saddr @block4 drop\n")
	b.WriteString("    ip6 saddr @block6 drop\n")
	if k.stealth {
		if k.wanIface != "" {
			fmt.Fprintf(&b, "    iifname %q icmp type echo-request drop\n", k.wanIface)
			fmt.Fprintf(&b, "    iifname %q icmpv6 type echo-request drop\n", k.wanIface)
		} else {
			k.log.Warn("stealth ping drop skipped: WAN interface not configured")
		}
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	for _, r := range k.records {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			if a, aerr := netip.ParseAddr(r.CIDR); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		if p.Addr().Is4() {
			fmt.Fprintf(&b, "add element inet wafproxy block4 { %s }\n", p.String())
		} else {
			fmt.Fprintf(&b, "add element inet wafproxy block6 { %s }\n", p.String())
		}
	}
	return b.String()
}

// Add inserts one prefix into the kernel set incrementally.
func (k *Kernel) Add(cidr string) error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.available {
		return fmt.Errorf("%s", k.reason)
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		a, aerr := netip.ParseAddr(cidr)
		if aerr != nil {
			return aerr
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	set := "block4"
	if p.Addr().Is6() {
		set = "block6"
	}
	cmd := exec.Command(k.bin, "add", "element", "inet", "wafproxy", set, "{", p.String(), "}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft add: %s", firstLine(stderr.String(), err.Error()))
	}
	// Keep the in-memory snapshot in step so a later rebuild (for example when
	// stealth settings change) does not drop incrementally added bans.
	found := false
	for _, r := range k.records {
		if r.CIDR == p.String() {
			found = true
			break
		}
	}
	if !found {
		k.records = append(k.records, Record{CIDR: p.String(), Permanent: true})
	}
	return nil
}

// Remove deletes one prefix from the kernel set.
func (k *Kernel) Remove(cidr string) error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.available {
		return nil
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		a, aerr := netip.ParseAddr(cidr)
		if aerr != nil {
			return aerr
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	set := "block4"
	if p.Addr().Is6() {
		set = "block6"
	}
	cmd := exec.Command(k.bin, "delete", "element", "inet", "wafproxy", set, "{", p.String(), "}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft delete: %s", firstLine(stderr.String(), err.Error()))
	}
	kept := k.records[:0]
	for _, r := range k.records {
		if r.CIDR != p.String() {
			kept = append(kept, r)
		}
	}
	k.records = kept
	return nil
}
