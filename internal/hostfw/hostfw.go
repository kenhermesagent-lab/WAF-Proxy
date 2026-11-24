// Package hostfw opens a forwarder's listen range on the host firewall, which a
// native install needs: the listener binds the port, but firewalld or ufw still
// drops the packets. A container with host networking shares the host's rules,
// so the same call covers both installs when the tools are reachable.
//
// Everything here is best effort. A save must never fail because the host has no
// firewall, the binary lacks CAP_NET_ADMIN, or the tools moved; the report says
// what happened and the page shows it.
package hostfw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// specTimeout bounds one firewall command. A reload can take a moment on a big
// rule set, but a hung tool must not hold the save.
const specTimeout = 15 * time.Second

// Spec is one listen range on one protocol.
type Spec struct {
	Port     int
	Count    int
	Protocol string // tcp or udp
}

// ForConfig builds the specs a forwarder needs for its configuration.
func ForConfig(port, count int, protocol string) []Spec {
	if count < 1 {
		count = 1
	}
	switch protocol {
	case "udp":
		return []Spec{{Port: port, Count: count, Protocol: "udp"}}
	case "both":
		return []Spec{
			{Port: port, Count: count, Protocol: "tcp"},
			{Port: port, Count: count, Protocol: "udp"},
		}
	default:
		return []Spec{{Port: port, Count: count, Protocol: "tcp"}}
	}
}

func (s Spec) ports() string {
	if s.Count <= 1 {
		return strconv.Itoa(s.Port)
	}
	return fmt.Sprintf("%d-%d", s.Port, s.Port+s.Count-1)
}

// String is how a spec is stored and compared, e.g. 2456-2458/udp.
func (s Spec) String() string { return s.ports() + "/" + s.Protocol }

// firewalldArg is the --add-port form, which is the same as String.
func (s Spec) firewalldArg() string { return s.String() }

// ufwArg is ufw's range form, which uses a colon, e.g. 2456:2458/udp.
func (s Spec) ufwArg() string {
	if s.Count <= 1 {
		return s.String()
	}
	return fmt.Sprintf("%d:%d/%s", s.Port, s.Port+s.Count-1, s.Protocol)
}

// Parse reads a stored spec back, so a disabled or edited forwarder can close
// exactly what it opened.
func Parse(raw string) (Spec, error) {
	raw = strings.TrimSpace(raw)
	ports, protocol, ok := strings.Cut(raw, "/")
	if !ok || (protocol != "tcp" && protocol != "udp") {
		return Spec{}, fmt.Errorf("hostfw: %q is not a port/protocol spec", raw)
	}
	base, last, ok := strings.Cut(ports, "-")
	if !ok {
		last = base
	}
	first, err := strconv.Atoi(base)
	if err != nil || first < 1 || first > 65535 {
		return Spec{}, fmt.Errorf("hostfw: %q has no valid port", raw)
	}
	end, err := strconv.Atoi(last)
	if err != nil || end < first || end-first+1 > 16 {
		return Spec{}, fmt.Errorf("hostfw: %q has no valid port range", raw)
	}
	return Spec{Port: first, Count: end - first + 1, Protocol: protocol}, nil
}

// Report is what the console shows after a save: which ports this call changed
// and why nothing could be changed.
type Report struct {
	Opened []string `json:"opened,omitempty"`
	Closed []string `json:"closed,omitempty"`
	// Detail explains the outcome in one line the page can print.
	Detail string `json:"detail"`
	// Error names a command that failed; the save still succeeded.
	Error string `json:"error,omitempty"`
}

// Opener runs the host tools. run and readFile are fields so a test can drive
// both paths without a firewall.
type Opener struct {
	run      func(ctx context.Context, name string, args ...string) (string, error)
	readFile func(string) ([]byte, error)
}

// New returns an opener that runs the real tools.
func New() *Opener {
	return &Opener{
		run: func(ctx context.Context, name string, args ...string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, specTimeout)
			defer cancel()
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if msg := strings.TrimSpace(string(out)); err != nil && msg != "" {
				// Keep the tool's own words: "NOT_ENABLED: ..." says what to do,
				// "exit status 1" does not.
				return string(out), errors.New(msg)
			}
			return string(out), err
		},
		readFile: os.ReadFile,
	}
}

// backend detects which host firewall is running. An empty backend means there
// is nothing to open, which is normal in a container without the host's tools.
func (o *Opener) backend(ctx context.Context) string {
	// firewalld answers "running" exactly; "not running" must not match.
	if out, err := o.run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
		return "firewalld"
	}
	if out, err := o.run(ctx, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
		return "ufw"
	}
	return ""
}

// Sync makes the host's rules match want: it opens what is missing from have,
// closes what have holds and want does not, and returns what it changed. have
// is the spec list the previous save stored.
func (o *Opener) Sync(ctx context.Context, want []Spec, have []string) Report {
	rep := Report{Opened: []string{}, Closed: []string{}}
	backend := o.backend(ctx)
	if backend == "" {
		rep.Detail = o.unavailable()
		return rep
	}

	current := make(map[string]Spec, len(have))
	for _, raw := range have {
		if s, err := Parse(raw); err == nil {
			current[s.String()] = s
		}
	}
	target := make(map[string]Spec, len(want))
	for _, s := range want {
		target[s.String()] = s
	}

	for _, k := range sortedKeys(target) {
		if _, ok := current[k]; ok {
			continue
		}
		if err := o.add(ctx, backend, target[k]); err != nil {
			rep.Error = err.Error()
			break
		}
		rep.Opened = append(rep.Opened, k)
	}

	if rep.Error == "" {
		for _, k := range sortedKeys(current) {
			if _, ok := target[k]; ok {
				continue
			}
			if err := o.remove(ctx, backend, current[k]); err != nil {
				rep.Error = err.Error()
				break
			}
			rep.Closed = append(rep.Closed, k)
		}
	}

	if backend == "firewalld" && (len(rep.Opened) > 0 || len(rep.Closed) > 0) {
		if _, err := o.run(ctx, "firewall-cmd", "--reload"); err != nil && rep.Error == "" {
			rep.Error = "firewall-cmd --reload: " + strings.TrimSpace(err.Error())
		}
	}
	rep.Detail = o.summary(backend, rep)
	return rep
}

// sortedKeys keeps the commands in a stable order, so a report reads the same
// whatever order the map iterates in.
func sortedKeys(m map[string]Spec) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (o *Opener) add(ctx context.Context, backend string, s Spec) error {
	switch backend {
	case "firewalld":
		if _, err := o.run(ctx, "firewall-cmd", "--permanent", "--add-port="+s.firewalldArg()); err != nil {
			return fmt.Errorf("firewall-cmd --add-port=%s: %w", s.firewalldArg(), err)
		}
	case "ufw":
		if _, err := o.run(ctx, "ufw", "allow", s.ufwArg()); err != nil {
			return fmt.Errorf("ufw allow %s: %w", s.ufwArg(), err)
		}
	}
	return nil
}

func (o *Opener) remove(ctx context.Context, backend string, s Spec) error {
	switch backend {
	case "firewalld":
		if _, err := o.run(ctx, "firewall-cmd", "--permanent", "--remove-port="+s.firewalldArg()); err != nil {
			return fmt.Errorf("firewall-cmd --remove-port=%s: %w", s.firewalldArg(), err)
		}
	case "ufw":
		if _, err := o.run(ctx, "ufw", "delete", "allow", s.ufwArg()); err != nil {
			return fmt.Errorf("ufw delete allow %s: %w", s.ufwArg(), err)
		}
	}
	return nil
}

// unavailable explains the one case where nothing could be opened. A confined
// service needs a port label as well, so say so instead of only naming the
// firewall; an unconfined one, which is what the shipped unit and image run,
// binds any port the firewall lets through.
func (o *Opener) unavailable() string {
	if o.confined() {
		return "No firewalld or ufw is running, so nothing was opened; a confined service also needs the range labelled with semanage."
	}
	return "No firewalld or ufw is running, so nothing was opened; open the range on the router or host firewall that filters this host."
}

// summary states the outcome of a sync in one line.
func (o *Opener) summary(backend string, rep Report) string {
	if len(rep.Opened) == 0 && len(rep.Closed) == 0 {
		switch backend {
		case "firewalld":
			return "Already open in firewalld."
		case "ufw":
			return "Already allowed in ufw."
		}
	}
	parts := []string{}
	if len(rep.Opened) > 0 {
		parts = append(parts, "opened "+strings.Join(rep.Opened, ", ")+" in "+backend)
	}
	if len(rep.Closed) > 0 {
		parts = append(parts, "closed "+strings.Join(rep.Closed, ", "))
	}
	return strings.Join(parts, "; ")
}

// confined reports whether SELinux confines this process. An unconfined service
// may bind any port, so labelling is only worth doing when a policy applies.
func (o *Opener) confined() bool {
	if raw, err := o.readFile("/proc/self/attr/current"); err == nil {
		label := strings.TrimSpace(string(raw))
		if label == "" || strings.HasPrefix(label, "unconfined") {
			return false
		}
		return true
	}
	return false
}
