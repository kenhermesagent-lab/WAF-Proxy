package hostfw

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fake runs the host tools from memory and records every command.
type fake struct {
	replies map[string]string
	fail    map[string]error
	calls   []string
}

func newFake(replies map[string]string) *fake {
	return &fake{replies: replies, fail: map[string]error{}}
}

func (f *fake) run(_ context.Context, name string, args ...string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, line)
	if err, ok := f.fail[line]; ok {
		return "", err
	}
	return f.replies[line], nil
}

func (f *fake) opener() *Opener {
	return &Opener{run: f.run, readFile: func(string) ([]byte, error) { return []byte("unconfined_service_t"), nil }}
}

func (f *fake) called(want string) bool {
	for _, c := range f.calls {
		if c == want {
			return true
		}
	}
	return false
}

func TestSpecsFromConfig(t *testing.T) {
	cases := []struct {
		protocol string
		want     []string
	}{
		{"tcp", []string{"32400/tcp"}},
		{"udp", []string{"32400/udp"}},
		{"both", []string{"32400/tcp", "32400/udp"}},
		{"", []string{"32400/tcp"}},
	}
	for _, c := range cases {
		var got []string
		for _, s := range ForConfig(32400, 1, c.protocol) {
			got = append(got, s.String())
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("protocol %q produced %v, want %v", c.protocol, got, c.want)
		}
	}
	ranged := ForConfig(2456, 3, "udp")
	if len(ranged) != 1 || ranged[0].String() != "2456-2458/udp" || ranged[0].ufwArg() != "2456:2458/udp" {
		t.Fatalf("range specs = %+v", ranged)
	}
}

func TestParse(t *testing.T) {
	for _, raw := range []string{"32400/tcp", "2456-2458/udp", "7777-7778/udp"} {
		s, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if s.String() != raw {
			t.Fatalf("parse %q came back as %q", raw, s.String())
		}
	}
	for _, raw := range []string{"", "32400", "32400/sctp", "0/tcp", "5000-9000/tcp"} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("parse %q was accepted", raw)
		}
	}
}

func TestFirewalldOpensAndClosesTheRange(t *testing.T) {
	f := newFake(map[string]string{"firewall-cmd --state": "running\n"})
	rep := f.opener().Sync(context.Background(), ForConfig(32400, 1, "tcp"), nil)
	if rep.Backend != "firewalld" || rep.Error != "" {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Opened) != 1 || rep.Opened[0] != "32400/tcp" {
		t.Fatalf("opened = %v", rep.Opened)
	}
	for _, want := range []string{
		"firewall-cmd --permanent --add-port=32400/tcp",
		"firewall-cmd --reload",
	} {
		if !f.called(want) {
			t.Errorf("did not run %q, ran %v", want, f.calls)
		}
	}

	// Moving the port closes the old rule as part of the same save.
	f2 := newFake(map[string]string{"firewall-cmd --state": "running\n"})
	rep = f2.opener().Sync(context.Background(), ForConfig(8096, 1, "tcp"), []string{"32400/tcp"})
	if len(rep.Opened) != 1 || rep.Opened[0] != "8096/tcp" || len(rep.Closed) != 1 || rep.Closed[0] != "32400/tcp" {
		t.Fatalf("move report = %+v", rep)
	}
	if !f2.called("firewall-cmd --permanent --remove-port=32400/tcp") {
		t.Errorf("the old port was not closed: %v", f2.calls)
	}

	// Turning the forwarder off closes what this feature opened.
	f3 := newFake(map[string]string{"firewall-cmd --state": "running\n"})
	rep = f3.opener().Sync(context.Background(), nil, []string{"32400/tcp", "32400/udp"})
	if len(rep.Closed) != 2 || rep.Detail == "" {
		t.Fatalf("disable report = %+v", rep)
	}
}

func TestUFWUsesItsRangeSyntax(t *testing.T) {
	f := newFake(map[string]string{"ufw status": "Status: active\n"})
	rep := f.opener().Sync(context.Background(), ForConfig(2456, 3, "udp"), nil)
	if rep.Backend != "ufw" || rep.Error != "" {
		t.Fatalf("report = %+v", rep)
	}
	if !f.called("ufw allow 2456:2458/udp") {
		t.Fatalf("ufw was not asked to allow the range: %v", f.calls)
	}
}

func TestNoFirewallLeavesNothingToDo(t *testing.T) {
	f := newFake(nil)
	o := f.opener()
	o.stat = func(string) error { return nil }
	rep := o.Sync(context.Background(), ForConfig(32400, 1, "tcp"), nil)
	if rep.Backend != "" || len(rep.Opened) != 0 || rep.Detail == "" {
		t.Fatalf("report = %+v", rep)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "add-port") || strings.Contains(c, "allow") {
			t.Fatalf("a rule was changed with no firewall running: %q", c)
		}
	}
}

func TestAFailedCommandIsReportedNotFatal(t *testing.T) {
	f := newFake(map[string]string{"firewall-cmd --state": "running\n"})
	f.fail["firewall-cmd --permanent --add-port=32400/tcp"] = errors.New("exit status 1")
	rep := f.opener().Sync(context.Background(), ForConfig(32400, 1, "tcp"), nil)
	if rep.Error == "" || len(rep.Opened) != 0 {
		t.Fatalf("report = %+v", rep)
	}
}
