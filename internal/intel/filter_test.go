package intel

import (
	"net/netip"
	"strings"
	"testing"
)

// A remote feed must not be able to block the operator's own network, the
// cloud metadata address, or the documentation ranges the console uses as
// example clients. FireHOL lists all three test nets as bogons.
func TestFilterPublicDropsNonPublicRanges(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("239.0.0.0/8"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	kept, skipped := filterPublic(in)
	if skipped != 10 {
		t.Fatalf("skipped %d, want 10", skipped)
	}
	if len(kept) != 0 {
		t.Fatalf("kept %v, want nothing", kept)
	}
}

// An ordinary public prefix from a feed is still applied.
func TestFilterPublicKeepsRealAddresses(t *testing.T) {
	kept, skipped := filterPublic([]netip.Prefix{netip.MustParsePrefix("52.94.0.0/16"),
		netip.MustParsePrefix("8.8.8.8/32")})
	if skipped != 0 || len(kept) != 2 {
		t.Fatalf("kept %v, skipped %d, want both kept", kept, skipped)
	}
}

func TestParseStillReturnsEveryPrefix(t *testing.T) {
	prefixes, err := Parse(strings.NewReader("10.0.0.0/8\n203.0.113.7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("Parse kept %d prefixes, want 2 (filtering is the caller's job)", len(prefixes))
	}
}
