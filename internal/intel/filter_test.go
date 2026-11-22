package intel

import (
	"net/netip"
	"strings"
	"testing"
)

// A remote feed must not be able to block the operator's own network or the
// cloud metadata address.
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
	if skipped != 8 {
		t.Fatalf("skipped %d, want 8", skipped)
	}
	if len(kept) != 2 || kept[0].String() != "203.0.113.0/24" || kept[1].String() != "2001:db8::/32" {
		t.Fatalf("kept %v", kept)
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
