package netmatch

import (
	"net/netip"
	"testing"
)

// purgeExpired removes the prefix it is handed, so Range has to survive a
// mutating callback; holding the read lock across the callback deadlocked.
func TestRangeAllowsTheCallbackToRemoveEntries(t *testing.T) {
	m := New[int]()
	p1 := netip.MustParsePrefix("198.51.100.0/24")
	p2 := netip.MustParsePrefix("203.0.113.0/24")
	m.AddPrefix(p1, 1)
	m.AddPrefix(p2, 2)

	seen := 0
	m.Range(func(p netip.Prefix, _ int) bool {
		seen++
		m.RemovePrefix(p)
		return true
	})
	if seen != 2 {
		t.Fatalf("Range visited %d prefixes, want 2", seen)
	}
	if n := m.Len(); n != 0 {
		t.Fatalf("Len after removing inside Range = %d, want 0", n)
	}
}

func TestRangeStopsWhenTheCallbackReturnsFalse(t *testing.T) {
	m := New[int]()
	m.AddCIDR("198.51.100.0/24", 1)
	m.AddCIDR("203.0.113.0/24", 2)
	seen := 0
	m.Range(func(netip.Prefix, int) bool {
		seen++
		return false
	})
	if seen != 1 {
		t.Fatalf("Range visited %d prefixes after a false return, want 1", seen)
	}
	if n := m.Len(); n != 2 {
		t.Fatalf("Len = %d, want the map untouched", n)
	}
}
