package netmatch

import (
	"fmt"
	"net/netip"
	"testing"
)

// buildTable fills a map with n distinct /24 blocks spread across the IPv4
// space, plus a handful of broader prefixes, which resembles a threat feed.
func buildTable(n int) *Map[int] {
	m := New[int]()
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{byte(10 + i/65536%200), byte(i / 256 % 256), byte(i % 256), 0})
		m.AddPrefix(netip.PrefixFrom(a, 24), i)
	}
	return m
}

func BenchmarkMatch100k(b *testing.B) {
	m := buildTable(100000)
	addr := netip.MustParseAddr("10.1.2.3")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := m.Match(addr); !ok {
			b.Fatal("expected a match")
		}
	}
}

func BenchmarkMatch100kMiss(b *testing.B) {
	m := buildTable(100000)
	addr := netip.MustParseAddr("203.0.113.9")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(addr)
	}
}

func BenchmarkAggregate10k(b *testing.B) {
	prefixes := make([]netip.Prefix, 0, 10000)
	for i := 0; i < 10000; i++ {
		a := netip.AddrFrom4([4]byte{byte(10 + i/65536%200), byte(i / 256 % 256), byte(i % 256), 0})
		prefixes = append(prefixes, netip.PrefixFrom(a, 24))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := Aggregate(prefixes); len(got) != len(prefixes) {
			b.Fatalf("aggregate returned %d prefixes, want %d", len(got), len(prefixes))
		}
	}
}

func ExampleAggregate() {
	fmt.Println(len(Aggregate([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})))
	// Output: 2
}
