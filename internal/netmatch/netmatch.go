// Package netmatch provides a fast concurrent prefix lookup table.
package netmatch

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
)

// Map matches IP addresses against IPv4 and IPv6 prefixes. Lookups are O(number
// of distinct prefix lengths), which stays small even for millions of entries.
type Map[T any] struct {
	mu    sync.RWMutex
	v4    map[int]map[uint32]T
	v6    map[int]map[[16]byte]T
	lens4 []int
	lens6 []int
	n     int
}

// New returns an empty map.
func New[T any]() *Map[T] {
	return &Map[T]{
		v4: map[int]map[uint32]T{},
		v6: map[int]map[[16]byte]T{},
	}
}

// AddPrefix inserts or replaces a prefix.
func (m *Map[T]) AddPrefix(p netip.Prefix, v T) {
	p = p.Masked()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Addr().Is4() {
		bits := p.Bits()
		b := p.Addr().As4()
		if m.v4[bits] == nil {
			m.v4[bits] = map[uint32]T{}
			m.lens4 = insertLen(m.lens4, bits)
		}
		key := binary.BigEndian.Uint32(b[:])
		if _, exists := m.v4[bits][key]; !exists {
			m.n++
		}
		m.v4[bits][key] = v
		return
	}
	bits := p.Bits()
	b := p.Addr().As16()
	if m.v6[bits] == nil {
		m.v6[bits] = map[[16]byte]T{}
		m.lens6 = insertLen(m.lens6, bits)
	}
	if _, exists := m.v6[bits][b]; !exists {
		m.n++
	}
	m.v6[bits][b] = v
}

func insertLen(lens []int, bits int) []int {
	i := sort.SearchInts(lens, bits)
	if i < len(lens) && lens[i] == bits {
		return lens
	}
	lens = append(lens, 0)
	copy(lens[i+1:], lens[i:])
	lens[i] = bits
	return lens
}

func removeLen(lens []int, bits int) []int {
	i := sort.SearchInts(lens, bits)
	if i < len(lens) && lens[i] == bits {
		return append(lens[:i], lens[i+1:]...)
	}
	return lens
}

// AddCIDR parses a CIDR or bare address and inserts it.
func (m *Map[T]) AddCIDR(cidr string, v T) error {
	p, err := ParsePrefix(cidr)
	if err != nil {
		return err
	}
	m.AddPrefix(p, v)
	return nil
}

// RemovePrefix deletes a prefix.
func (m *Map[T]) RemovePrefix(p netip.Prefix) {
	p = p.Masked()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Addr().Is4() {
		bits := p.Bits()
		b := p.Addr().As4()
		key := binary.BigEndian.Uint32(b[:])
		if set, ok := m.v4[bits]; ok {
			if _, exists := set[key]; exists {
				delete(set, key)
				m.n--
			}
			if len(set) == 0 {
				delete(m.v4, bits)
				m.lens4 = removeLen(m.lens4, bits)
			}
		}
		return
	}
	bits := p.Bits()
	b := p.Addr().As16()
	if set, ok := m.v6[bits]; ok {
		if _, exists := set[b]; exists {
			delete(set, b)
			m.n--
		}
		if len(set) == 0 {
			delete(m.v6, bits)
			m.lens6 = removeLen(m.lens6, bits)
		}
	}
}

// Match returns the most specific prefix value containing addr.
func (m *Map[T]) Match(addr netip.Addr) (T, bool) {
	var zero T
	if !addr.IsValid() {
		return zero, false
	}
	addr = addr.Unmap()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if addr.Is4() {
		b := addr.As4()
		key := binary.BigEndian.Uint32(b[:])
		for i := len(m.lens4) - 1; i >= 0; i-- {
			bits := m.lens4[i]
			mask := mask32(bits)
			if v, ok := m.v4[bits][key&mask]; ok {
				return v, true
			}
		}
		return zero, false
	}
	b := addr.As16()
	for i := len(m.lens6) - 1; i >= 0; i-- {
		bits := m.lens6[i]
		masked := mask16(b, bits)
		if v, ok := m.v6[bits][masked]; ok {
			return v, true
		}
	}
	return zero, false
}

// ReplaceWith atomically swaps this map's contents with another map. The
// receiver pointer stays stable, so concurrent Match calls stay safe.
func (m *Map[T]) ReplaceWith(src *Map[T]) {
	src.mu.RLock()
	v4, v6 := src.v4, src.v6
	lens4, lens6 := src.lens4, src.lens6
	n := src.n
	src.mu.RUnlock()
	m.mu.Lock()
	m.v4, m.v6 = v4, v6
	m.lens4, m.lens6 = lens4, lens6
	m.n = n
	m.mu.Unlock()
}

// Len returns the number of stored prefixes.
func (m *Map[T]) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.n
}

// Range calls fn for every stored prefix. Returning false stops iteration. The
// entries are copied first, so fn may add or remove prefixes: holding the read
// lock across the callback deadlocked the ban sweeper, which removes the
// entries it walks.
func (m *Map[T]) Range(fn func(netip.Prefix, T) bool) {
	type entry struct {
		p netip.Prefix
		v T
	}
	m.mu.RLock()
	entries := make([]entry, 0, m.n)
	for bits, set := range m.v4 {
		for key, v := range set {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], key)
			entries = append(entries, entry{netip.PrefixFrom(netip.AddrFrom4(b), bits), v})
		}
	}
	for bits, set := range m.v6 {
		for key, v := range set {
			entries = append(entries, entry{netip.PrefixFrom(netip.AddrFrom16(key), bits), v})
		}
	}
	m.mu.RUnlock()
	for _, e := range entries {
		if !fn(e.p, e.v) {
			return
		}
	}
}

func mask32(bits int) uint32 {
	if bits == 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}

func mask16(b [16]byte, bits int) [16]byte {
	if bits == 0 {
		return [16]byte{}
	}
	out := b
	full := bits / 8
	for i := 0; i < full; i++ {
		out[i] = b[i]
	}
	if rem := bits % 8; rem != 0 && full < 16 {
		out[full] = b[full] & byte(0xff<<(8-rem))
		for i := full + 1; i < 16; i++ {
			out[i] = 0
		}
	} else if full < 16 {
		for i := full; i < 16; i++ {
			out[i] = 0
		}
	}
	return out
}

// ParsePrefix accepts "1.2.3.0/24", "1.2.3.4" or "2001:db8::/32".
func ParsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Aggregate removes prefixes already covered by a broader prefix.
func Aggregate(prefixes []netip.Prefix) []netip.Prefix {
	cleaned := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		cleaned = append(cleaned, p.Masked())
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].Addr().Is4() != cleaned[j].Addr().Is4() {
			return cleaned[i].Addr().Is4()
		}
		if cleaned[i].Bits() != cleaned[j].Bits() {
			return cleaned[i].Bits() < cleaned[j].Bits()
		}
		return cleaned[i].Addr().Less(cleaned[j].Addr())
	})
	out := make([]netip.Prefix, 0, len(cleaned))
	// An index of accepted prefixes makes coverage testing exact instead of
	// only inspecting the last few entries, which missed nested prefixes in
	// long feed lists.
	accepted := New[int]()
	for _, p := range cleaned {
		if bits, ok := accepted.Match(p.Addr()); ok && bits <= p.Bits() {
			continue
		}
		accepted.AddPrefix(p, p.Bits())
		out = append(out, p)
	}
	return out
}
