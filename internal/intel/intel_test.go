package intel

import (
	"strings"
	"testing"
)

func TestParseTextHandlesBOMCommentsAndQuotes(t *testing.T) {
	input := "\ufeff# comment\n\"203.0.113.7\"\n198.51.100.0/24 # inline\n10.0.0.1 10.0.0.255 24\n"
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.7/32", "198.51.100.0/24", "10.0.0.0/24"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseCSVFindsAddressInAnyColumn(t *testing.T) {
	input := "reason,ip,score\nscanner,\"203.0.113.7\",9\nrange,198.51.100.0/24,4\n10.0.0.1,10.0.0.255,24\nnoise,not-an-ip,1\n"
	got, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.7/32", "198.51.100.0/24", "10.0.0.0/24"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
}
