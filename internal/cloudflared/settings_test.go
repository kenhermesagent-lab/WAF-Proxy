package cloudflared

import "testing"

func TestPublishedHostnamesRoundTrip(t *testing.T) {
	kv := map[string]string{KeyPublished: EncodePublished([]string{"b.example.com", "a.example.com", "a.example.com", " "})}
	got := Published(kv)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("published = %v", got)
	}
	if !IsPublished(kv, "A.Example.com.") {
		t.Fatal("IsPublished must match case and a trailing dot")
	}
	if IsPublished(kv, "c.example.com") {
		t.Fatal("unlisted hostname reported as published")
	}
	if Published(map[string]string{KeyPublished: "{not json"}) != nil {
		t.Fatal("a corrupt list must read as empty, not panic")
	}
}
