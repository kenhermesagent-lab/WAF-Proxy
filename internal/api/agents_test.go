package api

import "testing"

// Agent webhooks are the same kind of operator-supplied outbound URL as a
// notification webhook, so they get the same guard: a LAN collector is fine, a
// cloud metadata or link-local address is not.
func TestValidateAgentLinkRejectsMetadataAndLinkLocal(t *testing.T) {
	refused := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"ftp://10.0.0.5/hook",
		"not-a-url",
	}
	for _, ep := range refused {
		if msg := validateAgentLink("collector", ep); msg == "" {
			t.Errorf("%q was accepted", ep)
		}
	}
	// A LAN collector and a loopback sidecar are the intended targets; the
	// guard exists to stop the metadata pivot, not to forbid the LAN.
	allowed := []string{
		"http://10.0.0.5:9000/hook",
		"http://127.0.0.1:18090/api/health",
		"https://homeassistant.lan/api/webhook/wafproxy",
	}
	for _, ep := range allowed {
		if msg := validateAgentLink("collector", ep); msg != "" {
			t.Errorf("%q was refused: %s", ep, msg)
		}
	}
}

func TestValidateAgentLinkChecksName(t *testing.T) {
	if msg := validateAgentLink("", "http://10.0.0.5/hook"); msg == "" {
		t.Error("an empty name was accepted")
	}
	if msg := validateAgentLink(string(make([]byte, 65)), "http://10.0.0.5/hook"); msg == "" {
		t.Error("a 65-character name was accepted")
	}
}
