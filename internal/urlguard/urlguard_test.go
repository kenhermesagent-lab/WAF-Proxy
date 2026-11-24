package urlguard

import (
	"strings"
	"testing"
)

// The guard is a best-effort filter, so each policy's refusals are pinned here.
func TestCheckClassifiesAddressesPerPolicy(t *testing.T) {
	cases := []struct {
		name, raw string
		policy    Policy
		want      string
	}{
		{"public upstream", "http://198.51.100.9:8080", Upstream, ""},
		{"lan upstream", "http://10.0.0.5:3000", Upstream, ""},
		{"loopback upstream", "http://127.0.0.1:8080", Upstream, ""},
		{"ipv6 loopback upstream", "http://[::1]:8080", Upstream, ""},
		{"metadata by ip is refused even for upstreams", "http://169.254.169.254/latest/meta-data/", Upstream, "cloud metadata endpoints are not allowed"},
		{"alibaba metadata", "http://100.100.100.200/", Upstream, "cloud metadata endpoints are not allowed"},
		{"aws ipv6 metadata", "http://[fd00:ec2::254]/", Upstream, "cloud metadata endpoints are not allowed"},
		{"metadata alias", "http://metadata/computeMetadata/v1/", Upstream, "cloud metadata endpoints are not allowed"},
		{"uppercase metadata host", "HTTP://METADATA.GOOGLE.INTERNAL/", Webhook, "cloud metadata endpoints are not allowed"},

		{"feed allows the public internet", "https://198.51.100.9/list.txt", Feed, ""},
		{"feed refuses private space", "https://10.0.0.5/list.txt", Feed, "private addresses are not allowed"},
		{"feed refuses loopback", "https://127.0.0.1/list.txt", Feed, "loopback addresses are not allowed"},
		{"feed refuses link-local", "https://169.254.1.1/list.txt", Feed, "link-local addresses are not allowed"},

		{"webhook allows a lan collector", "http://10.0.0.5:8123/api/webhook/x", Webhook, ""},
		{"webhook allows loopback", "http://127.0.0.1:9000/hook", Webhook, ""},
		{"webhook refuses link-local", "http://169.254.1.1/hook", Webhook, "link-local addresses are not allowed"},
		{"webhook refuses an ipv4-mapped metadata address", "http://[::ffff:169.254.169.254]/", Webhook, "link-local addresses are not allowed"},

		{"a url with no scheme", "app.example.com:8080", Feed, "url must use http or https"},
		{"a file url", "file:///etc/passwd", Feed, "url must use http or https"},
		{"a gopher url", "gopher://198.51.100.9/", Webhook, "url must use http or https"},
		{"a url with no host", "https:///path", Feed, "url has no host"},
		{"an unparsable url", "http://[::1", Feed, "invalid url"},
		{"surrounding whitespace is ignored", "  https://198.51.100.9/list  ", Feed, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Check(c.raw, c.policy)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Check(%q) = %v, want nil", c.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Check(%q) = %v, want an error containing %q", c.raw, err, c.want)
			}
		})
	}
}
