package api

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestValidateBodySkipPaths(t *testing.T) {
	cases := []struct {
		entry model.BodySkip
		ok    bool
	}{
		{model.BodySkip{Method: "POST", Prefix: "/seafhttp/upload-aj/*"}, true},
		{model.BodySkip{Method: "put", Prefix: "/remote.php/dav/files/"}, true},
		{model.BodySkip{Method: "POST", Prefix: "/api/assets"}, true},
		{model.BodySkip{Method: "GET", Prefix: "/api/assets"}, false},
		{model.BodySkip{Method: "POST", Prefix: "*"}, false},
		{model.BodySkip{Method: "POST", Prefix: "/"}, false},
		{model.BodySkip{Method: "POST", Prefix: "/*"}, false},
		{model.BodySkip{Method: "POST", Prefix: "/a*b"}, false},
		{model.BodySkip{Method: "POST", Prefix: "/a b"}, false},
	}
	for _, c := range cases {
		msg := validateBodySkip([]model.BodySkip{c.entry})
		if (msg == "") != c.ok {
			t.Errorf("%s %q: %q, want ok=%v", c.entry.Method, c.entry.Prefix, msg, c.ok)
		}
	}
}
