package norm

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspect(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		typ     string
		body    string
		want    string // kind:parameter, empty for no finding
		second  string
		hasSecs bool
	}{
		{name: "clean", target: "/search?q=router&page=2"},
		{name: "repeated same value", target: "/list?tag=a&tag=a"},
		{name: "duplicate query", target: "/item?id=1&id=2", want: "duplicate-parameter:id"},
		{name: "duplicate form", target: "/item", typ: "application/x-www-form-urlencoded",
			body: "role=user&role=admin", want: "duplicate-parameter:role"},
		{name: "double encoded query", target: "/q?next=%253Cscript%253E", want: "double-encoded:next",
			second: "<script>", hasSecs: true},
		{name: "double encoded form", target: "/q", typ: "application/x-www-form-urlencoded",
			body: "next=%253Cscript%253E", want: "double-encoded:next", second: "<script>", hasSecs: true},
		{name: "single encoding is fine", target: "/q?next=%3Cb%3E"},
		{name: "json body is not a form", target: "/api", typ: "application/json",
			body: `{"a":"1","a":"2"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.target, strings.NewReader(tc.body))
			if tc.body == "" {
				r = httptest.NewRequest("GET", tc.target, nil)
			}
			if tc.typ != "" {
				r.Header.Set("Content-Type", tc.typ)
			}
			got := Inspect(r, []byte(tc.body))
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %+v, want no findings", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("want %s, got nothing", tc.want)
			}
			key := got[0].Kind + ":" + got[0].Parameter
			if key != tc.want {
				t.Fatalf("got %s, want %s", key, tc.want)
			}
			if tc.hasSecs && got[0].Second != tc.second {
				t.Fatalf("second decode = %q, want %q", got[0].Second, tc.second)
			}
		})
	}
}
