package api

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type lookupFeed struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Action string `json:"action"`
}

type lookupBan struct {
	CIDR      string     `json:"cidr"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"`
	Permanent bool       `json:"permanent"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type lookupResult struct {
	IP   string      `json:"ip"`
	Feed *lookupFeed `json:"feed"`
	Ban  *lookupBan  `json:"ban"`
}

// lookupIP answers where a single address stands: a threat feed, an active ban,
// or neither.
func (s *Server) lookupIP(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "enter a single IPv4 or IPv6 address")
		return
	}
	out := lookupResult{IP: addr.String()}
	if s.feeds != nil {
		if e, ok := s.feeds.Match(addr); ok {
			out.Feed = &lookupFeed{ID: e.FeedID, Name: e.Feed, Action: e.Action}
		}
	}
	if rec, ok := s.bans.Match(addr); ok {
		out.Ban = &lookupBan{
			CIDR: rec.CIDR, Reason: rec.Reason, Source: rec.Source,
			Permanent: rec.Permanent, ExpiresAt: rec.ExpiresAt,
		}
	}
	writeJSON(w, http.StatusOK, out)
}
