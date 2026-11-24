package anomaly

import (
	"net/netip"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/netmatch"
)

// whitelistedSources is the set of prefixes the site's enabled IP whitelists
// allow. Those clients are expected traffic: the operator already lets them in,
// so a window made only of their bytes is not a spike. A policy scoped to
// another site does not apply here, and a malformed entry is skipped.
func (m *Manager) whitelistedSources(proxyID int64) []netip.Prefix {
	policies, err := m.st.ListPolicies()
	if err != nil {
		m.log.Warn("anomaly whitelist lookup failed", "err", err)
		return nil
	}
	out := []netip.Prefix{}
	for _, p := range policies {
		if !p.Enabled || p.Kind != model.PolicyIPWhitelist {
			continue
		}
		if p.Scope == "proxy" && (p.ProxyID == nil || *p.ProxyID != proxyID) {
			continue
		}
		for _, part := range strings.Split(p.Value, ",") {
			if pfx, err := netmatch.ParsePrefix(strings.TrimSpace(part)); err == nil {
				out = append(out, pfx)
			}
		}
	}
	return out
}
