package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
)

// A named whitelist or blocklist can be attached globally, in which case it
// applies to every proxy instead of only the ones whose access profile names
// it. The IDs live in settings so no schema change is needed.

type globalListsBody struct {
	WhitelistIDs []int64 `json:"whitelist_ids"`
	BlocklistIDs []int64 `json:"blocklist_ids"`
}

func parseSettingIDs(raw string) []int64 {
	out := []int64{}
	for _, part := range strings.Split(raw, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func joinSettingIDs(ids []int64) string {
	seen := map[int64]bool{}
	parts := []string{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// globalListAttached reports whether a list is applied under Global Profile.
// Deleting it from its own tab would otherwise stop enforcing it silently.
func (s *Server) globalListAttached(r *http.Request, id int64) (bool, error) {
	kv, err := s.db(r).Settings()
	if err != nil {
		return false, err
	}
	for _, key := range []string{"global_whitelist_ids", "global_blocklist_ids"} {
		for _, ref := range parseSettingIDs(kv[key]) {
			if ref == id {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Server) getGlobalLists(w http.ResponseWriter, r *http.Request) {
	kv, err := s.db(r).Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	lists, err := s.db(r).ListAccessLists()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lists":         lists,
		"whitelist_ids": parseSettingIDs(kv["global_whitelist_ids"]),
		"blocklist_ids": parseSettingIDs(kv["global_blocklist_ids"]),
	})
}

func (s *Server) putGlobalLists(w http.ResponseWriter, r *http.Request) {
	var in globalListsBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	lists, err := s.db(r).ListAccessLists()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	byID := make(map[int64]model.AccessList, len(lists))
	for _, l := range lists {
		byID[l.ID] = l
	}
	check := func(ids []int64, want, label string) string {
		for _, id := range ids {
			l, ok := byID[id]
			if !ok {
				return "no such profile: " + strconv.FormatInt(id, 10)
			}
			if l.Kind != want {
				return l.Name + " is not a " + label
			}
		}
		return ""
	}
	if msg := check(in.WhitelistIDs, model.ListKindAllow, "whitelist"); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if msg := check(in.BlocklistIDs, model.ListKindBlock, "blocklist"); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).SetSettings(map[string]string{
		"global_whitelist_ids": joinSettingIDs(in.WhitelistIDs),
		"global_blocklist_ids": joinSettingIDs(in.BlocklistIDs),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "global_lists.update",
		"whitelists "+joinSettingIDs(in.WhitelistIDs)+" blocklists "+joinSettingIDs(in.BlocklistIDs), clientIP(r))
	wl, bl := joinSettingIDs(in.WhitelistIDs), joinSettingIDs(in.BlocklistIDs)
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist_ids": parseSettingIDs(wl),
		"blocklist_ids": parseSettingIDs(bl),
	})
}

// asnSuggestion is a group of ASNs an operator can turn into a normal, editable
// block policy with one click. The list is a starting point, not a guarantee:
// providers move between networks, so the note says what was checked.
type asnSuggestion struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	ASNs []int  `json:"asns"`
	Note string `json:"note"`
}

var vpnSuggestions = []asnSuggestion{
	{ID: "mullvad", Name: "Mullvad VPN", ASNs: []int{39351, 197141, 216025},
		Note: "31173 Services AB and Mullvad's own ASNs, as published in RIPE records."},
	{ID: "proton", Name: "Proton VPN", ASNs: []int{209103, 208172},
		Note: "Proton AG networks; mail and calendar run on the same ASNs."},
	{ID: "nordvpn", Name: "NordVPN", ASNs: []int{136787, 207137},
		Note: "Tefincom and Packethub. Most NordVPN servers rent hosting space instead, so pair this with the hosting list."},
	{ID: "surfshark", Name: "Surfshark", ASNs: []int{209854},
		Note: "Surfshark's own network; the rest of its fleet sits on rented hosting."},
}

// listASNRecommendations returns groups an operator can add as ASN block
// policies. Hosting ASNs come from the engine's own default list, so the
// suggestion and the built-in setting cannot drift apart.
func (s *Server) listASNRecommendations(w http.ResponseWriter, r *http.Request) {
	hosting := asnSuggestion{
		ID:   "hosting",
		Name: "Hosting and cloud providers",
		ASNs: append([]int{}, policy.DefaultHostingASNs...),
		Note: "Already refused while the global hosting-ASN setting is on; adding a policy keeps them blocked if that setting is switched off.",
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosting": hosting,
		"vpn":     vpnSuggestions,
	})
}
