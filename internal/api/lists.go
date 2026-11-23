package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	maxListIPs       = 5000
	maxListCountries = 250
)

// listSeparators accepts what an operator is likely to paste: one entry per
// line, commas, semicolons or plain spaces.
func listSeparators(r rune) bool {
	switch r {
	case ',', ';', '\n', '\r', '\t', ' ':
		return true
	}
	return false
}

// parseListPrefix accepts a bare address or a CIDR, so "203.0.113.7" and
// "203.0.113.0/24" are both stored in canonical form.
func parseListPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// normalizeAccessList validates a list and rewrites its entries to the stored
// form, returning the reason it was refused. A typo is rejected here rather
// than silently ignored by the engine, which would leave a site looking
// protected while nothing matched.
func normalizeAccessList(in *model.AccessList) string {
	switch in.Kind {
	case model.ListKindBlock, model.ListKindAllow:
	default:
		return "a list kind must be blocklist or whitelist"
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return "a list name of 1–64 characters is required"
	}
	ips := []string{}
	seenIP := map[string]bool{}
	for _, raw := range strings.FieldsFunc(in.IPs, listSeparators) {
		pr, err := parseListPrefix(raw)
		if err != nil {
			return "not an IP address or CIDR: " + raw
		}
		canonical := pr.String()
		if seenIP[canonical] {
			continue
		}
		if len(ips) >= maxListIPs {
			return "a list holds at most " + strconv.Itoa(maxListIPs) + " addresses"
		}
		seenIP[canonical] = true
		ips = append(ips, canonical)
	}
	countries := []string{}
	seenCountry := map[string]bool{}
	for _, raw := range strings.FieldsFunc(in.Countries, listSeparators) {
		code := strings.ToUpper(raw)
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return "not a two-letter country code: " + raw
		}
		if seenCountry[code] {
			continue
		}
		if len(countries) >= maxListCountries {
			return "a list holds at most " + strconv.Itoa(maxListCountries) + " countries"
		}
		seenCountry[code] = true
		countries = append(countries, code)
	}
	in.IPs = strings.Join(ips, ",")
	in.Countries = strings.Join(countries, ",")
	return ""
}

func (s *Server) listAccessLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.db(r).ListAccessLists()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, lists)
}

func (s *Server) createAccessList(w http.ResponseWriter, r *http.Request) {
	var in model.AccessList
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if msg := normalizeAccessList(&in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).CreateAccessList(&in); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a list with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create list")
		return
	}
	s.reload(r.Context())
	s.refreshStreamLists()
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "access_list.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.db(r).GetAccessList(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var in model.AccessList
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// The name and kind are fixed once created: a profile points here, and an
	// edited kind would silently turn a blocklist into an allow list.
	in.Name, in.Kind = current.Name, current.Kind
	if msg := normalizeAccessList(&in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	current.IPs, current.Countries = in.IPs, in.Countries
	before := s.snapshotAccessList(r, current.ID)
	if err := s.db(r).UpdateAccessList(current); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update list")
		return
	}
	s.reload(r.Context())
	s.refreshStreamLists()
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "access_list.update", current.Name, clientIP(r), "access_list", current.ID, before, s.snapshotAccessList(r, current.ID))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.db(r).GetAccessList(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	inUse, err := s.db(r).AccessListInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	forwarders := s.streamListUsers(r, id)
	global, err := s.globalListAttached(r, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 || len(forwarders) > 0 || global {
		parts := forwarders
		if global {
			parts = append(parts, "Global Profile")
		}
		if inUse > 0 {
			noun := "access profiles"
			if inUse == 1 {
				noun = "access profile"
			}
			parts = append([]string{strconv.Itoa(inUse) + " " + noun}, parts...)
		}
		writeError(w, http.StatusConflict, current.Name+" is attached to "+strings.Join(parts, " and ")+"; detach it first")
		return
	}
	before := s.snapshotAccessList(r, id)
	if err := s.db(r).DeleteAccessList(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete list")
		return
	}
	s.reload(r.Context())
	s.refreshStreamLists()
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "access_list.delete", current.Name, clientIP(r), "access_list", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
