package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

var referrerPolicies = map[string]bool{
	"": true, "no-referrer": true, "no-referrer-when-downgrade": true,
	"origin": true, "origin-when-cross-origin": true, "same-origin": true,
	"strict-origin": true, "strict-origin-when-cross-origin": true, "unsafe-url": true,
}

// headerValue refuses values that would split or terminate a response header.
func headerValue(name, v string, max int) string {
	if strings.ContainsAny(v, "\r\n\x00") {
		return name + " contains a control character"
	}
	if len(v) > max {
		return name + " is longer than " + strconv.Itoa(max) + " characters"
	}
	return ""
}

func validateProtectionProfile(p *model.ProtectionProfile) string {
	if msg := headerValue("frame_options", p.FrameOptions, 16); msg != "" {
		return msg
	}
	switch p.FrameOptions {
	case "off", "deny", "sameorigin":
	default:
		return "frame options must be off, deny or sameorigin"
	}
	if !referrerPolicies[p.ReferrerPolicy] {
		return "unknown referrer policy"
	}
	if msg := headerValue("csp", p.CSP, 2048); msg != "" {
		return msg
	}
	if msg := headerValue("permissions_policy", p.PermissionsPolicy, 2048); msg != "" {
		return msg
	}
	return ""
}

func (s *Server) listProtectionProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := s.db(r).ListProtectionProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createProtectionProfile(w http.ResponseWriter, r *http.Request) {
	var in model.ProtectionProfile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeError(w, http.StatusBadRequest, "a profile name of 1–64 characters is required")
		return
	}
	if in.FrameOptions == "" {
		in.FrameOptions = "sameorigin"
	}
	if msg := validateProtectionProfile(&in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).CreateProtectionProfile(&in); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a profile with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "protection_profile.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updateProtectionProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.db(r).GetProtectionProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var in model.ProtectionProfile
	sent, err := decodeSent(r, &in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// Every switch is off by default, so an omitted one cannot be told from an
	// explicit false: only the keys the payload names are written. A request
	// turning on HSTS must not silently drop the CSP and nosniff with it.
	if _, ok := sent["force_https"]; ok {
		p.ForceHTTPS = in.ForceHTTPS
	}
	if _, ok := sent["hsts"]; ok {
		p.HSTS = in.HSTS
	}
	if _, ok := sent["hsts_subdomains"]; ok {
		p.HSTSSubdomains = in.HSTSSubdomains
	}
	if _, ok := sent["nosniff"]; ok {
		p.NoSniff = in.NoSniff
	}
	if _, ok := sent["hide_server"]; ok {
		p.HideServer = in.HideServer
	}
	if _, ok := sent["frame_options"]; ok {
		p.FrameOptions = in.FrameOptions
		if p.FrameOptions == "" {
			p.FrameOptions = "off"
		}
	}
	if _, ok := sent["referrer_policy"]; ok {
		p.ReferrerPolicy = in.ReferrerPolicy
	}
	if _, ok := sent["csp"]; ok {
		p.CSP = strings.TrimSpace(in.CSP)
	}
	if _, ok := sent["permissions_policy"]; ok {
		p.PermissionsPolicy = strings.TrimSpace(in.PermissionsPolicy)
	}
	if msg := validateProtectionProfile(p); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	before := s.snapshotProtectionProfile(r, p.ID)
	if err := s.db(r).UpdateProtectionProfile(p); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "protection_profile.update", p.Name, clientIP(r), "protection_profile", p.ID, before, s.snapshotProtectionProfile(r, p.ID))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProtectionProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.db(r).GetProtectionProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if p.Builtin {
		writeError(w, http.StatusConflict, "built-in profiles cannot be deleted")
		return
	}
	inUse, err := s.db(r).ProtectionProfileInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 {
		writeError(w, http.StatusConflict, inUseMessage(p.Name, inUse))
		return
	}
	before := s.snapshotProtectionProfile(r, id)
	if err := s.db(r).DeleteProtectionProfile(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "protection_profile.delete", p.Name, clientIP(r), "protection_profile", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func inUseMessage(name string, n int) string {
	noun := "proxies"
	if n == 1 {
		noun = "proxy"
	}
	return name + " is selected by " + strconv.Itoa(n) + " " + noun + "; assign another profile first"
}

func (s *Server) listAccessProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := s.db(r).ListAccessProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createAccessProfile(w http.ResponseWriter, r *http.Request) {
	var in model.AccessProfile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeError(w, http.StatusBadRequest, "a profile name of 1–64 characters is required")
		return
	}
	if msg := s.validateAccessProfile(r, &in); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.db(r).CreateAccessProfile(&in); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a profile with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "access_profile.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updateAccessProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.db(r).GetAccessProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var in model.AccessProfile
	sent, err := decodeSent(r, &in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// An empty rule set is a real setting, so presence decides: a request
	// changing the WAF profile must not empty the lists that grant access.
	if _, ok := sent["rules"]; ok {
		current.Rules = in.Rules
	}
	if _, ok := sent["list_ids"]; ok {
		current.ListIDs = in.ListIDs
	}
	if _, ok := sent["waf_profile_id"]; ok {
		current.WAFProfileID = in.WAFProfileID
	}
	if _, ok := sent["protection_profile_id"]; ok {
		current.ProtectionProfileID = in.ProtectionProfileID
	}
	if msg := s.validateAccessProfile(r, current); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	before := s.snapshotAccessProfile(r, current.ID)
	if err := s.db(r).UpdateAccessProfile(current); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "access_profile.update", current.Name, clientIP(r), "access_profile", current.ID, before, s.snapshotAccessProfile(r, current.ID))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteAccessProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.db(r).GetAccessProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	inUse, err := s.db(r).AccessProfileInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 {
		writeError(w, http.StatusConflict, inUseMessage(current.Name, inUse))
		return
	}
	before := s.snapshotAccessProfile(r, id)
	if err := s.db(r).DeleteAccessProfile(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.auditChange(r, sess.Username, "access_profile.delete", current.Name, clientIP(r), "access_profile", id, before, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// validateAccessProfile rejects references that do not exist, so a profile
// cannot silently point at a deleted list or protection profile.
func (s *Server) validateAccessProfile(r *http.Request, a *model.AccessProfile) string {
	for _, r := range a.Rules {
		switch r.Role {
		case "", model.AccessRoleAllow, model.AccessRoleDeny, model.AccessRoleInherit:
		default:
			return "a rule role must be allow, deny or inherit"
		}
	}
	ids := a.PolicyIDs()
	if msg := s.validateAccessPolicies(r, ids); msg != "" {
		return msg
	}
	for _, id := range a.ListIDs {
		if _, err := s.db(r).GetAccessList(id); err != nil {
			return "list " + strconv.FormatInt(id, 10) + " does not exist"
		}
	}
	if a.WAFProfileID != nil {
		if _, err := s.db(r).GetProfile(*a.WAFProfileID); err != nil {
			return "the selected WAF profile does not exist"
		}
	}
	if a.ProtectionProfileID != nil {
		if _, err := s.db(r).GetProtectionProfile(*a.ProtectionProfileID); err != nil {
			return "the selected protection profile does not exist"
		}
	}
	return ""
}

func (s *Server) validateAccessPolicies(r *http.Request, ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	existing, err := s.db(r).ListPolicies()
	if err != nil {
		return "database error"
	}
	known := map[int64]bool{}
	for _, p := range existing {
		known[p.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return "policy " + strconv.FormatInt(id, 10) + " does not exist"
		}
	}
	return ""
}
