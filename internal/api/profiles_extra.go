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
	list, err := s.st.ListProtectionProfiles()
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
	if err := s.st.CreateProtectionProfile(&in); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a profile with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "protection_profile.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updateProtectionProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProtectionProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var in model.ProtectionProfile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	p.ForceHTTPS = in.ForceHTTPS
	p.HSTS = in.HSTS
	p.HSTSSubdomains = in.HSTSSubdomains
	p.NoSniff = in.NoSniff
	p.HideServer = in.HideServer
	p.FrameOptions = in.FrameOptions
	p.ReferrerPolicy = in.ReferrerPolicy
	p.CSP = strings.TrimSpace(in.CSP)
	p.PermissionsPolicy = strings.TrimSpace(in.PermissionsPolicy)
	if p.FrameOptions == "" {
		p.FrameOptions = "off"
	}
	if msg := validateProtectionProfile(p); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.st.UpdateProtectionProfile(p); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "protection_profile.update", p.Name, clientIP(r))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProtectionProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetProtectionProfile(id)
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
	inUse, err := s.st.ProtectionProfileInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 {
		writeError(w, http.StatusConflict, inUseMessage(p.Name, inUse))
		return
	}
	if err := s.st.DeleteProtectionProfile(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "protection_profile.delete", p.Name, clientIP(r))
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
	list, err := s.st.ListAccessProfiles()
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
	if msg := s.validateAccessPolicies(in.PolicyIDs); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.st.CreateAccessProfile(&in); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a profile with that name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "cannot create profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "access_profile.create", in.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) updateAccessProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.st.GetAccessProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	var in model.AccessProfile
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if msg := s.validateAccessPolicies(in.PolicyIDs); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	current.PolicyIDs = in.PolicyIDs
	if err := s.st.UpdateAccessProfile(current); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "access_profile.update", current.Name, clientIP(r))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteAccessProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.st.GetAccessProfile(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	inUse, err := s.st.AccessProfileInUse(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if inUse > 0 {
		writeError(w, http.StatusConflict, inUseMessage(current.Name, inUse))
		return
	}
	if err := s.st.DeleteAccessProfile(id); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete profile")
		return
	}
	s.reload(r.Context())
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "access_profile.delete", current.Name, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// validateAccessPolicies rejects ids that do not exist, so a bundle cannot
// silently reference a deleted row.
func (s *Server) validateAccessPolicies(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	existing, err := s.st.ListPolicies()
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
