package api

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

var providerKinds = map[string]bool{"authelia": true, "authentik": true, "generic": true}

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func validateAuthProvider(p *model.AuthProvider) string {
	if p.Name == "" || len(p.Name) > 64 {
		return "a provider name of 1–64 characters is required"
	}
	if !providerKinds[p.Kind] {
		return "the provider kind must be authelia, authentik or generic"
	}
	if !isHTTPURL(p.VerifyURL) {
		return "the verify URL must be an absolute http(s) URL"
	}
	if p.LoginURL != "" && !isHTTPURL(p.LoginURL) {
		return "the login URL must be an absolute http(s) URL"
	}
	if !headerNameRE.MatchString(p.Header) {
		return "the secret header must be a header name"
	}
	return ""
}

// authProviderBody is the write shape: the sealed secret never round-trips, so
// an empty secret on update keeps the stored one.
type authProviderBody struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	VerifyURL string `json:"verify_url"`
	LoginURL  string `json:"login_url"`
	Header    string `json:"header"`
	Secret    string `json:"secret"`
}

func (in authProviderBody) apply(p *model.AuthProvider) {
	p.Name = strings.TrimSpace(in.Name)
	p.Kind = in.Kind
	p.VerifyURL = strings.TrimSpace(in.VerifyURL)
	p.LoginURL = strings.TrimSpace(in.LoginURL)
	p.Header = defaultStr(strings.TrimSpace(in.Header), "X-Wafproxy-Auth")
}

func (s *Server) listAuthProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListAuthProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createAuthProvider(w http.ResponseWriter, r *http.Request) {
	var in authProviderBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	var p model.AuthProvider
	in.apply(&p)
	if msg := validateAuthProvider(&p); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if in.Secret != "" {
		sealed, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		p.Secret = sealed
	}
	id, err := s.st.CreateAuthProvider(&p)
	if err != nil {
		writeError(w, http.StatusConflict, "a provider with that name already exists")
		return
	}
	p.ID = id
	p.HasSecret = p.Secret != ""
	p.Secret = ""
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "auth-provider.create", p.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) updateAuthProvider(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.st.GetAuthProvider(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in authProviderBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.apply(current)
	if msg := validateAuthProvider(current); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if in.Secret != "" {
		sealed, err := s.box.Seal(in.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption error")
			return
		}
		current.Secret = sealed
	}
	if err := s.st.UpdateAuthProvider(current); err != nil {
		writeError(w, http.StatusConflict, "a provider with that name already exists")
		return
	}
	current.HasSecret = current.Secret != ""
	current.Secret = ""
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "auth-provider.update", current.Name, clientIP(r))
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) deleteAuthProvider(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	current, err := s.st.GetAuthProvider(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	used, err := s.st.DeleteAuthProvider(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot delete")
		return
	}
	if used {
		writeError(w, http.StatusConflict, "a proxy still uses this provider; detach it first")
		return
	}
	sess := sessionFrom(r)
	s.st.AddAudit(sess.Username, "auth-provider.delete", current.Name, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
