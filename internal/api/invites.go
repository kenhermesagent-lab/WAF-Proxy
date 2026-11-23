package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

const inviteTTL = 7 * 24 * time.Hour

type inviteBody struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	RoleID    int64  `json:"role_id"`
}

// inviteUser mails a single-use link instead of choosing a password for the
// recipient. The account is created only when that link is opened, so the
// administrator never has to hand over credentials.
func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request) {
	if !s.emailConfigured(r) {
		writeError(w, http.StatusBadRequest, "email notifications are not configured; set up SMTP first")
		return
	}
	var in inviteBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	firstName := strings.TrimSpace(in.FirstName)
	lastName := strings.TrimSpace(in.LastName)
	if !validEmail(email) {
		writeError(w, http.StatusBadRequest, "enter a valid email address")
		return
	}
	if len(firstName) > 64 || len(lastName) > 64 {
		writeError(w, http.StatusBadRequest, "names must be at most 64 characters")
		return
	}
	role, err := s.db(r).RoleByID(in.RoleID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "choose a valid role")
		return
	}
	if used, err := s.db(r).EmailInUse(email); err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	} else if used {
		writeError(w, http.StatusConflict, "an administrator already uses that address")
		return
	}
	token, err := wfcrypto.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create the invitation")
		return
	}
	if err := s.db(r).CreateInvite(tokenDigest(token), email, firstName, lastName, role.ID, time.Now().Add(inviteTTL)); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot create the invitation")
		return
	}
	link := s.inviteOrigin(r) + "/#/invite?token=" + url.QueryEscape(token)
	name := strings.TrimSpace(firstName + " " + lastName)
	if name == "" {
		name = email
	}
	text := fmt.Sprintf("Hello %s,\n\n"+
		"You have been invited to administer the WAF-Proxy console.\n\n"+
		"Open the link below within 7 days to choose a username and password and to enrol an authenticator:\n\n%s\n\n"+
		"If you were not expecting this invitation, ignore the message; no account exists until the link is used.\n", name, link)
	if err := s.notifyFor(r).SendMailLink([]string{email}, "You have been invited to the WAF-Proxy console", text, "Create your account", link); err != nil {
		_ = s.db(r).DeleteInvite(tokenDigest(token))
		s.log.Warn("invitation email", "err", err)
		writeError(w, http.StatusBadGateway, "the invitation could not be emailed: "+err.Error())
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "user.invite", email, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]string{"status": "invited", "email": email})
}

// inviteOrigin is the console origin of the site the invitation belongs to.
// An administrator can invite into another site through the switcher, and the
// account is created on that site's console, so the link must name that
// console's host instead of the one the administrator happens to be using.
// The port stays the one this request arrived on, because one listener serves
// every site's console.
func (s *Server) inviteOrigin(r *http.Request) string {
	origin := requestOrigin(r)
	site, err := s.st.SiteByID(s.db(r).SiteID())
	if err != nil || site == nil || strings.TrimSpace(site.ConsoleHost) == "" {
		return origin
	}
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(site.ConsoleHost, port)
	} else {
		u.Host = site.ConsoleHost
	}
	return u.Scheme + "://" + u.Host
}

// inviteInfo lets the signed-out invite page greet the recipient before asking
// for a username and password.
func (s *Server) inviteInfo(w http.ResponseWriter, r *http.Request) {
	inv, ok := s.db(r).InviteByToken(tokenDigest(strings.TrimSpace(r.URL.Query().Get("token"))))
	if !ok {
		writeError(w, http.StatusNotFound, "this invitation is invalid or has expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email": inv.Email, "first_name": inv.FirstName, "last_name": inv.LastName,
		"expires_at": inv.ExpiresAt,
	})
}

type inviteAccept struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// acceptInvite creates the administrator from an invitation. The account is
// enrolled with a new authenticator immediately, so the first sign-in and
// every later one need the second factor.
func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.Allow("invite:"+ip, 10, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in inviteAccept
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	token := strings.TrimSpace(in.Token)
	inv, ok := s.db(r).InviteByToken(tokenDigest(token))
	if !ok {
		writeError(w, http.StatusBadRequest, "this invitation is invalid or has expired")
		return
	}
	username := strings.TrimSpace(in.Username)
	if username == "" || len(username) > 64 {
		writeError(w, http.StatusBadRequest, "a username of 1–64 characters is required")
		return
	}
	role, err := s.db(r).RoleByID(inv.RoleID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the invited role no longer exists")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate authenticator secret")
		return
	}
	codes, stored, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate recovery codes")
		return
	}
	sealedSecret, err := s.box.Seal(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	sealedCodes, err := s.box.Seal(stored)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	id, err := s.db(r).CreateUserWithRole(username, hash, sealedSecret, sealedCodes, true, role.ID)
	if err != nil {
		writeError(w, http.StatusConflict, "that username is already taken")
		return
	}
	if err := s.db(r).SetUserEmail(id, inv.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save the email address")
		return
	}
	_ = s.db(r).DeleteInvite(tokenDigest(token))
	s.db(r).AddAudit(username, "user.invite.accept", inv.Email, ip)
	writeJSON(w, http.StatusCreated, map[string]any{
		"username": username, "totp_secret": secret,
		"otpauth_url":    auth.OTPAuthURL("WAF-Proxy", username, secret),
		"recovery_codes": codes,
	})
}
