package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// consumeRecoveryCode spends one single-use recovery code. The code hashes are
// encrypted at rest like the TOTP secret, so both the comparison and the rewrite
// have to go through the box; comparing the ciphertext directly would reject
// every code.
func (s *Server) consumeRecoveryCode(r *http.Request, user *store.User, candidate string) bool {
	plain, err := s.box.Open(user.Recovery)
	if err != nil {
		return false
	}
	remaining, used := auth.ConsumeRecoveryCode(plain, candidate)
	if !used {
		return false
	}
	sealed, err := s.box.Seal(remaining)
	if err != nil {
		return false
	}
	return s.db(r).UpdateUserRecovery(user.ID, sealed) == nil
}

// verifyAdminSecret checks the current password and, when enrolled, a live
// authenticator code. A recovery code is accepted as a fallback and consumed,
// because otherwise an operator who signed in with a recovery code could never
// rotate the lost factor from this page.
func (s *Server) verifyAdminSecret(r *http.Request, user *store.User, password, totp, recovery string) bool {
	if user == nil || !auth.VerifyPassword(user.PasswordHash, password) {
		return false
	}
	if !user.TOTPEnabled {
		return true
	}
	secret, err := s.box.Open(user.TOTPSecret)
	if err == nil && auth.ValidateTOTP(secret, totp, time.Now()) {
		return true
	}
	recovery = strings.TrimSpace(recovery)
	if recovery == "" {
		return false
	}
	return s.consumeRecoveryCode(r, user, recovery)
}

// clearPendingTOTP drops an unconfirmed rotation for a session. Credential
// changes and sign-outs must not leave a usable pending secret behind.
func (s *Server) clearPendingTOTP(sessionID string) {
	s.totpMu.Lock()
	delete(s.totpPending, sessionID)
	s.totpMu.Unlock()
}

func (s *Server) accountUser(w http.ResponseWriter, r *http.Request) (*store.User, *store.Session, bool) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil, false
	}
	user, err := s.db(r).UserByID(sess.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "account not found")
		return nil, nil, false
	}
	return user, sess, true
}

type passwordChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	TOTP            string `json:"totp"`
	Recovery        string `json:"recovery"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.accountUser(w, r)
	if !ok {
		return
	}
	if !s.limiter.Allow("account:"+user.Username, 10, 5*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in passwordChange
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !s.verifyAdminSecret(r, user, in.CurrentPassword, strings.TrimSpace(in.TOTP), in.Recovery) {
		writeError(w, http.StatusUnauthorized, "current password, authenticator code or recovery code is incorrect")
		return
	}
	if in.NewPassword == in.CurrentPassword {
		writeError(w, http.StatusBadRequest, "the new password must be different")
		return
	}
	hash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db(r).UpdateUserPassword(user.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update password")
		return
	}
	s.clearPendingTOTP(sess.ID)
	// Credential rotations invalidate every other browser. The current session
	// survives so the operator is not bounced out mid-change.
	revoked := true
	if err := s.db(r).DeleteOtherSessions(user.ID, sess.ID); err != nil {
		revoked = false
		s.log.Error("revoke sessions after password change", "err", err)
	}
	s.limiter.Reset("account:" + user.Username)
	s.db(r).AddAudit(user.Username, "account.password", fmt.Sprintf("other sessions revoked: %t", revoked), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "other_sessions_revoked": revoked})
}

type totpBegin struct {
	CurrentPassword string `json:"current_password"`
	TOTP            string `json:"totp"`
	Recovery        string `json:"recovery"`
}

// beginTOTP verifies the current factor and returns a new secret. Nothing is
// stored until confirmTOTP proves the authenticator has accepted it, so a
// mistake cannot lock the administrator out.
func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.accountUser(w, r)
	if !ok {
		return
	}
	if !s.limiter.Allow("account:"+user.Username, 10, 5*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in totpBegin
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if !s.verifyAdminSecret(r, user, in.CurrentPassword, strings.TrimSpace(in.TOTP), in.Recovery) {
		writeError(w, http.StatusUnauthorized, "current password, authenticator code or recovery code is incorrect")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate secret")
		return
	}
	now := time.Now()
	s.totpMu.Lock()
	for id, p := range s.totpPending {
		if now.After(p.expires) {
			delete(s.totpPending, id)
		}
	}
	s.totpPending[sess.ID] = pendingTOTP{secret: secret, userID: user.ID, expires: now.Add(5 * time.Minute)}
	s.totpMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_url": auth.OTPAuthURL("WAF-Proxy", user.Username, secret),
	})
}

type totpConfirm struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.accountUser(w, r)
	if !ok {
		return
	}
	if !s.limiter.Allow("account:"+user.Username, 10, 5*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in totpConfirm
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	s.totpMu.Lock()
	pending, found := s.totpPending[sess.ID]
	delete(s.totpPending, sess.ID)
	s.totpMu.Unlock()
	if !found || pending.userID != user.ID || time.Now().After(pending.expires) {
		writeError(w, http.StatusBadRequest, "start the rotation again")
		return
	}
	in.Secret = strings.ToUpper(strings.TrimSpace(in.Secret))
	if in.Secret != pending.secret {
		writeError(w, http.StatusBadRequest, "start the rotation again")
		return
	}
	if !auth.ValidateTOTP(pending.secret, strings.TrimSpace(in.Code), time.Now()) {
		writeError(w, http.StatusBadRequest, "the new authenticator code is not valid")
		return
	}
	sealed, err := s.box.Seal(in.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	codes, stored, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate recovery codes")
		return
	}
	sealedCodes, err := s.box.Seal(stored)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption error")
		return
	}
	if err := s.db(r).UpdateUserTOTP(user.ID, sealed, sealedCodes, true); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update authenticator")
		return
	}
	revoked := true
	if err := s.db(r).DeleteOtherSessions(user.ID, sess.ID); err != nil {
		revoked = false
		s.log.Error("revoke sessions after TOTP change", "err", err)
	}
	s.limiter.Reset("account:" + user.Username)
	s.db(r).AddAudit(user.Username, "account.totp", fmt.Sprintf("authenticator rotated; other sessions revoked: %t", revoked), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "recovery_codes": codes, "other_sessions_revoked": revoked,
	})
}

func (s *Server) logoutAll(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.accountUser(w, r)
	if !ok {
		return
	}
	if err := s.db(r).DeleteUserSessions(user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot revoke sessions")
		return
	}
	if sess := sessionFrom(r); sess != nil {
		s.clearPendingTOTP(sess.ID)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	s.db(r).AddAudit(user.Username, "account.logout_all", "all sessions revoked", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
