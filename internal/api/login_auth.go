package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

const (
	deviceCookie = "__wfp_device"
	deviceTTL    = 30 * 24 * time.Hour
	resetTTL     = 30 * time.Minute
)

// tokenDigest is what the database stores for a device or reset token.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// trustedDeviceUser reports whether the request carries a live device cookie
// issued to this administrator, which stands in for the authenticator code.
func (s *Server) trustedDeviceUser(r *http.Request, userID int64) bool {
	c, err := r.Cookie(deviceCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got, ok := s.db(r).TrustedDeviceUser(tokenDigest(c.Value))
	return ok && got == userID
}

// rememberDevice issues a new trusted-device cookie. Only the digest is
// stored, so the database never holds a usable token.
func (s *Server) rememberDevice(w http.ResponseWriter, r *http.Request, userID int64) {
	token, err := wfcrypto.RandomToken(32)
	if err != nil {
		return
	}
	expires := time.Now().Add(deviceTTL)
	if err := s.db(r).CreateTrustedDevice(tokenDigest(token), userID, r.UserAgent(), clientIP(r), expires); err != nil {
		s.log.Warn("remember device", "err", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: deviceCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		Expires: expires, MaxAge: int(deviceTTL.Seconds()),
	})
}

// requestOrigin is the console origin as the browser reached it, used to build
// the link in a reset email.
func requestOrigin(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	// The panel proxy terminates TLS before forwarding to the console.
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

func (s *Server) emailConfigured() bool {
	return s.notify != nil && s.notify.EmailConfigured()
}

// forgotAvailable tells the signed-out login form whether to offer the link.
func (s *Server) forgotAvailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"available": s.emailConfigured()})
}

type forgotRequest struct {
	Username string `json:"username"`
}

// forgotPassword sends a single-use reset link to the administrator's own
// address. It answers the same way for an unknown name or an account with no
// address, so the endpoint cannot be used to enumerate administrators.
func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.Allow("forgot:"+ip, 5, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	if !s.emailConfigured() {
		writeError(w, http.StatusBadRequest, "email notifications are not configured")
		return
	}
	var in forgotRequest
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	user, err := s.db(r).UserByUsername(strings.TrimSpace(in.Username))
	if err == nil && user != nil && strings.TrimSpace(user.Email) != "" {
		token, terr := wfcrypto.RandomToken(32)
		if terr == nil && s.db(r).CreatePasswordReset(tokenDigest(token), user.ID, time.Now().Add(resetTTL)) == nil {
			link := requestOrigin(r) + "/#/reset-password?token=" + url.QueryEscape(token)
			text := fmt.Sprintf("Someone asked to reset the WAF-Proxy console password for %q.\n\n"+
				"Open this link within 30 minutes to choose a new password:\n\n%s\n\n"+
				"If you did not ask for this, ignore the message; the password is unchanged.\n", user.Username, link)
			if serr := s.notify.SendMailTo([]string{user.Email}, "Reset your WAF-Proxy console password", text); serr != nil {
				s.log.Warn("password reset email", "err", serr)
			} else {
				s.db(r).AddAudit(user.Username, "account.forgot", "reset email sent", ip)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

type resetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.Allow("reset:"+ip, 10, 15*time.Minute) {
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var in resetRequest
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	userID, ok := s.db(r).ConsumePasswordReset(tokenDigest(strings.TrimSpace(in.Token)))
	if !ok {
		writeError(w, http.StatusBadRequest, "this reset link is invalid or has expired")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.db(r).UserByID(userID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "this reset link is invalid or has expired")
		return
	}
	if err := s.db(r).UpdateUserPassword(user.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot update password")
		return
	}
	if err := s.db(r).DeleteUserSessions(user.ID); err != nil {
		s.log.Error("revoke sessions after password reset", "err", err)
	}
	if err := s.db(r).DeleteUserTrustedDevices(user.ID); err != nil {
		s.log.Error("forget devices after password reset", "err", err)
	}
	s.db(r).AddAudit(user.Username, "account.reset", "password reset by email link", ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
