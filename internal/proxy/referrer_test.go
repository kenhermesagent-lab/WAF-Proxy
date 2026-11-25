package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The baseline must not be no-referrer. Under no-referrer a browser sends
// "Origin: null" on a same-origin HTML form post, and an app that verifies its
// own CSRF origin (Django, so Seafile's login) rejects the submit with a 403.
func TestBaselineReferrerPolicyKeepsOriginOnFormPosts(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &responseWriter{ResponseWriter: rec}
	w.WriteHeader(http.StatusOK)
	if got, want := rec.Header().Get("Referrer-Policy"), "strict-origin-when-cross-origin"; got != want {
		t.Fatalf("Referrer-Policy = %q, want %q", got, want)
	}
}

// A protection profile still replaces the baseline, which is how an existing
// proxy changes the policy without a rebuild.
func TestProtectionProfileOverridesReferrerPolicy(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &responseWriter{
		ResponseWriter: rec,
		protection:     &model.ProtectionProfile{ReferrerPolicy: "same-origin"},
	}
	w.WriteHeader(http.StatusOK)
	if got, want := rec.Header().Get("Referrer-Policy"), "same-origin"; got != want {
		t.Fatalf("Referrer-Policy = %q, want %q", got, want)
	}
}
