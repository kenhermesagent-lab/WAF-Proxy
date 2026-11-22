package proxy

import (
	"net/http"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func TestBotFilterRefusesScrapersBeforeTheChallenge(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SetSettings(map[string]string{
		"bot_filter":       "scrapers",
		"bot_filter_allow": "Googlebot",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}

	scraper := h.request(http.MethodGet, testHost, "/", "", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	})
	if scraper.Code != http.StatusForbidden {
		t.Fatalf("scraper status = %d, want 403", scraper.Code)
	}
	event := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "bot-filter" })
	if event.RuleID != "bot:ahrefsbot" {
		t.Fatalf("rule = %q, want bot:ahrefsbot", event.RuleID)
	}
	if h.hits.Load() != 0 {
		t.Fatalf("blocked scraper reached the upstream %d time(s)", h.hits.Load())
	}

	google := h.request(http.MethodGet, testHost, "/", "", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	})
	if google.Code != http.StatusOK {
		t.Fatalf("allowed crawler status = %d, want 200", google.Code)
	}
}
