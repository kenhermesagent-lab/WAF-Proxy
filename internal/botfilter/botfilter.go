// Package botfilter classifies user agents and decides whether a request is a
// bot the operator asked to refuse. It complements the proof-of-work challenge:
// a challenge stops automation, a filter refuses categories outright.
package botfilter

import "strings"

// Filter modes stored in the bot_filter setting.
const (
	ModeOff      = "off"
	ModeScrapers = "scrapers" // known SEO/marketing crawlers
	ModeAll      = "all"      // scrapers, empty agents and any unlisted declared bot
)

// Category is what a user agent looks like.
type Category string

const (
	CategoryBrowser Category = "browser"
	CategorySearch  Category = "search-engine"
	CategorySocial  Category = "social-preview"
	CategoryScraper Category = "scraper"
	CategoryBot     Category = "declared-bot"
	CategoryEmpty   Category = "empty"
)

// scraperTokens are marketing, SEO and AI-training crawlers that rarely bring
// a visitor and often ignore robots.txt.
var scraperTokens = []string{
	"ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot", "bytespider",
	"ccbot", "blexbot", "dataforseo", "serpstatbot", "screaming frog",
	"seznambot", "megaindex", "linkdexbot", "contentking", "zoominfobot",
	"gptbot", "claudebot", "anthropic-ai", "perplexitybot", "amazonbot",
}

// searchTokens are crawlers most operators want to keep.
var searchTokens = []string{
	"googlebot", "google-inspectiontool", "bingbot", "bingpreview", "duckduckbot",
	"applebot", "baiduspider", "yandexbot", "yandeximages", "slurp",
}

// socialTokens preview links and should keep working when a site is shared.
var socialTokens = []string{
	"facebookexternalhit", "twitterbot", "linkedinbot", "slackbot", "discordbot",
	"telegrambot", "whatsapp", "pinterest", "embedly", "skypeuripreview",
}

// DefaultAllow is the allow list a new install starts with: a scraper rule must
// never take a real search crawler down with it.
const DefaultAllow = "Googlebot, Bingbot, DuckDuckBot, Applebot, facebookexternalhit, Twitterbot, Slackbot"

// Classify returns the category and the matched token for a user agent.
func Classify(ua string) (Category, string) {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return CategoryEmpty, ""
	}
	if token, ok := match(ua, scraperTokens); ok {
		return CategoryScraper, token
	}
	if token, ok := match(ua, searchTokens); ok {
		return CategorySearch, token
	}
	if token, ok := match(ua, socialTokens); ok {
		return CategorySocial, token
	}
	for _, token := range []string{"bot", "spider", "crawler", "crawl"} {
		if strings.Contains(ua, token) {
			return CategoryBot, token
		}
	}
	return CategoryBrowser, ""
}

// Blocked reports whether a request with this user agent should be refused and
// which rule matched. An allow-list entry (case-insensitive substring) always
// wins, so an operator can exempt a crawler the default rules would catch.
func Blocked(ua, mode, allow string) (bool, string) {
	if mode != ModeScrapers && mode != ModeAll {
		return false, ""
	}
	if allowed(ua, allow) {
		return false, ""
	}
	category, token := Classify(ua)
	switch mode {
	case ModeScrapers:
		if category == CategoryScraper {
			return true, token
		}
	case ModeAll:
		switch category {
		case CategoryScraper, CategoryBot:
			return true, token
		case CategoryEmpty:
			return true, "empty user agent"
		}
	}
	return false, ""
}

func match(ua string, tokens []string) (string, bool) {
	for _, token := range tokens {
		if strings.Contains(ua, token) {
			return token, true
		}
	}
	return "", false
}

func allowed(ua, allow string) bool {
	ua = strings.ToLower(ua)
	for _, part := range strings.Split(allow, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" && strings.Contains(ua, part) {
			return true
		}
	}
	return false
}
