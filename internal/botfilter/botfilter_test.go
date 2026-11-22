package botfilter

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		ua   string
		want Category
	}{
		{"Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/130.0", CategoryBrowser},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", CategorySearch},
		{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", CategorySocial},
		{"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", CategoryScraper},
		{"MyCrawler/1.0", CategoryBot},
		{"", CategoryEmpty},
	}
	for _, tc := range cases {
		if got, _ := Classify(tc.ua); got != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.ua, got, tc.want)
		}
	}
}

func TestBlockedModes(t *testing.T) {
	scraper := "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"
	if blocked, _ := Blocked(scraper, ModeOff, ""); blocked {
		t.Fatal("off mode must not block")
	}
	if blocked, rule := Blocked(scraper, ModeScrapers, DefaultAllow); !blocked || rule != "semrushbot" {
		t.Fatalf("scrapers mode = %v %q, want block by semrushbot", blocked, rule)
	}
	google := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if blocked, _ := Blocked(google, ModeAll, DefaultAllow); blocked {
		t.Fatal("the default allow list must keep Googlebot")
	}
	if blocked, _ := Blocked("", ModeScrapers, ""); blocked {
		t.Fatal("scrapers mode must not block an empty agent")
	}
	if blocked, rule := Blocked("", ModeAll, ""); !blocked || rule != "empty user agent" {
		t.Fatalf("all mode on an empty agent = %v %q", blocked, rule)
	}
	if blocked, _ := Blocked(scraper, ModeAll, "semrush"); blocked {
		t.Fatal("an allow-list fragment must exempt a scraper")
	}
}
