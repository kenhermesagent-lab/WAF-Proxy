package notify

import (
	"encoding/json"
	"testing"
)

func TestNormalizeTelegramChat(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"-1001234567890":              "-1001234567890",
		"123456789":                   "123456789",
		"@channel":                    "@channel",
		"channel":                     "@channel",
		"https://t.me/channel":        "@channel",
		"http://t.me/channel/":        "@channel",
		"https://telegram.me/channel": "@channel",
		"https://t.me/@channel":       "@channel",
	}
	for in, want := range cases {
		if got := normalizeTelegramChat(in); got != want {
			t.Errorf("normalizeTelegramChat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTelegramPayloadUsesBooleanPreviewFlag(t *testing.T) {
	raw, err := json.Marshal(telegramMessage{
		ChatID:                "@channel",
		Text:                  "test",
		ParseMode:             "HTML",
		DisableWebPagePreview: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["disable_web_page_preview"] != true {
		t.Fatalf("disable_web_page_preview = %#v, want true", payload["disable_web_page_preview"])
	}
}

func TestEscapeTelegramHTML(t *testing.T) {
	if got, want := escapeTelegramHTML(`a & <b> "c"`), `a &amp; &lt;b&gt; "c"`; got != want {
		t.Fatalf("escapeTelegramHTML = %q, want %q", got, want)
	}
}
