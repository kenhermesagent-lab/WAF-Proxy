package updates

import "testing"

func TestRepoFromRemote(t *testing.T) {
	cases := map[string]string{
		"https://github.com/kenhermesagent-lab/WAF-Proxy-Docker.git":   "kenhermesagent-lab/waf-proxy-docker",
		"https://github.com/kenhermesagent-lab/WAF-Proxy-Docker":       "kenhermesagent-lab/waf-proxy-docker",
		"https://github.com/kenhermesagent-lab/WAF-Proxy-Docker/":      "kenhermesagent-lab/waf-proxy-docker",
		"git@github.com:kenhermesagent-lab/WAF-Proxy-Docker.git":       "kenhermesagent-lab/waf-proxy-docker",
		"ssh://git@github.com/kenhermesagent-lab/WAF-Proxy-Docker.git": "kenhermesagent-lab/waf-proxy-docker",
		"git://example.com/kenhermesagent-lab/WAF-Proxy-Docker.git":    "kenhermesagent-lab/waf-proxy-docker",
		"https://github.com/someone/else.git":                          "someone/else",
		"":                                                             "",
		"/local/path/only":                                             "",
	}
	for remote, want := range cases {
		if got := RepoFromRemote(remote); got != want {
			t.Errorf("RepoFromRemote(%q) = %q, want %q", remote, got, want)
		}
	}
}

// The helper must refuse a checkout whose origin is another repository,
// including one that merely shares a name in a different owner.
func TestRepoMatchesCompiledRepository(t *testing.T) {
	old := AppRepo
	AppRepo = "kenhermesagent-lab/WAF-Proxy-Docker"
	defer func() { AppRepo = old }()

	matching := []string{
		"https://github.com/kenhermesagent-lab/WAF-Proxy-Docker.git",
		"git@github.com:kenhermesagent-lab/WAF-Proxy-Docker.git",
		"https://github.com/kenhermesagent-lab/waf-proxy-docker",
	}
	for _, remote := range matching {
		if !RepoMatches(remote) {
			t.Errorf("%q did not match the compiled repository", remote)
		}
	}
	foreign := []string{
		"https://github.com/attacker/WAF-Proxy-Docker.git",
		"https://github.com/kenhermesagent-lab/WAF-Proxy-Docker-fork.git",
		"https://example.com/kenhermesagent-lab/other.git",
		"",
	}
	for _, remote := range foreign {
		if RepoMatches(remote) {
			t.Errorf("%q was accepted as the compiled repository", remote)
		}
	}
}
