package updates

import (
	"net/url"
	"strings"
)

// RepoFromRemote normalises a git remote URL to "owner/repository", so the
// helper can tell a checkout of the compiled repository from any other. It
// accepts the https, ssh and scp-like spellings git itself accepts.
func RepoFromRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	switch {
	case strings.Contains(remote, "://"):
		u, err := url.Parse(remote)
		if err != nil || u.Path == "" {
			return ""
		}
		remote = u.Path
	case strings.Contains(remote, "@") && strings.Contains(remote, ":"):
		// scp-like: git@github.com:owner/repository.git
		remote = remote[strings.Index(remote, ":")+1:]
	default:
		// A local path has no origin to compare.
		return ""
	}
	remote = strings.TrimSuffix(strings.TrimRight(remote, "/"), ".git")
	parts := strings.Split(strings.Trim(remote, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-2] + "/" + parts[len(parts)-1])
}

// RepoMatches reports whether a remote names the repository this binary was
// built from. The Update button rebuilds and installs as root, so pointing it
// at another origin would run that repository's code with the helper's rights.
func RepoMatches(remote string) bool {
	got := RepoFromRemote(remote)
	return got != "" && got == strings.ToLower(AppRepo)
}
