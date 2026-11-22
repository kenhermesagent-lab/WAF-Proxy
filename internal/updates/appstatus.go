package updates

import "strings"

// AppStatus is the recorded checkout and installed updater scripts as the host
// sees them. A Docker install runs the console inside a container where /etc
// and /var/lib/waf-proxy are not the host's, so the console asks the root helper
// for this instead of stat()ing its own filesystem.
type AppStatus struct {
	SourceDir      string
	Mode           string
	CheckoutExists bool
	MissingScripts []string
}

// ReadAppStatus reports the recorded checkout and updater scripts on this host.
// It is called by the root helper, which is the only component that shares the
// installer's filesystem.
func ReadAppStatus() AppStatus {
	var st AppStatus
	values, err := ReadSelfUpdateConf(SelfUpdateConfFile())
	if err != nil {
		st.MissingScripts = MissingUpdateScripts()
		return st
	}
	st.SourceDir = strings.TrimSpace(values["WAFPROXY_UPDATE_SOURCE_DIR"])
	st.Mode = strings.TrimSpace(values["WAFPROXY_UPDATE_MODE"])
	st.CheckoutExists = st.SourceDir != "" && dirExists(st.SourceDir)
	st.MissingScripts = MissingUpdateScripts()
	return st
}
