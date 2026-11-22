package store

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func providerFixture() *model.AuthProvider {
	return &model.AuthProvider{
		Name: "home", Kind: "authelia", VerifyURL: "http://authelia:9091/api/verify",
		Header: "X-Wafproxy-Auth", Secret: "sealed",
	}
}

func TestAuthProviderLifecycle(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateAuthProvider(providerFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAuthProvider(providerFixture()); err != ErrDuplicate {
		t.Fatalf("duplicate name error = %v, want ErrDuplicate", err)
	}
	got, err := st.GetAuthProvider(id)
	if err != nil || got.Name != "home" || !got.HasSecret {
		t.Fatalf("provider = %+v, err = %v", got, err)
	}
	got.LoginURL = "https://auth.example.com/portal"
	if err := st.UpdateAuthProvider(got); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.GetAuthProvider(id); again.LoginURL != "https://auth.example.com/portal" {
		t.Fatalf("login url not saved: %q", again.LoginURL)
	}
	if used, err := st.DeleteAuthProvider(id); err != nil || used {
		t.Fatalf("delete unused: used=%v err=%v", used, err)
	}
	if _, err := st.GetAuthProvider(id); err != ErrNotFound {
		t.Fatalf("provider still present: %v", err)
	}
}

func TestAuthProviderInUseIsNotDeleted(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateAuthProvider(providerFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true, GateMode: "off"}); err != nil {
		t.Fatal(err)
	}
	proxies, err := st.ListProxies()
	if err != nil || len(proxies) != 1 {
		t.Fatalf("proxies = %v, err = %v", proxies, err)
	}
	proxies[0].GateMode = "forward_auth"
	proxies[0].AuthProviderID = &id
	if err := st.UpdateProxy(&proxies[0]); err != nil {
		t.Fatal(err)
	}
	if reloaded, _ := st.GetProxy(proxies[0].ID); reloaded.AuthProviderID == nil || *reloaded.AuthProviderID != id {
		t.Fatalf("proxy provider id not persisted: %+v", reloaded)
	}
	used, err := st.DeleteAuthProvider(id)
	if err != nil || !used {
		t.Fatalf("delete in-use: used=%v err=%v", used, err)
	}
	if _, err := st.GetAuthProvider(id); err != nil {
		t.Fatalf("an in-use provider must survive: %v", err)
	}
}
