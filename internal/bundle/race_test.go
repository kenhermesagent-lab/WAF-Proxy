package bundle

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

// The console polls Status, Rules and RuleIndex while the refresh loop is
// installing, and a 304 must still record the check without losing the packs.
func TestChecksAreSafeAgainstReaders(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	manifest, rawPack := signedChannel(t, priv, 1, testPack("2026.11.23-04"))
	srv := (&channel{manifest: manifest, packs: map[string][]byte{"/packs/cve-2026-11.json": rawPack}}).serve()
	defer srv.Close()

	m := newTestManager(t, t.TempDir(), srv.URL+"/manifest.json", pub)
	m.OnChange(func() {})

	const readers = 4
	stop := make(chan struct{})
	ready := make(chan struct{}, readers)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				m.Status()
				m.Rules()
				m.RuleIndex()
				_ = m.Enabled()
				if first {
					ready <- struct{}{}
					first = false
				}
			}
		}()
	}
	for i := 0; i < readers; i++ {
		<-ready
	}

	var checkErr error
	for i := 0; i < 5; i++ {
		if err := m.Check(context.Background()); err != nil {
			checkErr = err
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if checkErr != nil {
		t.Fatal(checkErr)
	}
	if got := len(m.Rules()); got != 1 {
		t.Fatalf("installed packs = %d, want 1", got)
	}
}

// Start is the production entry point: one goroutine that checks, then ticks.
// Cancelling the context must stop it while the console keeps reading state.
func TestStartStopsOnCancel(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	manifest, rawPack := signedChannel(t, priv, 1, testPack("2026.11.23-04"))
	srv := (&channel{manifest: manifest, packs: map[string][]byte{"/packs/cve-2026-11.json": rawPack}}).serve()
	defer srv.Close()

	m := newTestManager(t, t.TempDir(), srv.URL+"/manifest.json", pub)
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Providers[0].LastCheck == nil {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the refresh loop never checked the channel")
		}
		m.Status()
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}
