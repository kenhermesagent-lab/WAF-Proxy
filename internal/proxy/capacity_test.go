package proxy

import "testing"

func TestSiteCapRefusesBeyondLimit(t *testing.T) {
	l := newCapLimiter(2)
	first := l.acquire()
	second := l.acquire()
	if !first || !second {
		t.Fatal("the site budget refused a request below its limit")
	}
	if l.acquire() {
		t.Fatal("the site budget accepted a request past its limit")
	}
	l.release()
	if !l.acquire() {
		t.Fatal("the site budget did not free a slot on release")
	}
}

func TestZeroSiteCapInheritsTheGlobalBudget(t *testing.T) {
	l := newCapLimiter(0)
	for i := 0; i < 100; i++ {
		if !l.acquire() {
			t.Fatal("a zero site cap refused a request")
		}
	}
}

func TestClientCapIsPerClientAndCleansUp(t *testing.T) {
	l := newClientLimiter(1)
	if !l.acquire("198.51.100.1") {
		t.Fatal("first request of a client refused")
	}
	if l.acquire("198.51.100.1") {
		t.Fatal("second request of the same client accepted past the cap")
	}
	if !l.acquire("198.51.100.2") {
		t.Fatal("a different client was charged for the first client's requests")
	}
	l.release("198.51.100.1")
	if !l.acquire("198.51.100.1") {
		t.Fatal("the client slot was not released")
	}
	l.release("198.51.100.1")
	if len(l.counts) != 1 {
		t.Fatalf("idle client entries were not removed: %v", l.counts)
	}
}
