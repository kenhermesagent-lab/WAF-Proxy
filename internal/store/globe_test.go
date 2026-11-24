package store

import (
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// The globe splits a country into city dots once the map zooms in, so the
// aggregate has to keep the city the geoip database reported with the event.
func TestGlobeGroupsByCity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pid := testProxy(t, st, "app.example.com")
	now := time.Now().UTC()
	events := []model.Event{
		{TS: now.Add(-3 * time.Minute), ProxyID: &pid, Host: "app.example.com", SrcIP: "203.0.113.7",
			Country: "RU", City: "Moscow", Lat: 55.75, Lon: 37.61, Stage: "waf", Action: "block"},
		{TS: now.Add(-2 * time.Minute), ProxyID: &pid, Host: "app.example.com", SrcIP: "203.0.113.8",
			Country: "RU", City: "Moscow", Lat: 55.75, Lon: 37.61, Stage: "waf", Action: "block"},
		{TS: now.Add(-time.Minute), ProxyID: &pid, Host: "app.example.com", SrcIP: "203.0.113.9",
			Country: "RU", City: "Omsk", Lat: 54.99, Lon: 73.37, Stage: "waf", Action: "block"},
	}
	if err := st.InsertEvents(events); err != nil {
		t.Fatal(err)
	}
	points, err := st.Globe(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 {
		t.Fatalf("points = %+v", points)
	}
	if points[0].City != "Moscow" || points[0].Count != 2 {
		t.Fatalf("first point = %+v", points[0])
	}
	if points[1].City != "Omsk" {
		t.Fatalf("second point = %+v", points[1])
	}
	if points[0].Lat < 55 || points[0].Lat > 56 {
		t.Fatalf("latitude = %v", points[0].Lat)
	}
}

// A database without city data groups into one point per country rather than
// dropping the traffic.
func TestGlobeWithoutCityData(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pid := testProxy(t, st, "app.example.com")
	now := time.Now().UTC()
	if err := st.InsertEvents([]model.Event{{
		TS: now, ProxyID: &pid, Host: "app.example.com", SrcIP: "198.51.100.4",
		Country: "US", Lat: 38.0, Lon: -97.0, Stage: "waf", Action: "block",
	}}); err != nil {
		t.Fatal(err)
	}
	points, err := st.Globe(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 || points[0].City != "" || points[0].Country != "US" {
		t.Fatalf("points = %+v", points)
	}
}
