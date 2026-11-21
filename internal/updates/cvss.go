package updates

import (
	"math"
	"strconv"
	"strings"
)

// CVSSv3Score computes the CVSS v3.x base score from a vector. OSV publishes
// the vector rather than a numeric score, so this small parser is needed to
// rank advisories without an extra dependency.
func CVSSv3Score(vector string) (float64, bool) {
	const prefix = "CVSS:3."
	if !strings.HasPrefix(vector, prefix) {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(part, ":")
		if ok {
			metrics[strings.ToUpper(key)] = strings.ToUpper(value)
		}
	}
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	c, ok4 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
	i, ok5 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
	a, ok6 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}
	scopeChanged := metrics["S"] == "C"
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := prTable[metrics["PR"]]
	if !ok {
		return 0, false
	}
	impact := 1 - (1-c)*(1-i)*(1-a)
	if scopeChanged {
		impact = 7.52*(impact-0.029) - 3.25*math.Pow(impact-0.02, 15)
	} else {
		impact = 6.42 * impact
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	base := impact + exploitability
	if scopeChanged {
		base = 1.08 * base
	}
	base = math.Min(10, base)
	// CVSS v3.1 requires round-up to one decimal place.
	base = math.Ceil(base*10) / 10
	if _, err := strconv.ParseFloat(strconv.FormatFloat(base, 'f', 1, 64), 64); err != nil {
		return 0, false
	}
	return base, true
}
