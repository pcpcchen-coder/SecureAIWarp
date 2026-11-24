package manifest

import "strings"

// Risk is a mechanical score used only for comparison and ranking.
type Risk struct {
	Score int    `json:"score"`
	Level string `json:"level"` // 低 | 中 | 高
}

// RiskLevel maps a score to a level.
func RiskLevel(score int) string {
	switch {
	case score < 25:
		return "低"
	case score < 60:
		return "中"
	}
	return "高"
}

// ComputeRisk derives the risk score from the manifest. Weights are
// intentionally simple; see docs/04 §4 for the rationale.
func ComputeRisk(m *Manifest, res *Result) Risk {
	s := 0
	for _, f := range m.Files {
		kind, _, _ := PathVar(f.Path)
		switch {
		case kind == "USER_PICK" && f.Mode == "rw":
			s += 15
		case kind == "USER_PICK":
			s += 5
		case f.Mode == "rw":
			s += 2
		default:
			s++
		}
	}
	for _, e := range m.Network.Egress {
		s += 4
		if strings.HasPrefix(e.Host, "*.") {
			s += 15
		}
		if e.LAN {
			s += 20
		}
	}
	for _, in := range m.Network.Ingress {
		switch in.Expose {
		case "public":
			s += 30
		case "lan":
			s += 15
		default:
			s += 3
		}
	}
	for _, sec := range m.Secrets {
		if sec.Visibility == "app-visible" {
			s += 20
		} else {
			s += 3
		}
	}
	switch m.Runtime.Spawn {
	case "listed":
		s += 5
	case "any":
		s += 20
	}
	if m.AI != nil {
		for _, t := range m.AI.Tools {
			if t.Risk == "high" {
				s += 8
			} else {
				s++
			}
		}
		if m.AI.Budget != nil && m.AI.Budget.DailyUSD > 20 {
			s += 10
		}
		// Declared-only channel: assume the worst for what we cannot see.
		s += 5
	}
	if m.Data != nil && len(m.Data.Flows) > 0 {
		s += 5
	}
	s += 10 * len(m.Exceptions)
	return Risk{Score: s, Level: RiskLevel(s)}
}
