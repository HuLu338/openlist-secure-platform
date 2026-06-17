package scoring

import "openlist-secure-platform/internal/core/model"

func CalculateTotalScore(risks []model.RiskItem) int {
	score := 100

	for _, risk := range risks {
		switch risk.Severity {
		case "critical":
			score -= 30
		case "high":
			score -= 20
		case "medium":
			score -= 10
		case "low":
			score -= 5
		default:
			score -= 5
		}
	}

	if score < 0 {
		return 0
	}

	return score
}
