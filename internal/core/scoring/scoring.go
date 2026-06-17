package scoring

import "openlist-secure-platform/internal/core/model"

const BaseScore = 100

func CalculateTotalScore(risks []model.RiskItem) int {
	return CalculateScoringBreakdown(risks).FinalScore
}

func CalculateScoringBreakdown(risks []model.RiskItem) model.ScoringBreakdown {
	breakdown := model.ScoringBreakdown{
		BaseScore: BaseScore,
		Penalties: make([]model.ScoringPenalty, 0, len(risks)),
	}

	for _, risk := range risks {
		penalty := PenaltyForSeverity(risk.Severity)
		breakdown.TotalPenalty += penalty
		breakdown.Penalties = append(breakdown.Penalties, model.ScoringPenalty{
			RuleID:   risk.RuleID,
			Severity: risk.Severity,
			Penalty:  penalty,
			Reason:   risk.Severity + " severity finding",
		})
	}

	breakdown.FinalScore = breakdown.BaseScore - breakdown.TotalPenalty
	if breakdown.FinalScore < 0 {
		breakdown.FinalScore = 0
	}

	return breakdown
}

func PenaltyForSeverity(severity string) int {
	switch severity {
	case "critical":
		return 30
	case "high":
		return 20
	case "medium":
		return 10
	case "low":
		return 5
	default:
		return 5
	}
}
