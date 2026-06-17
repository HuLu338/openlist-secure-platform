package scoring

import (
	"testing"

	"openlist-secure-platform/internal/core/model"
)

func TestCalculateTotalScore(t *testing.T) {
	tests := []struct {
		name  string
		risks []model.RiskItem
		want  int
	}{
		{
			name: "no risks returns 100",
			want: 100,
		},
		{
			name:  "low risk subtracts 5",
			risks: []model.RiskItem{{Severity: "low"}},
			want:  95,
		},
		{
			name:  "medium risk subtracts 10",
			risks: []model.RiskItem{{Severity: "medium"}},
			want:  90,
		},
		{
			name:  "high risk subtracts 20",
			risks: []model.RiskItem{{Severity: "high"}},
			want:  80,
		},
		{
			name:  "critical risk subtracts 30",
			risks: []model.RiskItem{{Severity: "critical"}},
			want:  70,
		},
		{
			name: "score does not go below zero",
			risks: []model.RiskItem{
				{Severity: "critical"},
				{Severity: "critical"},
				{Severity: "critical"},
				{Severity: "critical"},
			},
			want: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CalculateTotalScore(test.risks)
			if got != test.want {
				t.Fatalf("CalculateTotalScore() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCalculateScoringBreakdown(t *testing.T) {
	risks := []model.RiskItem{
		{RuleID: "openlist-https-disabled", Severity: "high"},
		{RuleID: "openlist-logging-disabled", Severity: "low"},
	}

	breakdown := CalculateScoringBreakdown(risks)
	if breakdown.BaseScore != 100 {
		t.Fatalf("BaseScore = %d, want 100", breakdown.BaseScore)
	}
	if breakdown.TotalPenalty != 25 {
		t.Fatalf("TotalPenalty = %d, want 25", breakdown.TotalPenalty)
	}
	if breakdown.FinalScore != 75 {
		t.Fatalf("FinalScore = %d, want 75", breakdown.FinalScore)
	}
	if len(breakdown.Penalties) != 2 {
		t.Fatalf("len(Penalties) = %d, want 2", len(breakdown.Penalties))
	}
	if breakdown.Penalties[0].RuleID != "openlist-https-disabled" || breakdown.Penalties[0].Penalty != 20 {
		t.Fatalf("first penalty = %+v, want high severity penalty for openlist-https-disabled", breakdown.Penalties[0])
	}
}

func TestCalculateScoringBreakdownNeverBelowZero(t *testing.T) {
	risks := []model.RiskItem{
		{RuleID: "critical-1", Severity: "critical"},
		{RuleID: "critical-2", Severity: "critical"},
		{RuleID: "critical-3", Severity: "critical"},
		{RuleID: "critical-4", Severity: "critical"},
	}

	breakdown := CalculateScoringBreakdown(risks)
	if breakdown.FinalScore != 0 {
		t.Fatalf("FinalScore = %d, want 0", breakdown.FinalScore)
	}
	if breakdown.TotalPenalty != 120 {
		t.Fatalf("TotalPenalty = %d, want 120", breakdown.TotalPenalty)
	}
}
