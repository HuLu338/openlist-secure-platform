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
