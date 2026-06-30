package service

import (
	"testing"

	"openlist-secure-platform/internal/core/model"
)

type testPolicyReader struct {
	policy model.SecurityPolicy
}

func (r testPolicyReader) GetPolicy() (*model.SecurityPolicy, error) {
	return &r.policy, nil
}

func TestMapSeverityToPriority(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{severity: "critical", want: "high"},
		{severity: "high", want: "high"},
		{severity: "medium", want: "medium"},
		{severity: "low", want: "low"},
	}

	for _, test := range tests {
		t.Run(test.severity, func(t *testing.T) {
			got := mapSeverityToPriority(test.severity)
			if got != test.want {
				t.Fatalf("mapSeverityToPriority(%q) = %q, want %q", test.severity, got, test.want)
			}
		})
	}
}

func TestScanServiceBuildRecommendations(t *testing.T) {
	service := NewScanService(nil, nil, nil, nil, nil)
	report := &model.ScanReport{
		ID: 42,
		Risks: []model.RiskItem{
			{RuleID: "critical-rule", Title: "Critical", Severity: "critical", Recommendation: "Fix critical"},
			{RuleID: "high-rule", Title: "High", Severity: "high", Recommendation: "Fix high"},
			{RuleID: "medium-rule", Title: "Medium", Severity: "medium", Recommendation: "Fix medium"},
			{RuleID: "low-rule", Title: "Low", Severity: "low", Recommendation: "Fix low"},
		},
	}

	recommendations := service.buildRecommendations(report)
	wantPriorities := []string{"high", "high", "medium", "low"}

	if len(recommendations) != len(wantPriorities) {
		t.Fatalf("len(recommendations) = %d, want %d", len(recommendations), len(wantPriorities))
	}

	for i, recommendation := range recommendations {
		if recommendation.Priority != wantPriorities[i] {
			t.Fatalf("recommendations[%d].Priority = %q, want %q", i, recommendation.Priority, wantPriorities[i])
		}
		if recommendation.ScanReportID != report.ID {
			t.Fatalf("recommendations[%d].ScanReportID = %d, want %d", i, recommendation.ScanReportID, report.ID)
		}
		if recommendation.Status != "open" {
			t.Fatalf("recommendations[%d].Status = %q, want open", i, recommendation.Status)
		}
	}
}

func TestScanServiceBuildAlerts(t *testing.T) {
	policy := model.DefaultSecurityPolicy()
	policy.LowScoreThreshold = 70
	service := NewScanService(nil, nil, nil, nil, testPolicyReader{policy: policy})

	report := &model.ScanReport{
		ID:         7,
		TotalScore: 65,
		Risks: []model.RiskItem{
			{Severity: "critical"},
		},
	}

	alerts := service.buildAlerts(report)
	if len(alerts) != 2 {
		t.Fatalf("len(alerts) = %d, want 2", len(alerts))
	}

	if alerts[0].AlertType != "critical_risk_detected" {
		t.Fatalf("alerts[0].AlertType = %q, want critical_risk_detected", alerts[0].AlertType)
	}
	if alerts[1].AlertType != "low_security_score" {
		t.Fatalf("alerts[1].AlertType = %q, want low_security_score", alerts[1].AlertType)
	}
	if alerts[1].Message != "A scan produced a security score below the configured threshold (70)." {
		t.Fatalf("alerts[1].Message = %q", alerts[1].Message)
	}
}

func TestScanServiceBuildAlertsForTokenAndWebDAV(t *testing.T) {
	policy := model.DefaultSecurityPolicy()
	policy.LowScoreThreshold = 50
	service := NewScanService(nil, nil, nil, nil, testPolicyReader{policy: policy})

	report := &model.ScanReport{
		ID:         9,
		TotalScore: 80,
		Risks: []model.RiskItem{
			{RuleID: "openlist-token-validity-too-long", Severity: "medium"},
			{RuleID: "openlist-webdav-risky-access", Severity: "medium"},
		},
	}

	alerts := service.buildAlerts(report)
	wantTypes := map[string]bool{
		"long_token_validity":   false,
		"risky_webdav_activity": false,
	}

	for _, alert := range alerts {
		if _, ok := wantTypes[alert.AlertType]; ok {
			wantTypes[alert.AlertType] = true
		}
	}

	for alertType, seen := range wantTypes {
		if !seen {
			t.Fatalf("expected alert type %q was not generated", alertType)
		}
	}
}
