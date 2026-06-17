package service

import (
	"testing"

	"openlist-secure-platform/internal/core/model"
)

func TestEventServiceBuildAlertsForMultipleLoginFailures(t *testing.T) {
	policy := model.DefaultSecurityPolicy()
	policy.MultipleLoginFailuresThreshold = 3
	service := NewEventService(nil, nil, nil, testPolicyReader{policy: policy})

	events := []model.SecurityEvent{
		{ID: 1, EventType: "login_failed", Severity: "medium"},
		{ID: 2, EventType: "login_failed", Severity: "medium"},
		{ID: 3, EventType: "login_failed", Severity: "medium"},
	}

	alerts := service.buildAlerts(events, "/tmp/openlist.log")
	if len(alerts) != 1 {
		t.Fatalf("len(alerts) = %d, want 1", len(alerts))
	}
	if alerts[0].AlertType != "multiple_login_failures" {
		t.Fatalf("alerts[0].AlertType = %q, want multiple_login_failures", alerts[0].AlertType)
	}
	if alerts[0].Message != "An imported log batch contains 3 or more failed login events." {
		t.Fatalf("alerts[0].Message = %q", alerts[0].Message)
	}
}
