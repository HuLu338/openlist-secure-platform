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

func TestEventServiceBuildAlertsForWebDAVAndAdminChanges(t *testing.T) {
	service := NewEventService(nil, nil, nil, testPolicyReader{policy: model.DefaultSecurityPolicy()})

	events := []model.SecurityEvent{
		{ID: 10, EventType: "webdav_write", Severity: "medium", RawMessage: "webdav write path=/webdav/docs/upload.txt user=alice"},
		{ID: 11, EventType: "webdav_manage", Severity: "high", RawMessage: "webdav manage permission path=/webdav user=admin"},
		{ID: 12, EventType: "admin_action", Severity: "high", RawMessage: "admin changed setting target=sharing_policy user=admin", Target: "sharing_policy"},
	}

	alerts := service.buildAlerts(events, "/tmp/openlist.log")
	counts := map[string]int{}
	for _, alert := range alerts {
		counts[alert.AlertType]++
	}

	if counts["risky_webdav_activity"] != 2 {
		t.Fatalf("risky_webdav_activity alerts = %d, want 2", counts["risky_webdav_activity"])
	}
	if counts["suspicious_admin_change"] != 1 {
		t.Fatalf("suspicious_admin_change alerts = %d, want 1", counts["suspicious_admin_change"])
	}
	if counts["high_severity_event"] != 2 {
		t.Fatalf("high_severity_event alerts = %d, want 2", counts["high_severity_event"])
	}
}
