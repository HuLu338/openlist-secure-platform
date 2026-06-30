package service

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
)

type EventService struct {
	Collector    contracts.LogCollector
	Store        contracts.SecurityEventStore
	Alerts       contracts.AlertStore
	PolicyReader contracts.PolicyReader
}

func NewEventService(
	collector contracts.LogCollector,
	store contracts.SecurityEventStore,
	alerts contracts.AlertStore,
	policyReader contracts.PolicyReader,
) *EventService {
	return &EventService{
		Collector:    collector,
		Store:        store,
		Alerts:       alerts,
		PolicyReader: policyReader,
	}
}

func (s *EventService) ImportEvents(logPath string) ([]model.SecurityEvent, error) {
	if s.Collector == nil {
		return nil, errors.New("log collector is not configured")
	}

	if s.Store == nil {
		return nil, errors.New("security event store is not configured")
	}

	if logPath == "" {
		return nil, errors.New("log path is required")
	}

	events, err := s.Collector.ParseLogFile(logPath)
	if err != nil {
		return nil, err
	}

	if err := s.Store.SaveSecurityEvents(events); err != nil {
		return nil, err
	}

	if s.Alerts != nil {
		alerts := s.buildAlerts(events, logPath)
		if err := s.Alerts.SaveAlerts(alerts); err != nil {
			return nil, err
		}
	}

	// TODO: add event deduplication for repeated log imports.
	return events, nil
}

func (s *EventService) DeleteAllEvents() error {
	if s.Store == nil {
		return errors.New("security event store is not configured")
	}

	// TODO: keep audit metadata for cleanup actions in a later phase.
	return s.Store.DeleteAllSecurityEvents()
}

func (s *EventService) buildAlerts(events []model.SecurityEvent, logPath string) []model.Alert {
	alerts := make([]model.Alert, 0)
	loginFailedCount := 0
	loginFailedThreshold := s.loginFailedThreshold()

	for _, event := range events {
		if event.EventType == "login_failed" {
			loginFailedCount++
		}

		sourceRef := strconv.FormatInt(event.ID, 10)
		if isRiskyWebDAVEvent(event) {
			alerts = append(alerts, model.Alert{
				SourceType: "event",
				SourceRef:  sourceRef,
				AlertType:  "risky_webdav_activity",
				Severity:   event.Severity,
				Message:    "A risky WebDAV security event was imported.",
				Status:     "open",
				CreatedAt:  time.Now(),
			})
		}

		if isSuspiciousAdminChange(event) {
			alerts = append(alerts, model.Alert{
				SourceType: "event",
				SourceRef:  sourceRef,
				AlertType:  "suspicious_admin_change",
				Severity:   "high",
				Message:    "A sensitive administrative change was imported and should be reviewed.",
				Status:     "open",
				CreatedAt:  time.Now(),
			})
		}

		if event.Severity == "high" {
			alerts = append(alerts, model.Alert{
				SourceType: "event",
				SourceRef:  sourceRef,
				AlertType:  "high_severity_event",
				Severity:   "high",
				Message:    "A high severity security event was imported.",
				Status:     "open",
				CreatedAt:  time.Now(),
			})
		}
	}

	if loginFailedCount >= loginFailedThreshold {
		alerts = append(alerts, model.Alert{
			SourceType: "event",
			SourceRef:  "import:" + logPath,
			AlertType:  "multiple_login_failures",
			Severity:   "medium",
			Message:    fmt.Sprintf("An imported log batch contains %d or more failed login events.", loginFailedThreshold),
			Status:     "open",
			CreatedAt:  time.Now(),
		})
	}

	// TODO: add alert deduplication for repeated imports of the same log file.
	// TODO: integrate notification delivery after the alerting module matures.
	return alerts
}

func isRiskyWebDAVEvent(event model.SecurityEvent) bool {
	if !strings.HasPrefix(event.EventType, "webdav_") {
		return false
	}

	return event.Severity == "medium" || event.Severity == "high"
}

func isSuspiciousAdminChange(event model.SecurityEvent) bool {
	if event.EventType != "admin_action" {
		return false
	}

	combined := strings.ToLower(event.RawMessage + " " + event.Target)
	keywords := []string{
		"admin changed",
		"admin action",
		"changed setting",
		"auth",
		"permission",
		"policy",
		"security",
		"sharing",
		"storage",
		"token",
		"webdav",
	}

	for _, keyword := range keywords {
		if strings.Contains(combined, keyword) {
			return true
		}
	}

	return false
}

func (s *EventService) loginFailedThreshold() int {
	defaultPolicy := model.DefaultSecurityPolicy()
	if s.PolicyReader == nil {
		// TODO: centralize policy fallback handling across services.
		return defaultPolicy.MultipleLoginFailuresThreshold
	}

	policy, err := s.PolicyReader.GetPolicy()
	if err != nil || policy == nil {
		// TODO: add structured logging when policy loading falls back to defaults.
		return defaultPolicy.MultipleLoginFailuresThreshold
	}

	return policy.MultipleLoginFailuresThreshold
}
