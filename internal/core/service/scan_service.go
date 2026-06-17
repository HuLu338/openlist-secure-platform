package service

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
	"openlist-secure-platform/internal/core/scoring"
)

type ScanService struct {
	Scanner         contracts.ConfigScanner
	Store           contracts.ScanReportStore
	Alerts          contracts.AlertStore
	Recommendations contracts.RecommendationStore
	PolicyReader    contracts.PolicyReader
}

func NewScanService(
	scanner contracts.ConfigScanner,
	store contracts.ScanReportStore,
	alerts contracts.AlertStore,
	recommendations contracts.RecommendationStore,
	policyReader contracts.PolicyReader,
) *ScanService {
	return &ScanService{
		Scanner:         scanner,
		Store:           store,
		Alerts:          alerts,
		Recommendations: recommendations,
		PolicyReader:    policyReader,
	}
}

func (s *ScanService) RunConfigScan(configPath string) (*model.ScanReport, error) {
	if s.Scanner == nil {
		return nil, errors.New("config scanner is not configured")
	}

	if configPath == "" {
		return nil, errors.New("config path is required")
	}

	report, err := s.Scanner.ScanConfig(configPath)
	if err != nil {
		return nil, err
	}

	if report == nil {
		return nil, errors.New("scan report is nil")
	}

	if report.ScanTime.IsZero() {
		report.ScanTime = time.Now()
	}

	report.TargetPath = configPath
	report.TriggeredRulesCount = len(report.Risks)
	report.TotalScore = scoring.CalculateTotalScore(report.Risks)

	if s.Store == nil {
		return nil, errors.New("scan report store is not configured")
	}

	if err := s.Store.SaveScanReport(report); err != nil {
		return nil, err
	}

	if s.Alerts != nil {
		alerts := s.buildAlerts(report)
		if err := s.Alerts.SaveAlerts(alerts); err != nil {
			return nil, err
		}
	}

	if s.Recommendations != nil {
		recommendations := s.buildRecommendations(report)
		if err := s.Recommendations.SaveRecommendations(recommendations); err != nil {
			return nil, err
		}
	}

	// TODO: attach scan history when history storage is implemented.
	// TODO: combine config scanning with log analysis in a later phase.
	return report, nil
}

func (s *ScanService) buildAlerts(report *model.ScanReport) []model.Alert {
	if report == nil {
		return nil
	}

	alerts := make([]model.Alert, 0)
	sourceRef := strconv.FormatInt(report.ID, 10)
	lowScoreThreshold := s.lowScoreThreshold()

	for _, risk := range report.Risks {
		if risk.Severity == "critical" {
			alerts = append(alerts, model.Alert{
				SourceType: "scan",
				SourceRef:  sourceRef,
				AlertType:  "critical_risk_detected",
				Severity:   "high",
				Message:    "A scan detected at least one critical security risk.",
				Status:     "open",
				CreatedAt:  time.Now(),
			})
			break
		}
	}

	if report.TotalScore < lowScoreThreshold {
		alerts = append(alerts, model.Alert{
			SourceType: "scan",
			SourceRef:  sourceRef,
			AlertType:  "low_security_score",
			Severity:   "medium",
			Message:    fmt.Sprintf("A scan produced a security score below the configured threshold (%d).", lowScoreThreshold),
			Status:     "open",
			CreatedAt:  time.Now(),
		})
	}

	// TODO: add alert deduplication for repeated low-score or critical-risk scans.
	// TODO: allow alert thresholds to be customized in future versions.
	return alerts
}

func (s *ScanService) lowScoreThreshold() int {
	defaultPolicy := model.DefaultSecurityPolicy()
	if s.PolicyReader == nil {
		// TODO: centralize policy fallback handling across services.
		return defaultPolicy.LowScoreThreshold
	}

	policy, err := s.PolicyReader.GetPolicy()
	if err != nil || policy == nil {
		// TODO: add structured logging when policy loading falls back to defaults.
		return defaultPolicy.LowScoreThreshold
	}

	return policy.LowScoreThreshold
}

func (s *ScanService) buildRecommendations(report *model.ScanReport) []model.Recommendation {
	if report == nil {
		return nil
	}

	recommendations := make([]model.Recommendation, 0, len(report.Risks))
	for _, risk := range report.Risks {
		recommendations = append(recommendations, model.Recommendation{
			ScanReportID:   report.ID,
			RuleID:         risk.RuleID,
			Title:          risk.Title,
			Priority:       mapSeverityToPriority(risk.Severity),
			Recommendation: risk.Recommendation,
			Status:         "open",
			CreatedAt:      time.Now(),
		})
	}

	// TODO: add recommendation deduplication and merging for repeated scans.
	// TODO: add remediation categories and platform-specific guidance.
	return recommendations
}

func mapSeverityToPriority(severity string) string {
	switch severity {
	case "critical", "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}
