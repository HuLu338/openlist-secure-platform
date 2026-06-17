package contracts

import "openlist-secure-platform/internal/core/model"

type ScanReportStore interface {
	SaveScanReport(report *model.ScanReport) error
}

type ScanReportReader interface {
	GetLatestScanReport() (*model.ScanReport, error)
	ListScanReports() ([]model.ScanReportSummary, error)
	ListScanReportsFiltered(minScore, maxScore *int, targetPath string) ([]model.ScanReportSummary, error)
	GetScanReportByID(id int64) (*model.ScanReport, error)
}

type SecurityEventStore interface {
	SaveSecurityEvents(events []model.SecurityEvent) error
	DeleteAllSecurityEvents() error
}

type SecurityEventReader interface {
	ListSecurityEvents() ([]model.SecurityEvent, error)
	ListSecurityEventsFiltered(eventType, severity, actor string) ([]model.SecurityEvent, error)
	GetLatestSecurityEvent() (*model.SecurityEvent, error)
	GetSecurityEventByID(id int64) (*model.SecurityEvent, error)
	GetSecurityEventStats() (*model.SecurityEventStats, error)
}

type AlertStore interface {
	SaveAlerts(alerts []model.Alert) error
	CloseAlert(id int64) error
}

type AlertReader interface {
	ListAlerts() ([]model.Alert, error)
	ListAlertsFiltered(status, severity, alertType string) ([]model.Alert, error)
	GetLatestAlert() (*model.Alert, error)
	GetAlertByID(id int64) (*model.Alert, error)
}

type SecurityRuleReader interface {
	ListSecurityRules() ([]model.SecurityRule, error)
	GetSecurityRule(ruleID string) (*model.SecurityRule, error)
}

type SecurityRuleStore interface {
	UpdateSecurityRule(ruleID string, enabled *bool, severity string) error
}

type DashboardReader interface {
	GetDashboardSummary() (*model.DashboardSummary, error)
}

type AnalyticsReader interface {
	GetRiskTrend() ([]model.RiskTrendItem, error)
	GetTopRiskRules() ([]model.TopRiskRuleItem, error)
	GetAlertAnalyticsSummary() (*model.AlertAnalyticsSummary, error)
}

type RecommendationStore interface {
	SaveRecommendations(recommendations []model.Recommendation) error
	UpdateRecommendationStatus(id int64, status string) error
}

type RecommendationReader interface {
	ListRecommendationsFiltered(status, priority string, scanReportID *int64) ([]model.Recommendation, error)
	GetLatestRecommendations() ([]model.Recommendation, error)
	GetRecommendationsByScanID(scanID int64) ([]model.Recommendation, error)
	GetRecommendationByID(id int64) (*model.Recommendation, error)
}

type PolicyReader interface {
	GetPolicy() (*model.SecurityPolicy, error)
}

type PolicyStore interface {
	UpdatePolicy(policy *model.SecurityPolicy) error
}

type APIAuditLogStore interface {
	SaveAPIAuditLog(log model.APIAuditLog) error
}

type APIAuditLogReader interface {
	ListAPIAuditLogs() ([]model.APIAuditLog, error)
	ListAPIAuditLogsFiltered(method string, statusCode *int, success *bool, apiKeyUsed *bool, path string) ([]model.APIAuditLog, error)
	GetLatestAPIAuditLog() (*model.APIAuditLog, error)
}

type DevelopmentResetStore interface {
	DeleteAllSecurityEvents() error
	DeleteAllAlerts() error
	DeleteAllAPIAuditLogs() error
	DeleteAllRecommendations() error
}
