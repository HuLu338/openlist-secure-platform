package model

import "time"

type DashboardSummary struct {
	Platform     string       `json:"platform"`
	SystemStatus string       `json:"system_status"`
	ScanSummary  ScanSummary  `json:"scan_summary"`
	EventSummary EventSummary `json:"event_summary"`
	AlertSummary AlertSummary `json:"alert_summary"`
}

type ScanSummary struct {
	TotalScans                int        `json:"total_scans"`
	LatestScanTime            *time.Time `json:"latest_scan_time"`
	LatestScore               int        `json:"latest_score"`
	LatestTriggeredRulesCount int        `json:"latest_triggered_rules_count"`
}

type EventSummary struct {
	TotalEvents          int `json:"total_events"`
	HighSeverityEvents   int `json:"high_severity_events"`
	MediumSeverityEvents int `json:"medium_severity_events"`
	LowSeverityEvents    int `json:"low_severity_events"`
}

type AlertSummary struct {
	TotalAlerts     int    `json:"total_alerts"`
	OpenAlerts      int    `json:"open_alerts"`
	ClosedAlerts    int    `json:"closed_alerts"`
	LatestAlertType string `json:"latest_alert_type"`
}
