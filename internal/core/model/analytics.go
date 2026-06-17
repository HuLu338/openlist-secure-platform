package model

import "time"

type RiskTrendItem struct {
	ScanID              int64     `json:"scan_id"`
	ScanTime            time.Time `json:"scan_time"`
	TotalScore          int       `json:"total_score"`
	TriggeredRulesCount int       `json:"triggered_rules_count"`
	TargetPath          string    `json:"target_path"`
}

type TopRiskRuleItem struct {
	RuleID       string `json:"rule_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	TriggerCount int    `json:"trigger_count"`
}

type AlertAnalyticsSummary struct {
	TotalAlerts  int            `json:"total_alerts"`
	OpenAlerts   int            `json:"open_alerts"`
	ClosedAlerts int            `json:"closed_alerts"`
	ByType       map[string]int `json:"by_type"`
	BySeverity   map[string]int `json:"by_severity"`
}
