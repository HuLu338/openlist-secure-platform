package model

import "time"

type Recommendation struct {
	ID             int64     `json:"id"`
	ScanReportID   int64     `json:"scan_report_id"`
	RuleID         string    `json:"rule_id"`
	Title          string    `json:"title"`
	Priority       string    `json:"priority"`
	Recommendation string    `json:"recommendation"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}
