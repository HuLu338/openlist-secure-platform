package model

import "time"

type SecurityRule struct {
	ID             int64     `json:"id"`
	RuleID         string    `json:"rule_id"`
	Platform       string    `json:"platform"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	Category       string    `json:"category"`
	Enabled        bool      `json:"enabled"`
	Description    string    `json:"description"`
	Recommendation string    `json:"recommendation"`
	UpdatedAt      time.Time `json:"updated_at"`
}
