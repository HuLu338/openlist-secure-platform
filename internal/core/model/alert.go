package model

import "time"

type Alert struct {
	ID         int64     `json:"id"`
	SourceType string    `json:"source_type"`
	SourceRef  string    `json:"source_ref"`
	AlertType  string    `json:"alert_type"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}
