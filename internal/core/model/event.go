package model

import "time"

type SecurityEvent struct {
	ID         int64     `json:"id"`
	Platform   string    `json:"platform"`
	EventTime  time.Time `json:"event_time"`
	EventType  string    `json:"event_type"`
	Severity   string    `json:"severity"`
	Actor      string    `json:"actor"`
	Target     string    `json:"target"`
	SourceIP   string    `json:"source_ip"`
	RawMessage string    `json:"raw_message"`
}

type SecurityEventStats struct {
	TotalEvents int            `json:"total_events"`
	ByType      map[string]int `json:"by_type"`
	BySeverity  map[string]int `json:"by_severity"`
}
