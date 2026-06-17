package model

import "time"

type APIAuditLog struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	ClientIP   string    `json:"client_ip"`
	UserAgent  string    `json:"user_agent"`
	APIKeyUsed bool      `json:"api_key_used"`
	Success    bool      `json:"success"`
}
