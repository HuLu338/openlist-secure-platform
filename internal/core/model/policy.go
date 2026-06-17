package model

import "time"

type SecurityPolicy struct {
	ID                             int64     `json:"id"`
	LowScoreThreshold              int       `json:"low_score_threshold"`
	MultipleLoginFailuresThreshold int       `json:"multiple_login_failures_threshold"`
	LongTokenHoursThreshold        int       `json:"long_token_hours_threshold"`
	UpdatedAt                      time.Time `json:"updated_at"`
}

func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		ID:                             1,
		LowScoreThreshold:              60,
		MultipleLoginFailuresThreshold: 3,
		LongTokenHoursThreshold:        168,
		UpdatedAt:                      time.Now(),
	}
}
