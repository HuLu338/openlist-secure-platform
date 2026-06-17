package model

type AssistantRequest struct {
	Question string `json:"question"`
}

type AssistantResponse struct {
	Answer           string   `json:"answer"`
	Intent           string   `json:"intent"`
	Confidence       string   `json:"confidence"`
	Sources          []string `json:"sources"`
	SuggestedActions []string `json:"suggested_actions"`
}

type AssistantContext struct {
	HasLatestScan       bool `json:"has_latest_scan"`
	AlertCount          int  `json:"alert_count"`
	RecommendationCount int  `json:"recommendation_count"`
	RuleCount           int  `json:"rule_count"`
	AuditLogCount       int  `json:"audit_log_count"`
	EventCount          int  `json:"event_count"`
}

type AssistantSuggestion struct {
	Question string `json:"question"`
}

type AssistantChatRequest struct {
	Message string `json:"message"`
}

type AssistantChatResponse struct {
	Answer           string   `json:"answer"`
	Mode             string   `json:"mode"`
	Sources          []string `json:"sources"`
	SuggestedActions []string `json:"suggested_actions"`
}
