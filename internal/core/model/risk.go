package model

import "time"

type RiskItem struct {
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Evidence       string `json:"evidence"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

type ScanRule struct {
	ID             string
	Title          string
	Severity       string
	Description    string
	Recommendation string
}

type ScanReport struct {
	ID                  int64            `json:"id"`
	Platform            string           `json:"platform"`
	ScanTime            time.Time        `json:"scan_time"`
	TargetPath          string           `json:"target_path"`
	TotalScore          int              `json:"total_score"`
	TriggeredRulesCount int              `json:"triggered_rules_count"`
	ScoringBreakdown    ScoringBreakdown `json:"scoring_breakdown"`
	Risks               []RiskItem       `json:"risks"`
}

type ScanReportSummary struct {
	ID                  int64     `json:"id"`
	Platform            string    `json:"platform"`
	ScanTime            time.Time `json:"scan_time"`
	TargetPath          string    `json:"target_path"`
	TotalScore          int       `json:"total_score"`
	TriggeredRulesCount int       `json:"triggered_rules_count"`
}

type ScoringBreakdown struct {
	BaseScore    int              `json:"base_score"`
	TotalPenalty int              `json:"total_penalty"`
	FinalScore   int              `json:"final_score"`
	Penalties    []ScoringPenalty `json:"penalties"`
}

type ScoringPenalty struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Penalty  int    `json:"penalty"`
	Reason   string `json:"reason"`
}
