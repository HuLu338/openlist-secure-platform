package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
)

const (
	IntentSystemStatus           = "system_status"
	IntentLowScoreReason         = "low_score_reason"
	IntentFixPriority            = "fix_priority"
	IntentLatestAlertExplanation = "latest_alert_explanation"
	IntentSuspiciousAPIActivity  = "suspicious_api_activity"
	IntentRulePolicyExplanation  = "rule_policy_explanation"
	IntentGeneralHelp            = "general_help"
)

type AssistantService struct {
	DashboardReader      contracts.DashboardReader
	ScanReader           contracts.ScanReportReader
	AlertReader          contracts.AlertReader
	RecommendationReader contracts.RecommendationReader
	RuleReader           contracts.SecurityRuleReader
	PolicyReader         contracts.PolicyReader
	AuditReader          contracts.APIAuditLogReader
	EventReader          contracts.SecurityEventReader
	AssistantMode        string
	OpenAIAPIKey         string
	OpenAIModel          string
	HTTPClient           *http.Client
}

type AssistantOption func(*AssistantService)

func NewAssistantService(
	dashboardReader contracts.DashboardReader,
	scanReader contracts.ScanReportReader,
	alertReader contracts.AlertReader,
	recommendationReader contracts.RecommendationReader,
	ruleReader contracts.SecurityRuleReader,
	policyReader contracts.PolicyReader,
	auditReader contracts.APIAuditLogReader,
	eventReader contracts.SecurityEventReader,
	options ...AssistantOption,
) *AssistantService {
	service := &AssistantService{
		DashboardReader:      dashboardReader,
		ScanReader:           scanReader,
		AlertReader:          alertReader,
		RecommendationReader: recommendationReader,
		RuleReader:           ruleReader,
		PolicyReader:         policyReader,
		AuditReader:          auditReader,
		EventReader:          eventReader,
		AssistantMode:        "local",
		OpenAIModel:          "gpt-4.1-mini",
		HTTPClient:           &http.Client{Timeout: 20 * time.Second},
	}

	for _, option := range options {
		option(service)
	}

	if strings.TrimSpace(service.AssistantMode) == "" {
		service.AssistantMode = "local"
	}
	if strings.TrimSpace(service.OpenAIModel) == "" {
		service.OpenAIModel = "gpt-4.1-mini"
	}
	if service.HTTPClient == nil {
		service.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}

	return service
}

func WithAssistantGatewayConfig(mode string, openAIAPIKey string, openAIModel string) AssistantOption {
	return func(service *AssistantService) {
		service.AssistantMode = strings.ToLower(strings.TrimSpace(mode))
		service.OpenAIAPIKey = strings.TrimSpace(openAIAPIKey)
		service.OpenAIModel = strings.TrimSpace(openAIModel)
	}
}

func (s *AssistantService) Ask(question string) (*model.AssistantResponse, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		return nil, errors.New("question is required")
	}

	intent := DetectAssistantIntent(question)
	switch intent {
	case IntentSystemStatus:
		return s.answerSystemStatus()
	case IntentLowScoreReason:
		return s.answerLowScoreReason()
	case IntentFixPriority:
		return s.answerFixPriority()
	case IntentLatestAlertExplanation:
		return s.answerLatestAlertExplanation()
	case IntentSuspiciousAPIActivity:
		return s.answerSuspiciousAPIActivity()
	case IntentRulePolicyExplanation:
		return s.answerRulePolicyExplanation()
	default:
		return s.answerGeneralHelp(), nil
	}
}

func (s *AssistantService) Chat(message string) (*model.AssistantChatResponse, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, errors.New("message is required")
	}

	if strings.EqualFold(s.AssistantMode, "openai") {
		if s.OpenAIAPIKey == "" {
			log.Print("assistant openai mode requested but OPENAI_API_KEY is missing; falling back to local assistant")
			return s.localChat(message)
		}

		response, err := s.openAIChat(message)
		if err == nil {
			return response, nil
		}

		log.Printf("assistant OpenAI request failed; falling back to local assistant: %v", err)
		return s.localChat(message)
	}

	return s.localChat(message)
}

func (s *AssistantService) localChat(message string) (*model.AssistantChatResponse, error) {
	localResponse, err := s.Ask(message)
	if err != nil {
		return nil, err
	}

	return &model.AssistantChatResponse{
		Answer:           localResponse.Answer,
		Mode:             "local",
		Sources:          localResponse.Sources,
		SuggestedActions: localResponse.SuggestedActions,
	}, nil
}

func (s *AssistantService) Suggestions() []string {
	return []string{
		"What is the current security status?",
		"Why is the latest scan score low?",
		"What should I fix first?",
		"Explain the latest alert",
		"Are there suspicious API activities?",
		"How do current rules and policies affect scanning?",
	}
}

func (s *AssistantService) Context() (*model.AssistantContext, error) {
	context := &model.AssistantContext{}

	if s.ScanReader != nil {
		latestScan, err := s.ScanReader.GetLatestScanReport()
		if err != nil {
			return nil, err
		}
		context.HasLatestScan = latestScan != nil
	}

	if s.AlertReader != nil {
		alerts, err := s.AlertReader.ListAlerts()
		if err != nil {
			return nil, err
		}
		context.AlertCount = len(alerts)
	}

	if s.RecommendationReader != nil {
		recommendations, err := s.RecommendationReader.ListRecommendationsFiltered("", "", nil)
		if err != nil {
			return nil, err
		}
		context.RecommendationCount = len(recommendations)
	}

	if s.RuleReader != nil {
		rules, err := s.RuleReader.ListSecurityRules()
		if err != nil {
			return nil, err
		}
		context.RuleCount = len(rules)
	}

	if s.AuditReader != nil {
		auditLogs, err := s.AuditReader.ListAPIAuditLogs()
		if err != nil {
			return nil, err
		}
		context.AuditLogCount = len(auditLogs)
	}

	if s.EventReader != nil {
		stats, err := s.EventReader.GetSecurityEventStats()
		if err != nil {
			return nil, err
		}
		if stats != nil {
			context.EventCount = stats.TotalEvents
		}
	}

	return context, nil
}

func DetectAssistantIntent(question string) string {
	normalized := strings.ToLower(strings.TrimSpace(question))

	switch {
	case containsAny(normalized, "latest alert", "explain alert", "alert meaning", "why alert"):
		return IntentLatestAlertExplanation
	case containsAny(normalized, "why score low", "score low", "latest scan", "risk score", "scan result"):
		return IntentLowScoreReason
	case containsAny(normalized, "fix first", "priority", "what should i fix", "recommendation", "remediation"):
		return IntentFixPriority
	case containsAny(normalized, "suspicious", "unauthorized", "failed api", "audit", "401", "500"):
		return IntentSuspiciousAPIActivity
	case containsAny(normalized, "rule", "policy", "threshold", "disabled rule", "severity"):
		return IntentRulePolicyExplanation
	case containsAny(normalized, "status", "overview", "summary", "current security", "system health"):
		return IntentSystemStatus
	default:
		return IntentGeneralHelp
	}
}

func (s *AssistantService) answerSystemStatus() (*model.AssistantResponse, error) {
	sources := make([]string, 0)
	var builder strings.Builder
	confidence := "low"

	if s.DashboardReader != nil {
		summary, err := s.DashboardReader.GetDashboardSummary()
		if err != nil {
			return nil, err
		}
		if summary != nil {
			sources = append(sources, "dashboard_summary")
			confidence = "high"
			fmt.Fprintf(&builder, "Platform %s is currently marked %s. ", summary.Platform, summary.SystemStatus)
			fmt.Fprintf(&builder, "There are %d total scans, %d open alerts, and %d high severity events. ",
				summary.ScanSummary.TotalScans,
				summary.AlertSummary.OpenAlerts,
				summary.EventSummary.HighSeverityEvents,
			)
			if summary.ScanSummary.TotalScans > 0 {
				fmt.Fprintf(&builder, "The latest scan score is %d with %d triggered rules. ",
					summary.ScanSummary.LatestScore,
					summary.ScanSummary.LatestTriggeredRulesCount,
				)
			} else {
				builder.WriteString("No scan has been recorded yet. ")
			}
			builder.WriteString(securityPostureText(summary.ScanSummary.LatestScore, summary.AlertSummary.OpenAlerts, summary.EventSummary.HighSeverityEvents))
		}
	}

	if builder.Len() == 0 {
		builder.WriteString("I do not have enough local dashboard data to summarize the current security status yet.")
	}

	return &model.AssistantResponse{
		Answer:     builder.String(),
		Intent:     IntentSystemStatus,
		Confidence: confidence,
		Sources:    sources,
		SuggestedActions: []string{
			"Run a configuration scan if no latest scan exists",
			"Review open alerts",
			"Check high severity events",
		},
	}, nil
}

func (s *AssistantService) answerLowScoreReason() (*model.AssistantResponse, error) {
	if s.ScanReader == nil {
		return missingDataResponse(IntentLowScoreReason, "latest_scan", "The latest scan reader is not configured."), nil
	}

	scan, err := s.ScanReader.GetLatestScanReport()
	if err != nil {
		return nil, err
	}
	if scan == nil {
		return missingDataResponse(IntentLowScoreReason, "latest_scan", "There is no latest scan report yet. Run a scan first."), nil
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "The latest scan score is %d and %d rules were triggered. ", scan.TotalScore, scan.TriggeredRulesCount)
	if len(scan.Risks) == 0 {
		builder.WriteString("No risks are attached to the latest scan, so there is no local evidence explaining a low score.")
		return &model.AssistantResponse{
			Answer:           builder.String(),
			Intent:           IntentLowScoreReason,
			Confidence:       "medium",
			Sources:          []string{"latest_scan"},
			SuggestedActions: []string{"Run another scan if the score looks stale", "Review rule configuration"},
		}, nil
	}

	counts := riskCounts(scan.Risks)
	fmt.Fprintf(&builder, "Score reductions came from %d critical, %d high, %d medium, and %d low risks. ",
		counts["critical"], counts["high"], counts["medium"], counts["low"])

	importantRisks := filterRisksBySeverity(scan.Risks, "critical", "high")
	if len(importantRisks) > 0 {
		builder.WriteString("The most important risks are: ")
		for i, risk := range limitRisks(importantRisks, 4) {
			if i > 0 {
				builder.WriteString("; ")
			}
			fmt.Fprintf(&builder, "%s (%s)", risk.Title, risk.Severity)
		}
		builder.WriteString(".")
	} else {
		builder.WriteString("No critical or high risks were found; the lower score is caused by medium and low severity findings.")
	}

	return &model.AssistantResponse{
		Answer:     builder.String(),
		Intent:     IntentLowScoreReason,
		Confidence: "high",
		Sources:    []string{"latest_scan", "latest_scan_risks"},
		SuggestedActions: []string{
			"Review critical and high risks first",
			"Open the recommendations page for concrete remediation steps",
			"Check whether rule severities match your policy",
		},
	}, nil
}

func (s *AssistantService) answerFixPriority() (*model.AssistantResponse, error) {
	recommendations := make([]model.Recommendation, 0)
	sources := make([]string, 0)

	if s.RecommendationReader != nil {
		latestRecommendations, err := s.RecommendationReader.GetLatestRecommendations()
		if err != nil {
			return nil, err
		}
		recommendations = append(recommendations, latestRecommendations...)
		if len(latestRecommendations) > 0 {
			sources = append(sources, "recommendations")
		}
	}

	if len(recommendations) == 0 && s.ScanReader != nil {
		scan, err := s.ScanReader.GetLatestScanReport()
		if err != nil {
			return nil, err
		}
		if scan != nil && len(scan.Risks) > 0 {
			sources = append(sources, "latest_scan_risks")
			for _, risk := range scan.Risks {
				recommendations = append(recommendations, model.Recommendation{
					ScanReportID:   scan.ID,
					RuleID:         risk.RuleID,
					Title:          risk.Title,
					Priority:       mapSeverityToPriority(risk.Severity),
					Recommendation: risk.Recommendation,
					Status:         "open",
				})
			}
		}
	}

	if len(recommendations) == 0 {
		return &model.AssistantResponse{
			Answer:     "I do not have recommendations or latest scan risks to prioritize yet. Run a scan to generate remediation recommendations.",
			Intent:     IntentFixPriority,
			Confidence: "low",
			Sources:    sources,
			SuggestedActions: []string{
				"Run a configuration scan",
				"Open the Recommendations page after the scan completes",
			},
		}, nil
	}

	sort.SliceStable(recommendations, func(i, j int) bool {
		return priorityWeight(recommendations[i].Priority) > priorityWeight(recommendations[j].Priority)
	})

	var builder strings.Builder
	builder.WriteString("Fix the highest priority open items first. Recommended order: ")
	for i, recommendation := range limitRecommendations(recommendations, 5) {
		if i > 0 {
			builder.WriteString("; ")
		}
		fmt.Fprintf(&builder, "%s (%s): %s", recommendation.Title, recommendation.Priority, recommendation.Recommendation)
	}
	builder.WriteString(".")

	return &model.AssistantResponse{
		Answer:     builder.String(),
		Intent:     IntentFixPriority,
		Confidence: "high",
		Sources:    sources,
		SuggestedActions: []string{
			"Fix high priority recommendations first",
			"Then handle medium priority recommendations",
			"Re-run the scan after remediation",
		},
	}, nil
}

func (s *AssistantService) answerLatestAlertExplanation() (*model.AssistantResponse, error) {
	if s.AlertReader == nil {
		return missingDataResponse(IntentLatestAlertExplanation, "latest_alert", "The alert reader is not configured."), nil
	}

	alert, err := s.AlertReader.GetLatestAlert()
	if err != nil {
		return nil, err
	}
	if alert == nil {
		return missingDataResponse(IntentLatestAlertExplanation, "latest_alert", "There is no latest alert to explain yet."), nil
	}

	answer := fmt.Sprintf(
		"The latest alert is %s with %s severity. It came from %s reference %s. Message: %s Next action: review the source record and close the alert only after the condition is understood or fixed.",
		alert.AlertType,
		alert.Severity,
		alert.SourceType,
		alert.SourceRef,
		alert.Message,
	)

	return &model.AssistantResponse{
		Answer:     answer,
		Intent:     IntentLatestAlertExplanation,
		Confidence: "high",
		Sources:    []string{"latest_alert"},
		SuggestedActions: []string{
			"Open the alert details",
			"Review the linked scan or event",
			"Close the alert after review",
		},
	}, nil
}

func (s *AssistantService) answerSuspiciousAPIActivity() (*model.AssistantResponse, error) {
	if s.AuditReader == nil {
		return missingDataResponse(IntentSuspiciousAPIActivity, "api_audit_logs", "The API audit log reader is not configured."), nil
	}

	auditLogs, err := s.AuditReader.ListAPIAuditLogs()
	if err != nil {
		return nil, err
	}
	if len(auditLogs) == 0 {
		return missingDataResponse(IntentSuspiciousAPIActivity, "api_audit_logs", "There are no API audit logs yet."), nil
	}

	failedCount := 0
	unauthorizedCount := 0
	serverErrorCount := 0
	recentFailed := make([]model.APIAuditLog, 0)
	for _, auditLog := range auditLogs {
		if !auditLog.Success || auditLog.StatusCode >= 400 {
			failedCount++
			if len(recentFailed) < 5 {
				recentFailed = append(recentFailed, auditLog)
			}
		}
		if auditLog.StatusCode == 401 {
			unauthorizedCount++
		}
		if auditLog.StatusCode >= 500 {
			serverErrorCount++
		}
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "I found %d failed API requests, including %d unauthorized requests and %d server errors. ",
		failedCount, unauthorizedCount, serverErrorCount)
	if failedCount == 0 {
		builder.WriteString("Based on current local audit logs, there is no obvious suspicious API activity.")
	} else {
		builder.WriteString("Suspicious activity may exist if these failures are unexpected. Recent failed requests include: ")
		for i, auditLog := range recentFailed {
			if i > 0 {
				builder.WriteString("; ")
			}
			fmt.Fprintf(&builder, "%s %s returned %d", auditLog.Method, auditLog.Path, auditLog.StatusCode)
		}
		builder.WriteString(".")
	}

	return &model.AssistantResponse{
		Answer:     builder.String(),
		Intent:     IntentSuspiciousAPIActivity,
		Confidence: "high",
		Sources:    []string{"api_audit_logs"},
		SuggestedActions: []string{
			"Review repeated 401 responses",
			"Check server errors in backend logs",
			"Rotate the API key if unauthorized access is suspected",
		},
	}, nil
}

func (s *AssistantService) answerRulePolicyExplanation() (*model.AssistantResponse, error) {
	var policy *model.SecurityPolicy
	rules := make([]model.SecurityRule, 0)
	sources := make([]string, 0)

	if s.PolicyReader != nil {
		loadedPolicy, err := s.PolicyReader.GetPolicy()
		if err != nil {
			return nil, err
		}
		policy = loadedPolicy
		if policy != nil {
			sources = append(sources, "policies")
		}
	}

	if s.RuleReader != nil {
		loadedRules, err := s.RuleReader.ListSecurityRules()
		if err != nil {
			return nil, err
		}
		rules = loadedRules
		if len(rules) > 0 {
			sources = append(sources, "rules")
		}
	}

	if policy == nil && len(rules) == 0 {
		return missingDataResponse(IntentRulePolicyExplanation, "rules_policies", "No policy or rule data is available yet."), nil
	}

	enabledCount := 0
	disabledRules := make([]string, 0)
	for _, rule := range rules {
		if rule.Enabled {
			enabledCount++
		} else {
			disabledRules = append(disabledRules, rule.RuleID)
		}
	}

	var builder strings.Builder
	if policy != nil {
		fmt.Fprintf(&builder, "Current thresholds are: low score below %d, multiple login failures at %d, and long token validity above %d hours. ",
			policy.LowScoreThreshold,
			policy.MultipleLoginFailuresThreshold,
			policy.LongTokenHoursThreshold,
		)
	}
	if len(rules) > 0 {
		fmt.Fprintf(&builder, "%d of %d rules are enabled. ", enabledCount, len(rules))
		if len(disabledRules) > 0 {
			builder.WriteString("Disabled rules include ")
			builder.WriteString(strings.Join(limitStrings(disabledRules, 5), ", "))
			builder.WriteString(". ")
		}
		builder.WriteString("Enabled rules can trigger scan risks, and each rule severity affects the final scan score.")
	}

	return &model.AssistantResponse{
		Answer:     builder.String(),
		Intent:     IntentRulePolicyExplanation,
		Confidence: confidenceForSources(sources),
		Sources:    sources,
		SuggestedActions: []string{
			"Review disabled rules",
			"Confirm severity settings match your security policy",
			"Adjust thresholds carefully before running comparison scans",
		},
	}, nil
}

const openAISystemInstruction = "You are an AI Security Assistant embedded in an OpenList Secure Platform. You help administrators understand scan results, alerts, recommendations, rules, policies, audit logs, and analytics. Only use the provided platform context. If context is missing, say what is missing. Give concise, practical, non-destructive guidance. Prioritize critical and high risks first. Do not reveal API keys or secrets."

func (s *AssistantService) openAIChat(message string) (*model.AssistantChatResponse, error) {
	contextText, sources, err := s.compactSecurityContext()
	if err != nil {
		return nil, err
	}

	requestBody := map[string]any{
		"model":        s.OpenAIModel,
		"instructions": openAISystemInstruction,
		"input": fmt.Sprintf(
			"User message:\n%s\n\nCompact local platform context JSON:\n%s",
			message,
			contextText,
		),
		"max_output_tokens": 700,
		"temperature":       0.2,
		"store":             false,
	}

	requestBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+s.OpenAIAPIKey)
	request.Header.Set("Content-Type", "application/json")

	httpClient := s.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OpenAI API returned status %d: %s", response.StatusCode, string(responseBytes))
	}

	answer, err := extractOpenAIAnswer(responseBytes)
	if err != nil {
		return nil, err
	}

	// TODO: add streaming responses, tool calling, and model selection UI.
	// TODO: add conversation persistence, per-user chat history, and rate limiting.
	return &model.AssistantChatResponse{
		Answer:  answer,
		Mode:    "openai",
		Sources: sources,
		SuggestedActions: []string{
			"Review the referenced local platform data",
			"Prioritize critical and high risks first",
			"Re-run scans after remediation",
		},
	}, nil
}

func (s *AssistantService) compactSecurityContext() (string, []string, error) {
	context := make(map[string]any)
	sources := make([]string, 0)

	if s.DashboardReader != nil {
		summary, err := s.DashboardReader.GetDashboardSummary()
		if err != nil {
			return "", nil, err
		}
		if summary != nil {
			context["dashboard_summary"] = summary
			sources = append(sources, "dashboard_summary")
		}
	}

	if s.ScanReader != nil {
		scan, err := s.ScanReader.GetLatestScanReport()
		if err != nil {
			return "", nil, err
		}
		if scan != nil {
			context["latest_scan"] = map[string]any{
				"id":                    scan.ID,
				"platform":              scan.Platform,
				"total_score":           scan.TotalScore,
				"triggered_rules_count": scan.TriggeredRulesCount,
				"risks":                 limitRisks(scan.Risks, 8),
			}
			sources = append(sources, "latest_scan")
		}
	}

	if s.AlertReader != nil {
		alerts, err := s.AlertReader.ListAlerts()
		if err != nil {
			return "", nil, err
		}
		latestAlert, err := s.AlertReader.GetLatestAlert()
		if err != nil {
			return "", nil, err
		}
		context["alerts"] = map[string]any{
			"total_count":  len(alerts),
			"open_count":   countAlertsByStatus(alerts, "open"),
			"latest_alert": latestAlert,
		}
		sources = append(sources, "alerts")
	}

	if s.RecommendationReader != nil {
		recommendations, err := s.RecommendationReader.GetLatestRecommendations()
		if err != nil {
			return "", nil, err
		}
		context["recommendations"] = map[string]any{
			"latest_count": len(recommendations),
			"latest_items": limitRecommendations(recommendations, 8),
		}
		sources = append(sources, "recommendations")
	}

	if s.RuleReader != nil {
		rules, err := s.RuleReader.ListSecurityRules()
		if err != nil {
			return "", nil, err
		}
		context["rules"] = ruleSummaryForContext(rules)
		sources = append(sources, "rules")
	}

	if s.PolicyReader != nil {
		policy, err := s.PolicyReader.GetPolicy()
		if err != nil {
			return "", nil, err
		}
		if policy != nil {
			context["policy"] = policy
			sources = append(sources, "policies")
		}
	}

	if s.AuditReader != nil {
		auditLogs, err := s.AuditReader.ListAPIAuditLogs()
		if err != nil {
			return "", nil, err
		}
		context["api_audit_summary"] = auditSummaryForContext(auditLogs)
		sources = append(sources, "api_audit_logs")
	}

	if s.EventReader != nil {
		stats, err := s.EventReader.GetSecurityEventStats()
		if err != nil {
			return "", nil, err
		}
		if stats != nil {
			context["event_stats"] = stats
			sources = append(sources, "event_stats")
		}
	}

	contextBytes, err := json.MarshalIndent(context, "", "  ")
	if err != nil {
		return "", nil, err
	}

	return string(contextBytes), uniqueStrings(sources), nil
}

func (s *AssistantService) answerGeneralHelp() *model.AssistantResponse {
	return &model.AssistantResponse{
		Answer:     "I can answer questions using local platform data only. Try asking about current security status, why the latest scan score is low, what to fix first, the latest alert, suspicious API activity, or how rules and policies affect scanning.",
		Intent:     IntentGeneralHelp,
		Confidence: "low",
		Sources:    []string{},
		SuggestedActions: []string{
			"Ask: What is the current security status?",
			"Ask: What should I fix first?",
			"Ask: Are there suspicious API activities?",
		},
	}
}

func missingDataResponse(intent, source, message string) *model.AssistantResponse {
	return &model.AssistantResponse{
		Answer:     message,
		Intent:     intent,
		Confidence: "low",
		Sources:    []string{source},
		SuggestedActions: []string{
			"Generate or import the required data",
			"Refresh the related platform page",
		},
	}
}

func containsAny(value string, keywords ...string) bool {
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func securityPostureText(score int, openAlerts int, highSeverityEvents int) string {
	switch {
	case score >= 80 && openAlerts == 0 && highSeverityEvents == 0:
		return "Overall posture looks healthy based on the available local data."
	case score < 60 || openAlerts > 0 || highSeverityEvents > 0:
		return "Overall posture needs attention because local data shows a low score, open alerts, or high severity events."
	default:
		return "Overall posture is moderate; continue reviewing risks and recommendations."
	}
}

func riskCounts(risks []model.RiskItem) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, risk := range risks {
		counts[risk.Severity]++
	}
	return counts
}

func filterRisksBySeverity(risks []model.RiskItem, severities ...string) []model.RiskItem {
	allowed := make(map[string]bool, len(severities))
	for _, severity := range severities {
		allowed[severity] = true
	}

	filtered := make([]model.RiskItem, 0)
	for _, risk := range risks {
		if allowed[risk.Severity] {
			filtered = append(filtered, risk)
		}
	}
	return filtered
}

func limitRisks(risks []model.RiskItem, limit int) []model.RiskItem {
	if len(risks) <= limit {
		return risks
	}
	return risks[:limit]
}

func limitRecommendations(recommendations []model.Recommendation, limit int) []model.Recommendation {
	if len(recommendations) <= limit {
		return recommendations
	}
	return recommendations[:limit]
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func countAlertsByStatus(alerts []model.Alert, status string) int {
	count := 0
	for _, alert := range alerts {
		if alert.Status == status {
			count++
		}
	}
	return count
}

func ruleSummaryForContext(rules []model.SecurityRule) map[string]any {
	disabledRules := make([]string, 0)
	severityCounts := make(map[string]int)
	enabledCount := 0

	for _, rule := range rules {
		severityCounts[rule.Severity]++
		if rule.Enabled {
			enabledCount++
		} else {
			disabledRules = append(disabledRules, rule.RuleID)
		}
	}

	return map[string]any{
		"total_count":     len(rules),
		"enabled_count":   enabledCount,
		"disabled_count":  len(disabledRules),
		"disabled_rules":  limitStrings(disabledRules, 8),
		"severity_counts": severityCounts,
	}
}

func auditSummaryForContext(auditLogs []model.APIAuditLog) map[string]any {
	failedCount := 0
	unauthorizedCount := 0
	serverErrorCount := 0
	recentFailed := make([]map[string]any, 0)

	for _, auditLog := range auditLogs {
		if !auditLog.Success || auditLog.StatusCode >= 400 {
			failedCount++
			if len(recentFailed) < 6 {
				recentFailed = append(recentFailed, map[string]any{
					"method":      auditLog.Method,
					"path":        auditLog.Path,
					"status_code": auditLog.StatusCode,
					"timestamp":   auditLog.Timestamp,
				})
			}
		}
		if auditLog.StatusCode == http.StatusUnauthorized {
			unauthorizedCount++
		}
		if auditLog.StatusCode >= http.StatusInternalServerError {
			serverErrorCount++
		}
	}

	return map[string]any{
		"total_count":        len(auditLogs),
		"failed_count":       failedCount,
		"unauthorized_count": unauthorizedCount,
		"server_error_count": serverErrorCount,
		"recent_failed":      recentFailed,
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

type openAIResponseBody struct {
	OutputText string `json:"output_text"`
	Output     []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func extractOpenAIAnswer(responseBytes []byte) (string, error) {
	var response openAIResponseBody
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return "", err
	}

	if response.Error != nil && response.Error.Message != "" {
		return "", errors.New(response.Error.Message)
	}

	if strings.TrimSpace(response.OutputText) != "" {
		return strings.TrimSpace(response.OutputText), nil
	}

	for _, output := range response.Output {
		for _, content := range output.Content {
			if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
				return strings.TrimSpace(content.Text), nil
			}
		}
	}

	return "", errors.New("OpenAI response did not contain output text")
}

func priorityWeight(priority string) int {
	switch priority {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func confidenceForSources(sources []string) string {
	switch {
	case len(sources) >= 2:
		return "high"
	case len(sources) == 1:
		return "medium"
	default:
		return "low"
	}
}
