package httpapi

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openlist-secure-platform/internal/core/contracts"
	"openlist-secure-platform/internal/core/model"
	"openlist-secure-platform/internal/core/service"
)

type Router struct {
	scanService           *service.ScanService
	scanReader            contracts.ScanReportReader
	eventService          *service.EventService
	eventReader           contracts.SecurityEventReader
	alertService          *service.AlertService
	alertReader           contracts.AlertReader
	ruleReader            contracts.SecurityRuleReader
	ruleStore             contracts.SecurityRuleStore
	policyService         *service.PolicyService
	policyReader          contracts.PolicyReader
	recommendationService *service.RecommendationService
	recommendationReader  contracts.RecommendationReader
	dashboardReader       contracts.DashboardReader
	analyticsReader       contracts.AnalyticsReader
	assistantService      *service.AssistantService
	auditStore            contracts.APIAuditLogStore
	auditReader           contracts.APIAuditLogReader
	resetStore            contracts.DevelopmentResetStore
	adminAPIKey           string
}

type ScanStartRequest struct {
	ConfigPath string `json:"config_path"`
}

type EventImportRequest struct {
	LogPath string `json:"log_path"`
}

type RecommendationStatusRequest struct {
	Status string `json:"status"`
}

type PolicyUpdateRequest struct {
	LowScoreThreshold              *int `json:"low_score_threshold"`
	MultipleLoginFailuresThreshold *int `json:"multiple_login_failures_threshold"`
	LongTokenHoursThreshold        *int `json:"long_token_hours_threshold"`
}

type RuleUpdateRequest struct {
	Enabled  *bool  `json:"enabled"`
	Severity string `json:"severity"`
}

type APIDocItem struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Description  string `json:"description"`
	AuthRequired bool   `json:"auth_required"`
}

func NewRouter(
	scanService *service.ScanService,
	scanReader contracts.ScanReportReader,
	eventService *service.EventService,
	eventReader contracts.SecurityEventReader,
	alertService *service.AlertService,
	alertReader contracts.AlertReader,
	ruleReader contracts.SecurityRuleReader,
	ruleStore contracts.SecurityRuleStore,
	policyService *service.PolicyService,
	policyReader contracts.PolicyReader,
	recommendationService *service.RecommendationService,
	recommendationReader contracts.RecommendationReader,
	dashboardReader contracts.DashboardReader,
	analyticsReader contracts.AnalyticsReader,
	assistantService *service.AssistantService,
	auditStore contracts.APIAuditLogStore,
	auditReader contracts.APIAuditLogReader,
	resetStore contracts.DevelopmentResetStore,
	adminAPIKey string,
) http.Handler {
	router := &Router{
		scanService:           scanService,
		scanReader:            scanReader,
		eventService:          eventService,
		eventReader:           eventReader,
		alertService:          alertService,
		alertReader:           alertReader,
		ruleReader:            ruleReader,
		ruleStore:             ruleStore,
		policyService:         policyService,
		policyReader:          policyReader,
		recommendationService: recommendationService,
		recommendationReader:  recommendationReader,
		dashboardReader:       dashboardReader,
		analyticsReader:       analyticsReader,
		assistantService:      assistantService,
		auditStore:            auditStore,
		auditReader:           auditReader,
		resetStore:            resetStore,
		adminAPIKey:           adminAPIKey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/reset/events", router.resetEventsHandler)
	mux.HandleFunc("/admin/reset/alerts", router.resetAlertsHandler)
	mux.HandleFunc("/admin/reset/audit", router.resetAuditHandler)
	mux.HandleFunc("/admin/reset/recommendations", router.resetRecommendationsHandler)
	mux.HandleFunc("/analytics/risk-trends", router.riskTrendsHandler)
	mux.HandleFunc("/analytics/risk-rules/top", router.topRiskRulesHandler)
	mux.HandleFunc("/analytics/alerts/summary", router.alertAnalyticsSummaryHandler)
	mux.HandleFunc("/assistant/chat", router.assistantChatHandler)
	mux.HandleFunc("/assistant/ask", router.assistantAskHandler)
	mux.HandleFunc("/assistant/suggestions", router.assistantSuggestionsHandler)
	mux.HandleFunc("/assistant/context", router.assistantContextHandler)
	mux.HandleFunc("/api/docs", router.apiDocsHandler)
	mux.HandleFunc("/audit/api/latest", router.latestAPIAuditLogHandler)
	mux.HandleFunc("/audit/api", router.listAPIAuditLogsHandler)
	mux.HandleFunc("/dashboard/summary", router.dashboardSummaryHandler)
	mux.HandleFunc("/health", router.healthHandler)
	mux.HandleFunc("/policies", router.policyHandler)
	mux.HandleFunc("/recommendations", router.listRecommendationsHandler)
	mux.HandleFunc("/recommendations/latest", router.latestRecommendationsHandler)
	mux.HandleFunc("/recommendations/scan/", router.recommendationsByScanHandler)
	mux.HandleFunc("/recommendations/", router.recommendationStatusHandler)
	mux.HandleFunc("/rules/", router.ruleByIDHandler)
	mux.HandleFunc("/rules", router.listRulesHandler)
	mux.HandleFunc("/scan/start", router.scanStartHandler)
	mux.HandleFunc("/alerts/latest", router.latestAlertHandler)
	mux.HandleFunc("/alerts/", router.alertByIDHandler)
	mux.HandleFunc("/alerts", router.listAlertsHandler)
	mux.HandleFunc("/events/import", router.importEventsHandler)
	mux.HandleFunc("/events/latest", router.latestEventHandler)
	mux.HandleFunc("/events/stats", router.eventStatsHandler)
	mux.HandleFunc("/events/", router.eventByIDHandler)
	mux.HandleFunc("/events", router.listEventsHandler)
	mux.HandleFunc("/scans/latest", router.latestScanHandler)
	mux.HandleFunc("/scans/", router.scanByIDHandler)
	mux.HandleFunc("/scans", router.listScansHandler)
	return router.auditMiddleware(router.apiKeyMiddleware(mux))
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(statusCode int) {
	sr.statusCode = statusCode
	sr.ResponseWriter.WriteHeader(statusCode)
}

func (sr *statusRecorder) Write(data []byte) (int, error) {
	if sr.statusCode == 0 {
		sr.statusCode = http.StatusOK
	}

	return sr.ResponseWriter.Write(data)
}

func (rt *Router) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

		if r.Method == http.MethodDelete && r.URL.Path == "/admin/reset/audit" {
			return
		}

		statusCode := recorder.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		if rt.auditStore == nil {
			return
		}

		auditLog := model.APIAuditLog{
			Timestamp:  time.Now(),
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: statusCode,
			ClientIP:   clientIPFromRequest(r),
			UserAgent:  r.UserAgent(),
			APIKeyUsed: r.Header.Get("X-API-Key") != "",
			Success:    statusCode < http.StatusBadRequest,
		}

		if err := rt.auditStore.SaveAPIAuditLog(auditLog); err != nil {
			log.Printf("failed to save API audit log: %v", err)
		}
	})
}

func (rt *Router) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		providedKey := r.Header.Get("X-API-Key")
		if !rt.isAuthorized(providedKey) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid API key")
			return
		}

		// TODO: replace this simple API-key layer with real user authentication.
		// TODO: add role-based access control, audit logging, and per-user accounts.
		// TODO: support API key rotation and safer secret loading from environment or vault.
		next.ServeHTTP(w, r)
	})
}

func (rt *Router) isAuthorized(providedKey string) bool {
	if rt.adminAPIKey == "" {
		// TODO: fail closed more explicitly when secure configuration loading is added.
		return false
	}

	if len(providedKey) != len(rt.adminAPIKey) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(providedKey), []byte(rt.adminAPIKey)) == 1
}

func (rt *Router) apiDocsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string][]APIDocItem{
		"health": {
			{Method: "GET", Path: "/health", Description: "Check whether the backend server is running.", AuthRequired: false},
		},
		"scan": {
			{Method: "POST", Path: "/scan/start", Description: "Run an OpenList configuration scan.", AuthRequired: true},
			{Method: "GET", Path: "/scans", Description: "List scan report summaries with optional filters.", AuthRequired: true},
			{Method: "GET", Path: "/scans/latest", Description: "Get the latest scan report with risks.", AuthRequired: true},
			{Method: "GET", Path: "/scans/{id}", Description: "Get one scan report by ID.", AuthRequired: true},
		},
		"events": {
			{Method: "POST", Path: "/events/import", Description: "Import and parse an OpenList log file.", AuthRequired: true},
			{Method: "GET", Path: "/events", Description: "List security events with optional filters.", AuthRequired: true},
			{Method: "GET", Path: "/events/latest", Description: "Get the latest security event.", AuthRequired: true},
			{Method: "GET", Path: "/events/{id}", Description: "Get one security event by ID.", AuthRequired: true},
			{Method: "GET", Path: "/events/stats", Description: "Get event statistics by type and severity.", AuthRequired: true},
			{Method: "DELETE", Path: "/events", Description: "Clear imported security events for development testing.", AuthRequired: true},
		},
		"alerts": {
			{Method: "GET", Path: "/alerts", Description: "List alerts with optional filters.", AuthRequired: true},
			{Method: "GET", Path: "/alerts/latest", Description: "Get the latest alert.", AuthRequired: true},
			{Method: "GET", Path: "/alerts/{id}", Description: "Get one alert by ID.", AuthRequired: true},
			{Method: "PATCH", Path: "/alerts/{id}/close", Description: "Close an open alert.", AuthRequired: true},
		},
		"recommendations": {
			{Method: "GET", Path: "/recommendations", Description: "List remediation recommendations with optional filters.", AuthRequired: true},
			{Method: "GET", Path: "/recommendations/latest", Description: "Get recommendations from the latest scan.", AuthRequired: true},
			{Method: "GET", Path: "/recommendations/scan/{id}", Description: "Get recommendations for a scan report.", AuthRequired: true},
			{Method: "PATCH", Path: "/recommendations/{id}/status", Description: "Update recommendation status.", AuthRequired: true},
		},
		"rules": {
			{Method: "GET", Path: "/rules", Description: "List configurable security scanning rules.", AuthRequired: true},
			{Method: "GET", Path: "/rules/{rule_id}", Description: "Get one security rule by rule ID.", AuthRequired: true},
			{Method: "PATCH", Path: "/rules/{rule_id}", Description: "Enable, disable, or update severity for a security rule.", AuthRequired: true},
		},
		"policies": {
			{Method: "GET", Path: "/policies", Description: "Get the active security policy thresholds.", AuthRequired: true},
			{Method: "PATCH", Path: "/policies", Description: "Update security policy thresholds.", AuthRequired: true},
		},
		"dashboard": {
			{Method: "GET", Path: "/dashboard/summary", Description: "Get aggregated platform summary data.", AuthRequired: true},
		},
		"analytics": {
			{Method: "GET", Path: "/analytics/risk-trends", Description: "Get scan score history ordered by scan time.", AuthRequired: true},
			{Method: "GET", Path: "/analytics/risk-rules/top", Description: "Get the most frequently triggered risk rules.", AuthRequired: true},
			{Method: "GET", Path: "/analytics/alerts/summary", Description: "Get alert counts by status, type, and severity.", AuthRequired: true},
		},
		"assistant": {
			{Method: "POST", Path: "/assistant/ask", Description: "Ask the local rule-based security assistant a question.", AuthRequired: true},
			{Method: "POST", Path: "/assistant/chat", Description: "Chat with the assistant using local mode or optional backend OpenAI mode.", AuthRequired: true},
			{Method: "GET", Path: "/assistant/suggestions", Description: "List suggested assistant questions.", AuthRequired: true},
			{Method: "GET", Path: "/assistant/context", Description: "Get assistant data availability and record counts.", AuthRequired: true},
		},
		"audit": {
			{Method: "GET", Path: "/audit/api", Description: "List API audit logs with optional filters.", AuthRequired: true},
			{Method: "GET", Path: "/audit/api/latest", Description: "Get the latest API audit log entry.", AuthRequired: true},
		},
		"admin": {
			{Method: "DELETE", Path: "/admin/reset/events", Description: "Delete imported security event data for development.", AuthRequired: true},
			{Method: "DELETE", Path: "/admin/reset/alerts", Description: "Delete alert data for development.", AuthRequired: true},
			{Method: "DELETE", Path: "/admin/reset/audit", Description: "Delete API audit logs for development.", AuthRequired: true},
			{Method: "DELETE", Path: "/admin/reset/recommendations", Description: "Delete recommendation data for development.", AuthRequired: true},
		},
	})
}

func (rt *Router) listAPIAuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.auditReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "API audit log reader is not configured")
		return
	}

	statusCode, err := optionalIntQuery(r, "status_code")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid status_code")
		return
	}

	success, err := optionalBoolQuery(r, "success")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid success")
		return
	}

	apiKeyUsed, err := optionalBoolQuery(r, "api_key_used")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid api_key_used")
		return
	}

	auditLogs, err := rt.auditReader.ListAPIAuditLogsFiltered(
		r.URL.Query().Get("method"),
		statusCode,
		success,
		apiKeyUsed,
		r.URL.Query().Get("path"),
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load API audit logs")
		return
	}

	writeJSON(w, http.StatusOK, auditLogs)
}

func (rt *Router) latestAPIAuditLogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.auditReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "API audit log reader is not configured")
		return
	}

	auditLog, err := rt.auditReader.GetLatestAPIAuditLog()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load latest API audit log")
		return
	}

	if auditLog == nil {
		writeJSONError(w, http.StatusNotFound, "API audit log not found")
		return
	}

	writeJSON(w, http.StatusOK, auditLog)
}

func (rt *Router) riskTrendsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.analyticsReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "analytics reader is not configured")
		return
	}

	trends, err := rt.analyticsReader.GetRiskTrend()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load risk trend analytics")
		return
	}

	writeJSON(w, http.StatusOK, trends)
}

func (rt *Router) topRiskRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.analyticsReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "analytics reader is not configured")
		return
	}

	rules, err := rt.analyticsReader.GetTopRiskRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load top risk rules")
		return
	}

	writeJSON(w, http.StatusOK, rules)
}

func (rt *Router) alertAnalyticsSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.analyticsReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "analytics reader is not configured")
		return
	}

	summary, err := rt.analyticsReader.GetAlertAnalyticsSummary()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load alert analytics summary")
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

func (rt *Router) assistantAskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.assistantService == nil {
		writeJSONError(w, http.StatusInternalServerError, "assistant service is not configured")
		return
	}

	var request model.AssistantRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if strings.TrimSpace(request.Question) == "" {
		writeJSONError(w, http.StatusBadRequest, "question is required")
		return
	}

	response, err := rt.assistantService.Ask(request.Question)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate assistant response")
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) assistantChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.assistantService == nil {
		writeJSONError(w, http.StatusInternalServerError, "assistant service is not configured")
		return
	}

	var request model.AssistantChatRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if strings.TrimSpace(request.Message) == "" {
		writeJSONError(w, http.StatusBadRequest, "message is required")
		return
	}

	response, err := rt.assistantService.Chat(request.Message)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate assistant chat response")
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) assistantSuggestionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.assistantService == nil {
		writeJSONError(w, http.StatusInternalServerError, "assistant service is not configured")
		return
	}

	writeJSON(w, http.StatusOK, rt.assistantService.Suggestions())
}

func (rt *Router) assistantContextHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.assistantService == nil {
		writeJSONError(w, http.StatusInternalServerError, "assistant service is not configured")
		return
	}

	context, err := rt.assistantService.Context()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load assistant context")
		return
	}

	writeJSON(w, http.StatusOK, context)
}

func (rt *Router) listRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.ruleReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "rule reader is not configured")
		return
	}

	rules, err := rt.ruleReader.ListSecurityRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security rules")
		return
	}

	writeJSON(w, http.StatusOK, rules)
}

func (rt *Router) ruleByIDHandler(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimPrefix(r.URL.Path, "/rules/")
	if strings.TrimSpace(ruleID) == "" {
		writeJSONError(w, http.StatusBadRequest, "rule_id is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		rt.getRuleHandler(w, ruleID)
	case http.MethodPatch:
		rt.updateRuleHandler(w, r, ruleID)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (rt *Router) getRuleHandler(w http.ResponseWriter, ruleID string) {
	if rt.ruleReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "rule reader is not configured")
		return
	}

	rule, err := rt.ruleReader.GetSecurityRule(ruleID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security rule")
		return
	}
	if rule == nil {
		writeJSONError(w, http.StatusNotFound, "security rule not found")
		return
	}

	writeJSON(w, http.StatusOK, rule)
}

func (rt *Router) updateRuleHandler(w http.ResponseWriter, r *http.Request, ruleID string) {
	if rt.ruleStore == nil || rt.ruleReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "rule store is not configured")
		return
	}

	var request RuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if request.Severity != "" && !isValidSeverity(request.Severity) {
		writeJSONError(w, http.StatusBadRequest, "invalid severity")
		return
	}

	if err := rt.ruleStore.UpdateSecurityRule(ruleID, request.Enabled, request.Severity); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "security rule not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to update security rule")
		return
	}

	rule, err := rt.ruleReader.GetSecurityRule(ruleID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security rule")
		return
	}
	if rule == nil {
		writeJSONError(w, http.StatusNotFound, "security rule not found")
		return
	}

	writeJSON(w, http.StatusOK, rule)
}

func (rt *Router) resetEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.resetStore == nil {
		writeJSONError(w, http.StatusInternalServerError, "reset store is not configured")
		return
	}

	if err := rt.resetStore.DeleteAllSecurityEvents(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to reset security events")
		return
	}

	// TODO: development-only reset endpoints should be disabled or tightly restricted in production.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "all security events deleted",
	})
}

func (rt *Router) resetAlertsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.resetStore == nil {
		writeJSONError(w, http.StatusInternalServerError, "reset store is not configured")
		return
	}

	if err := rt.resetStore.DeleteAllAlerts(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to reset alerts")
		return
	}

	// TODO: development-only reset endpoints should be disabled or tightly restricted in production.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "all alerts deleted",
	})
}

func (rt *Router) resetAuditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.resetStore == nil {
		writeJSONError(w, http.StatusInternalServerError, "reset store is not configured")
		return
	}

	if err := rt.resetStore.DeleteAllAPIAuditLogs(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to reset API audit logs")
		return
	}

	// TODO: development-only reset endpoints should be disabled or tightly restricted in production.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "all API audit logs deleted",
	})
}

func (rt *Router) resetRecommendationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.resetStore == nil {
		writeJSONError(w, http.StatusInternalServerError, "reset store is not configured")
		return
	}

	if err := rt.resetStore.DeleteAllRecommendations(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to reset recommendations")
		return
	}

	// TODO: development-only reset endpoints should be disabled or tightly restricted in production.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "all recommendations deleted",
	})
}

func (rt *Router) policyHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rt.getPolicyHandler(w, r)
	case http.MethodPatch:
		rt.updatePolicyHandler(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (rt *Router) dashboardSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.dashboardReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "dashboard reader is not configured")
		return
	}

	summary, err := rt.dashboardReader.GetDashboardSummary()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load dashboard summary")
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

func (rt *Router) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (rt *Router) getPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if rt.policyReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "policy reader is not configured")
		return
	}

	policy, err := rt.policyReader.GetPolicy()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load policy")
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

func (rt *Router) updatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	if rt.policyService == nil {
		writeJSONError(w, http.StatusInternalServerError, "policy service is not configured")
		return
	}

	var request PolicyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if request.LowScoreThreshold != nil && *request.LowScoreThreshold <= 0 {
		writeJSONError(w, http.StatusBadRequest, "low_score_threshold must be a positive integer")
		return
	}
	if request.MultipleLoginFailuresThreshold != nil && *request.MultipleLoginFailuresThreshold <= 0 {
		writeJSONError(w, http.StatusBadRequest, "multiple_login_failures_threshold must be a positive integer")
		return
	}
	if request.LongTokenHoursThreshold != nil && *request.LongTokenHoursThreshold <= 0 {
		writeJSONError(w, http.StatusBadRequest, "long_token_hours_threshold must be a positive integer")
		return
	}

	policy, err := rt.policyService.UpdatePolicy(
		request.LowScoreThreshold,
		request.MultipleLoginFailuresThreshold,
		request.LongTokenHoursThreshold,
	)
	if err != nil {
		switch err.Error() {
		case "invalid low_score_threshold", "invalid multiple_login_failures_threshold", "invalid long_token_hours_threshold":
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "failed to update policy")
		}
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

func (rt *Router) scanStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var request ScanStartRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if strings.TrimSpace(request.ConfigPath) == "" {
		writeJSONError(w, http.StatusBadRequest, "config_path is required")
		return
	}

	report, err := rt.scanService.RunConfigScan(request.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (rt *Router) latestScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.scanReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "scan report reader is not configured")
		return
	}

	report, err := rt.scanReader.GetLatestScanReport()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load latest scan report")
		return
	}

	if report == nil {
		writeJSONError(w, http.StatusNotFound, "scan report not found")
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (rt *Router) importEventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.eventService == nil {
		writeJSONError(w, http.StatusInternalServerError, "event service is not configured")
		return
	}

	var request EventImportRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if strings.TrimSpace(request.LogPath) == "" {
		writeJSONError(w, http.StatusBadRequest, "log_path is required")
		return
	}

	events, err := rt.eventService.ImportEvents(request.LogPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"imported_count": len(events),
		"events":         events,
	})
}

func (rt *Router) listEventsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rt.listEventsWithFiltersHandler(w, r)
	case http.MethodDelete:
		rt.deleteAllEventsHandler(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (rt *Router) listAlertsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.alertReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "alert reader is not configured")
		return
	}

	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")
	alertType := r.URL.Query().Get("alert_type")

	alerts, err := rt.alertReader.ListAlertsFiltered(status, severity, alertType)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load alerts")
		return
	}

	writeJSON(w, http.StatusOK, alerts)
}

func (rt *Router) latestAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.alertReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "alert reader is not configured")
		return
	}

	alert, err := rt.alertReader.GetLatestAlert()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load latest alert")
		return
	}

	if alert == nil {
		writeJSONError(w, http.StatusNotFound, "alert not found")
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (rt *Router) listRecommendationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.recommendationReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "recommendation reader is not configured")
		return
	}

	status := r.URL.Query().Get("status")
	priority := r.URL.Query().Get("priority")
	var scanReportID *int64
	if value := r.URL.Query().Get("scan_report_id"); value != "" {
		parsedID, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsedID <= 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid scan_report_id")
			return
		}
		scanReportID = &parsedID
	}

	recommendations, err := rt.recommendationReader.ListRecommendationsFiltered(status, priority, scanReportID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load recommendations")
		return
	}

	writeJSON(w, http.StatusOK, recommendations)
}

func (rt *Router) latestRecommendationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.recommendationReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "recommendation reader is not configured")
		return
	}

	recommendations, err := rt.recommendationReader.GetLatestRecommendations()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load recommendations")
		return
	}

	writeJSON(w, http.StatusOK, recommendations)
}

func (rt *Router) recommendationsByScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.recommendationReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "recommendation reader is not configured")
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/recommendations/scan/")
	scanID, err := parseID(idText)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid scan report id")
		return
	}

	recommendations, err := rt.recommendationReader.GetRecommendationsByScanID(scanID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load recommendations")
		return
	}

	writeJSON(w, http.StatusOK, recommendations)
}

func (rt *Router) listEventsWithFiltersHandler(w http.ResponseWriter, r *http.Request) {
	if rt.eventReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "security event reader is not configured")
		return
	}

	eventType := r.URL.Query().Get("event_type")
	severity := r.URL.Query().Get("severity")
	actor := r.URL.Query().Get("actor")

	events, err := rt.eventReader.ListSecurityEventsFiltered(eventType, severity, actor)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security events")
		return
	}

	writeJSON(w, http.StatusOK, events)
}

func (rt *Router) eventStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.eventReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "security event reader is not configured")
		return
	}

	stats, err := rt.eventReader.GetSecurityEventStats()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security event stats")
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (rt *Router) latestEventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.eventReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "security event reader is not configured")
		return
	}

	event, err := rt.eventReader.GetLatestSecurityEvent()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load latest security event")
		return
	}

	if event == nil {
		writeJSONError(w, http.StatusNotFound, "security event not found")
		return
	}

	writeJSON(w, http.StatusOK, event)
}

func (rt *Router) eventByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.eventReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "security event reader is not configured")
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/events/")
	if idText == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid security event id")
		return
	}

	id, err := parseID(idText)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid security event id")
		return
	}

	event, err := rt.eventReader.GetSecurityEventByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load security event")
		return
	}

	if event == nil {
		writeJSONError(w, http.StatusNotFound, "security event not found")
		return
	}

	writeJSON(w, http.StatusOK, event)
}

func (rt *Router) alertByIDHandler(w http.ResponseWriter, r *http.Request) {
	if rt.alertReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "alert reader is not configured")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/alerts/")
	if path == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	if strings.HasSuffix(path, "/close") {
		rt.closeAlertHandler(w, r, strings.TrimSuffix(path, "/close"))
		return
	}

	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id, err := parseID(path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	alert, err := rt.alertReader.GetAlertByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load alert")
		return
	}

	if alert == nil {
		writeJSONError(w, http.StatusNotFound, "alert not found")
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (rt *Router) recommendationStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.recommendationService == nil || rt.recommendationReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "recommendation service is not configured")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/recommendations/")
	if !strings.HasSuffix(path, "/status") {
		writeJSONError(w, http.StatusNotFound, "recommendation not found")
		return
	}

	idText := strings.TrimSuffix(path, "/status")
	idText = strings.TrimSuffix(idText, "/")
	id, err := parseID(idText)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid recommendation id")
		return
	}

	var request RecommendationStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if request.Status != "open" && request.Status != "accepted" && request.Status != "dismissed" {
		writeJSONError(w, http.StatusBadRequest, "invalid recommendation status")
		return
	}

	if err := rt.recommendationService.UpdateStatus(id, request.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "recommendation not found")
			return
		}
		if err.Error() == "invalid recommendation status" || err.Error() == "invalid recommendation id" {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to update recommendation status")
		return
	}

	recommendation, err := rt.recommendationReader.GetRecommendationByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load recommendation")
		return
	}

	if recommendation == nil {
		writeJSONError(w, http.StatusNotFound, "recommendation not found")
		return
	}

	writeJSON(w, http.StatusOK, recommendation)
}

func (rt *Router) closeAlertHandler(w http.ResponseWriter, r *http.Request, idText string) {
	if r.Method != http.MethodPatch {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.alertService == nil {
		writeJSONError(w, http.StatusInternalServerError, "alert service is not configured")
		return
	}

	idText = strings.TrimSuffix(idText, "/")
	id, err := parseID(idText)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	if err := rt.alertService.CloseAlert(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "alert not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to close alert")
		return
	}

	alert, err := rt.alertReader.GetAlertByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load alert")
		return
	}

	if alert == nil {
		writeJSONError(w, http.StatusNotFound, "alert not found")
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (rt *Router) deleteAllEventsHandler(w http.ResponseWriter, r *http.Request) {
	if rt.eventService == nil {
		writeJSONError(w, http.StatusInternalServerError, "event service is not configured")
		return
	}

	if err := rt.eventService.DeleteAllEvents(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to delete security events")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "all security events deleted",
	})
}

func (rt *Router) listScansHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.scanReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "scan report reader is not configured")
		return
	}

	var minScore *int
	if value := r.URL.Query().Get("min_score"); value != "" {
		parsedValue, err := strconv.Atoi(value)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid min_score")
			return
		}
		minScore = &parsedValue
	}

	var maxScore *int
	if value := r.URL.Query().Get("max_score"); value != "" {
		parsedValue, err := strconv.Atoi(value)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid max_score")
			return
		}
		maxScore = &parsedValue
	}

	targetPath := r.URL.Query().Get("target_path")
	reports, err := rt.scanReader.ListScanReportsFiltered(minScore, maxScore, targetPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load scan reports")
		return
	}

	// TODO: add pagination, keyword search, date-range filters, and sorting options.
	writeJSON(w, http.StatusOK, reports)
}

func (rt *Router) scanByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if rt.scanReader == nil {
		writeJSONError(w, http.StatusInternalServerError, "scan report reader is not configured")
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/scans/")
	if idText == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid scan report id")
		return
	}

	id, err := parseID(idText)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid scan report id")
		return
	}

	report, err := rt.scanReader.GetScanReportByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load scan report")
		return
	}

	if report == nil {
		writeJSONError(w, http.StatusNotFound, "scan report not found")
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, statusCode int, code string, message string) {
	writeJSON(w, statusCode, map[string]map[string]string{
		"error": {
			"code":    code,
			"message": message,
		},
	})
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	// TODO: add request tracing, structured logging, and documented API error codes.
	// TODO: add an API test suite that checks common validation and error responses.
	writeError(w, statusCode, errorCodeForStatus(statusCode), message)
}

func errorCodeForStatus(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	default:
		return "internal_error"
	}
}

func parseID(value string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}

	return id, nil
}

func optionalIntQuery(r *http.Request, name string) (*int, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return nil, nil
	}

	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}

	return &parsedValue, nil
}

func optionalBoolQuery(r *http.Request, name string) (*bool, error) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return nil, nil
	}

	parsedValue, err := strconv.ParseBool(value)
	if err != nil {
		return nil, err
	}

	return &parsedValue, nil
}

func isValidSeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func clientIPFromRequest(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return r.RemoteAddr
}
