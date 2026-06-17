package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"openlist-secure-platform/internal/core/model"
)

type DB struct {
	sqlDB *sql.DB
	path  string
}

func NewDB(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite database path is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	sqlDB, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	db := &DB{
		sqlDB: sqlDB,
		path:  path,
	}

	if err := db.init(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	return db, nil
}

func (db *DB) init() error {
	if err := db.sqlDB.Ping(); err != nil {
		return err
	}

	if err := db.configurePragmas(); err != nil {
		return err
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS scan_reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			platform TEXT NOT NULL DEFAULT 'openlist',
			scan_time TEXT NOT NULL,
			target_path TEXT NOT NULL,
			total_score INTEGER NOT NULL,
			triggered_rules_count INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS risk_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_report_id INTEGER NOT NULL,
			rule_id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			recommendation TEXT NOT NULL,
			FOREIGN KEY(scan_report_id) REFERENCES scan_reports(id)
		);`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			platform TEXT NOT NULL,
			event_time TEXT NOT NULL,
			event_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			actor TEXT NOT NULL,
			target TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			raw_message TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_type TEXT NOT NULL,
			source_ref TEXT NOT NULL,
			alert_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			message TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS recommendations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_report_id INTEGER NOT NULL,
			rule_id TEXT NOT NULL,
			title TEXT NOT NULL,
			priority TEXT NOT NULL,
			recommendation TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS policies (
			id INTEGER PRIMARY KEY,
			low_score_threshold INTEGER NOT NULL,
			multiple_login_failures_threshold INTEGER NOT NULL,
			long_token_hours_threshold INTEGER NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS api_audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			client_ip TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			api_key_used TEXT NOT NULL,
			success INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS security_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id TEXT UNIQUE NOT NULL,
			platform TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			enabled INTEGER NOT NULL,
			description TEXT NOT NULL,
			recommendation TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
	}

	for _, query := range queries {
		if _, err := db.execWrite(query); err != nil {
			return err
		}
	}

	if err := db.ensurePlatformColumn(); err != nil {
		return err
	}

	if err := db.ensureDefaultPolicy(); err != nil {
		return err
	}

	return nil
}

func sqliteDSN(path string) string {
	if strings.HasPrefix(path, "file:") {
		return path
	}

	return fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on", filepath.ToSlash(path))
}

func (db *DB) configurePragmas() error {
	pragmas := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA busy_timeout = 5000;`,
		`PRAGMA foreign_keys = ON;`,
	}

	for _, pragma := range pragmas {
		if _, err := db.sqlDB.Exec(pragma); err != nil {
			return err
		}
	}

	// TODO: use PostgreSQL for higher write concurrency in production deployments.
	// TODO: add an async audit log queue, background audit writer, and database health monitoring.
	return nil
}

func (db *DB) withWriteRetry(writeFunc func() error) error {
	delays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	var err error

	for attempt := 0; attempt <= len(delays); attempt++ {
		err = writeFunc()
		if err == nil || !isSQLiteBusyError(err) {
			return err
		}

		if attempt < len(delays) {
			time.Sleep(delays[attempt])
		}
	}

	return err
}

func (db *DB) execWrite(query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := db.withWriteRetry(func() error {
		var execErr error
		result, execErr = db.sqlDB.Exec(query, args...)
		return execErr
	})
	return result, err
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sql logic error: database table is locked")
}

func (db *DB) SaveScanReport(report *model.ScanReport) error {
	return db.withWriteRetry(func() error {
		return db.saveScanReportOnce(report)
	})
}

func (db *DB) saveScanReportOnce(report *model.ScanReport) error {
	if report == nil {
		return fmt.Errorf("scan report is nil")
	}

	tx, err := db.sqlDB.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if report.Platform == "" {
		report.Platform = "openlist"
	}

	result, err := tx.Exec(
		`INSERT INTO scan_reports (platform, scan_time, target_path, total_score, triggered_rules_count)
		 VALUES (?, ?, ?, ?, ?)`,
		report.Platform,
		report.ScanTime.Format(time.RFC3339),
		report.TargetPath,
		report.TotalScore,
		report.TriggeredRulesCount,
	)
	if err != nil {
		return err
	}

	scanReportID, err := result.LastInsertId()
	if err != nil {
		return err
	}

	report.ID = scanReportID

	for _, risk := range report.Risks {
		_, err = tx.Exec(
			`INSERT INTO risk_items (scan_report_id, rule_id, title, severity, description, recommendation)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			scanReportID,
			risk.RuleID,
			risk.Title,
			risk.Severity,
			risk.Description,
			risk.Recommendation,
		)
		if err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// TODO: add history query support here in the next step.
	// TODO: add pagination once scan history listing is implemented.
	// TODO: add log analysis persistence in a later phase.
	// TODO: extend storage support for other platforms in future work.
	return nil
}

func (db *DB) SaveSecurityEvents(events []model.SecurityEvent) error {
	return db.withWriteRetry(func() error {
		return db.saveSecurityEventsOnce(events)
	})
}

func (db *DB) saveSecurityEventsOnce(events []model.SecurityEvent) error {
	tx, err := db.sqlDB.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for i := range events {
		event := &events[i]
		if event.Platform == "" {
			event.Platform = "openlist"
		}
		if event.EventTime.IsZero() {
			event.EventTime = time.Now()
		}

		result, execErr := tx.Exec(
			`INSERT INTO security_events (platform, event_time, event_type, severity, actor, target, source_ip, raw_message)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			event.Platform,
			event.EventTime.Format(time.RFC3339),
			event.EventType,
			event.Severity,
			event.Actor,
			event.Target,
			event.SourceIP,
			event.RawMessage,
		)
		if execErr != nil {
			err = execErr
			return err
		}

		eventID, execErr := result.LastInsertId()
		if execErr != nil {
			err = execErr
			return err
		}

		event.ID = eventID
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// TODO: add event deduplication when repeated imports need cleanup.
	// TODO: add alert generation after the alerting module is introduced.
	// TODO: add filtering and pagination for large event datasets.
	// TODO: add real-time log monitoring support.
	return nil
}

func (db *DB) SaveAlerts(alerts []model.Alert) error {
	return db.withWriteRetry(func() error {
		return db.saveAlertsOnce(alerts)
	})
}

func (db *DB) saveAlertsOnce(alerts []model.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	tx, err := db.sqlDB.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for i := range alerts {
		alert := &alerts[i]
		if alert.Status == "" {
			alert.Status = "open"
		}
		if alert.CreatedAt.IsZero() {
			alert.CreatedAt = time.Now()
		}

		result, execErr := tx.Exec(
			`INSERT INTO alerts (source_type, source_ref, alert_type, severity, message, status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			alert.SourceType,
			alert.SourceRef,
			alert.AlertType,
			alert.Severity,
			alert.Message,
			alert.Status,
			alert.CreatedAt.Format(time.RFC3339),
		)
		if execErr != nil {
			err = execErr
			return err
		}

		alertID, execErr := result.LastInsertId()
		if execErr != nil {
			err = execErr
			return err
		}

		alert.ID = alertID
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// TODO: add alert suppression and deduplication rules.
	// TODO: add notification delivery once outbound channels are implemented.
	return nil
}

func (db *DB) SaveRecommendations(recommendations []model.Recommendation) error {
	return db.withWriteRetry(func() error {
		return db.saveRecommendationsOnce(recommendations)
	})
}

func (db *DB) saveRecommendationsOnce(recommendations []model.Recommendation) error {
	if len(recommendations) == 0 {
		return nil
	}

	tx, err := db.sqlDB.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for i := range recommendations {
		recommendation := &recommendations[i]
		if recommendation.Status == "" {
			recommendation.Status = "open"
		}
		if recommendation.CreatedAt.IsZero() {
			recommendation.CreatedAt = time.Now()
		}

		result, execErr := tx.Exec(
			`INSERT INTO recommendations (scan_report_id, rule_id, title, priority, recommendation, status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			recommendation.ScanReportID,
			recommendation.RuleID,
			recommendation.Title,
			recommendation.Priority,
			recommendation.Recommendation,
			recommendation.Status,
			recommendation.CreatedAt.Format(time.RFC3339),
		)
		if execErr != nil {
			err = execErr
			return err
		}

		recommendationID, execErr := result.LastInsertId()
		if execErr != nil {
			err = execErr
			return err
		}

		recommendation.ID = recommendationID
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// TODO: add recommendation deduplication and merge repeated guidance later.
	// TODO: add dashboard recommendation counters and remediation categories.
	return nil
}

func (db *DB) SaveAPIAuditLog(auditLog model.APIAuditLog) error {
	if auditLog.Timestamp.IsZero() {
		auditLog.Timestamp = time.Now()
	}

	successValue := 0
	if auditLog.Success {
		successValue = 1
	}

	apiKeyUsed := "false"
	if auditLog.APIKeyUsed {
		apiKeyUsed = "true"
	}

	_, err := db.execWrite(
		`INSERT INTO api_audit_logs (timestamp, method, path, status_code, client_ip, user_agent, api_key_used, success)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		auditLog.Timestamp.Format(time.RFC3339),
		auditLog.Method,
		auditLog.Path,
		auditLog.StatusCode,
		auditLog.ClientIP,
		auditLog.UserAgent,
		apiKeyUsed,
		successValue,
	)
	if err != nil {
		return err
	}

	// TODO: add audit log filtering, pagination, and request correlation IDs.
	// TODO: add actor/user identity once real authentication is implemented.
	// TODO: add suspicious API access detection rules.
	return nil
}

func (db *DB) InitializeDefaultSecurityRules(rules []model.SecurityRule) error {
	var count int
	if err := db.sqlDB.QueryRow(`SELECT COUNT(*) FROM security_rules`).Scan(&count); err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	return db.withWriteRetry(func() error {
		return db.initializeDefaultSecurityRulesOnce(rules)
	})
}

func (db *DB) initializeDefaultSecurityRulesOnce(rules []model.SecurityRule) error {
	tx, err := db.sqlDB.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now()
	for _, rule := range rules {
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = now
		}

		enabledValue := 0
		if rule.Enabled {
			enabledValue = 1
		}

		_, execErr := tx.Exec(
			`INSERT INTO security_rules (rule_id, platform, title, severity, enabled, description, recommendation, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			rule.RuleID,
			rule.Platform,
			rule.Title,
			rule.Severity,
			enabledValue,
			rule.Description,
			rule.Recommendation,
			rule.UpdatedAt.Format(time.RFC3339),
		)
		if execErr != nil {
			err = execErr
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	// TODO: support custom user-defined rules and per-platform rule sets.
	// TODO: add rule categories, rule versioning, and an advanced condition engine.
	return nil
}

func (db *DB) GetLatestScanReport() (*model.ScanReport, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, platform, scan_time, target_path, total_score, triggered_rules_count
		 FROM scan_reports
		 ORDER BY id DESC
		 LIMIT 1`,
	)

	report, err := db.scanReportFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return report, nil
}

func (db *DB) ListScanReports() ([]model.ScanReportSummary, error) {
	return db.ListScanReportsFiltered(nil, nil, "")
}

func (db *DB) ListScanReportsFiltered(minScore, maxScore *int, targetPath string) ([]model.ScanReportSummary, error) {
	query := `SELECT id, platform, scan_time, target_path, total_score, triggered_rules_count
		 FROM scan_reports`
	conditions := make([]string, 0)
	args := make([]any, 0)

	if minScore != nil {
		conditions = append(conditions, "total_score >= ?")
		args = append(args, *minScore)
	}

	if maxScore != nil {
		conditions = append(conditions, "total_score <= ?")
		args = append(args, *maxScore)
	}

	if targetPath != "" {
		conditions = append(conditions, "target_path = ?")
		args = append(args, targetPath)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC"

	rows, err := db.sqlDB.Query(
		query,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summaries := make([]model.ScanReportSummary, 0)
	for rows.Next() {
		summary, err := db.scanReportSummaryFromRows(rows)
		if err != nil {
			return nil, err
		}

		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return summaries, nil
}

func (db *DB) GetScanReportByID(id int64) (*model.ScanReport, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, platform, scan_time, target_path, total_score, triggered_rules_count
		 FROM scan_reports
		 WHERE id = ?`,
		id,
	)

	report, err := db.scanReportFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return report, nil
}

func (db *DB) ListSecurityEvents() ([]model.SecurityEvent, error) {
	return db.ListSecurityEventsFiltered("", "", "")
}

func (db *DB) ListSecurityEventsFiltered(eventType, severity, actor string) ([]model.SecurityEvent, error) {
	query := `SELECT id, platform, event_time, event_type, severity, actor, target, source_ip, raw_message
		 FROM security_events`
	conditions := make([]string, 0)
	args := make([]any, 0)

	if eventType != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, eventType)
	}

	if severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}

	if actor != "" {
		conditions = append(conditions, "actor = ?")
		args = append(args, actor)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC"

	rows, err := db.sqlDB.Query(
		query,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]model.SecurityEvent, 0)
	for rows.Next() {
		event, scanErr := scanSecurityEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func (db *DB) GetSecurityEventStats() (*model.SecurityEventStats, error) {
	stats := &model.SecurityEventStats{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	row := db.sqlDB.QueryRow(`SELECT COUNT(*) FROM security_events`)
	if err := row.Scan(&stats.TotalEvents); err != nil {
		return nil, err
	}

	typeRows, err := db.sqlDB.Query(
		`SELECT event_type, COUNT(*)
		 FROM security_events
		 GROUP BY event_type`,
	)
	if err != nil {
		return nil, err
	}
	defer typeRows.Close()

	for typeRows.Next() {
		var (
			eventType string
			count     int
		)

		if err := typeRows.Scan(&eventType, &count); err != nil {
			return nil, err
		}

		stats.ByType[eventType] = count
	}

	if err := typeRows.Err(); err != nil {
		return nil, err
	}

	severityRows, err := db.sqlDB.Query(
		`SELECT severity, COUNT(*)
		 FROM security_events
		 GROUP BY severity`,
	)
	if err != nil {
		return nil, err
	}
	defer severityRows.Close()

	for severityRows.Next() {
		var (
			severity string
			count    int
		)

		if err := severityRows.Scan(&severity, &count); err != nil {
			return nil, err
		}

		stats.BySeverity[severity] = count
	}

	if err := severityRows.Err(); err != nil {
		return nil, err
	}

	// TODO: add date range filters for event statistics.
	// TODO: add dashboard chart-oriented aggregation outputs.
	return stats, nil
}

func (db *DB) GetLatestSecurityEvent() (*model.SecurityEvent, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, platform, event_time, event_type, severity, actor, target, source_ip, raw_message
		 FROM security_events
		 ORDER BY id DESC
		 LIMIT 1`,
	)

	event, err := scanSecurityEventFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return event, nil
}

func (db *DB) GetSecurityEventByID(id int64) (*model.SecurityEvent, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, platform, event_time, event_type, severity, actor, target, source_ip, raw_message
		 FROM security_events
		 WHERE id = ?`,
		id,
	)

	event, err := scanSecurityEventFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return event, nil
}

func (db *DB) DeleteAllSecurityEvents() error {
	_, err := db.execWrite(`DELETE FROM security_events`)
	if err != nil {
		return err
	}

	// TODO: add audit logging for bulk delete operations.
	// TODO: add safer cleanup options once pagination and filtering are implemented.
	return nil
}

func (db *DB) DeleteAllAlerts() error {
	_, err := db.execWrite(`DELETE FROM alerts`)
	if err != nil {
		return err
	}

	// TODO: this development-only reset endpoint should be disabled or tightly restricted in production.
	return nil
}

func (db *DB) DeleteAllAPIAuditLogs() error {
	_, err := db.execWrite(`DELETE FROM api_audit_logs`)
	if err != nil {
		return err
	}

	// TODO: this development-only reset endpoint should be disabled or tightly restricted in production.
	return nil
}

func (db *DB) DeleteAllRecommendations() error {
	_, err := db.execWrite(`DELETE FROM recommendations`)
	if err != nil {
		return err
	}

	// TODO: this development-only reset endpoint should be disabled or tightly restricted in production.
	return nil
}

func (db *DB) ListAlerts() ([]model.Alert, error) {
	return db.ListAlertsFiltered("", "", "")
}

func (db *DB) ListSecurityRules() ([]model.SecurityRule, error) {
	rows, err := db.sqlDB.Query(
		`SELECT id, rule_id, platform, title, severity, enabled, description, recommendation, updated_at
		 FROM security_rules
		 ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]model.SecurityRule, 0)
	for rows.Next() {
		rule, scanErr := scanSecurityRule(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func (db *DB) GetSecurityRule(ruleID string) (*model.SecurityRule, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, rule_id, platform, title, severity, enabled, description, recommendation, updated_at
		 FROM security_rules
		 WHERE rule_id = ?`,
		ruleID,
	)

	rule, err := scanSecurityRuleFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return rule, nil
}

func (db *DB) UpdateSecurityRule(ruleID string, enabled *bool, severity string) error {
	currentRule, err := db.GetSecurityRule(ruleID)
	if err != nil {
		return err
	}
	if currentRule == nil {
		return sql.ErrNoRows
	}

	enabledValue := 0
	if currentRule.Enabled {
		enabledValue = 1
	}
	if enabled != nil {
		if *enabled {
			enabledValue = 1
		} else {
			enabledValue = 0
		}
	}

	nextSeverity := currentRule.Severity
	if severity != "" {
		nextSeverity = severity
	}

	result, err := db.execWrite(
		`UPDATE security_rules
		 SET enabled = ?, severity = ?, updated_at = ?
		 WHERE rule_id = ?`,
		enabledValue,
		nextSeverity,
		time.Now().Format(time.RFC3339),
		ruleID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (db *DB) ListAlertsFiltered(status, severity, alertType string) ([]model.Alert, error) {
	query := `SELECT id, source_type, source_ref, alert_type, severity, message, status, created_at
		 FROM alerts`
	conditions := make([]string, 0)
	args := make([]any, 0)

	if status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}

	if severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}

	if alertType != "" {
		conditions = append(conditions, "alert_type = ?")
		args = append(args, alertType)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC"

	rows, err := db.sqlDB.Query(
		query,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]model.Alert, 0)
	for rows.Next() {
		alert, scanErr := scanAlert(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		alerts = append(alerts, alert)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return alerts, nil
}

func (db *DB) GetLatestAlert() (*model.Alert, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, source_type, source_ref, alert_type, severity, message, status, created_at
		 FROM alerts
		 ORDER BY id DESC
		 LIMIT 1`,
	)

	alert, err := scanAlertFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return alert, nil
}

func (db *DB) GetAlertByID(id int64) (*model.Alert, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, source_type, source_ref, alert_type, severity, message, status, created_at
		 FROM alerts
		 WHERE id = ?`,
		id,
	)

	alert, err := scanAlertFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return alert, nil
}

func (db *DB) GetLatestRecommendations() ([]model.Recommendation, error) {
	var latestScanID int64
	err := db.sqlDB.QueryRow(`SELECT id FROM scan_reports ORDER BY id DESC LIMIT 1`).Scan(&latestScanID)
	if err != nil {
		if err == sql.ErrNoRows {
			return []model.Recommendation{}, nil
		}
		return nil, err
	}

	return db.GetRecommendationsByScanID(latestScanID)
}

func (db *DB) ListRecommendationsFiltered(status, priority string, scanReportID *int64) ([]model.Recommendation, error) {
	query := `SELECT id, scan_report_id, rule_id, title, priority, recommendation, status, created_at
		 FROM recommendations`
	conditions := make([]string, 0)
	args := make([]any, 0)

	if status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}

	if priority != "" {
		conditions = append(conditions, "priority = ?")
		args = append(args, priority)
	}

	if scanReportID != nil {
		conditions = append(conditions, "scan_report_id = ?")
		args = append(args, *scanReportID)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC"

	rows, err := db.sqlDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	recommendations := make([]model.Recommendation, 0)
	for rows.Next() {
		recommendation, scanErr := scanRecommendation(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		recommendations = append(recommendations, recommendation)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TODO: add pagination for recommendation history queries.
	// TODO: add keyword search, date-range filters, and sorting options.
	// TODO: consider full-text search for long recommendation text later.
	return recommendations, nil
}

func (db *DB) GetRecommendationsByScanID(scanID int64) ([]model.Recommendation, error) {
	return db.ListRecommendationsFiltered("", "", &scanID)
}

func (db *DB) GetRecommendationByID(id int64) (*model.Recommendation, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, scan_report_id, rule_id, title, priority, recommendation, status, created_at
		 FROM recommendations
		 WHERE id = ?`,
		id,
	)

	recommendation, err := scanRecommendationFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return recommendation, nil
}

func (db *DB) UpdateRecommendationStatus(id int64, status string) error {
	result, err := db.execWrite(`UPDATE recommendations SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	// TODO: add recommendation acceptance workflow and audit trail.
	return nil
}

func (db *DB) GetDashboardSummary() (*model.DashboardSummary, error) {
	summary := &model.DashboardSummary{
		Platform:     "openlist",
		SystemStatus: "healthy",
	}

	totalScans, err := db.countRows("scan_reports")
	if err != nil {
		return nil, err
	}
	summary.ScanSummary.TotalScans = totalScans

	latestScan, err := db.GetLatestScanReport()
	if err != nil {
		return nil, err
	}
	if latestScan != nil {
		summary.ScanSummary.LatestScanTime = &latestScan.ScanTime
		summary.ScanSummary.LatestScore = latestScan.TotalScore
		summary.ScanSummary.LatestTriggeredRulesCount = latestScan.TriggeredRulesCount
	}

	eventStats, err := db.GetSecurityEventStats()
	if err != nil {
		return nil, err
	}
	if eventStats != nil {
		summary.EventSummary.TotalEvents = eventStats.TotalEvents
		summary.EventSummary.HighSeverityEvents = eventStats.BySeverity["high"]
		summary.EventSummary.MediumSeverityEvents = eventStats.BySeverity["medium"]
		summary.EventSummary.LowSeverityEvents = eventStats.BySeverity["low"]
	}

	totalAlerts, err := db.countRows("alerts")
	if err != nil {
		return nil, err
	}
	summary.AlertSummary.TotalAlerts = totalAlerts

	openAlerts, err := db.countAlertsByStatus("open")
	if err != nil {
		return nil, err
	}
	summary.AlertSummary.OpenAlerts = openAlerts

	closedAlerts, err := db.countAlertsByStatus("closed")
	if err != nil {
		return nil, err
	}
	summary.AlertSummary.ClosedAlerts = closedAlerts

	latestAlert, err := db.GetLatestAlert()
	if err != nil {
		return nil, err
	}
	if latestAlert != nil {
		summary.AlertSummary.LatestAlertType = latestAlert.AlertType
	}

	// TODO: add time-range metrics for dashboard views.
	// TODO: add trend analysis and chart-friendly outputs.
	// TODO: add multi-platform aggregation in future versions.
	// TODO: add top risky actors and IP summaries.
	return summary, nil
}

func (db *DB) GetRiskTrend() ([]model.RiskTrendItem, error) {
	rows, err := db.sqlDB.Query(
		`SELECT id, scan_time, total_score, triggered_rules_count, target_path
		 FROM scan_reports
		 ORDER BY scan_time ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	trends := make([]model.RiskTrendItem, 0)
	for rows.Next() {
		var (
			item         model.RiskTrendItem
			scanTimeText string
		)

		if err := rows.Scan(
			&item.ScanID,
			&scanTimeText,
			&item.TotalScore,
			&item.TriggeredRulesCount,
			&item.TargetPath,
		); err != nil {
			return nil, err
		}

		scanTime, err := time.Parse(time.RFC3339, scanTimeText)
		if err != nil {
			return nil, err
		}
		item.ScanTime = scanTime

		trends = append(trends, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TODO: add date range filters, weekly/monthly grouping, and CSV export.
	// TODO: add chart-ready aggregation and per-platform analytics.
	return trends, nil
}

func (db *DB) GetTopRiskRules() ([]model.TopRiskRuleItem, error) {
	rows, err := db.sqlDB.Query(
		`SELECT rule_id, title, severity, COUNT(*) AS trigger_count
		 FROM risk_items
		 GROUP BY rule_id, title, severity
		 ORDER BY trigger_count DESC, rule_id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]model.TopRiskRuleItem, 0)
	for rows.Next() {
		var item model.TopRiskRuleItem
		if err := rows.Scan(
			&item.RuleID,
			&item.Title,
			&item.Severity,
			&item.TriggerCount,
		); err != nil {
			return nil, err
		}

		rules = append(rules, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TODO: add date range filters and per-platform analytics for top risk rules.
	return rules, nil
}

func (db *DB) GetAlertAnalyticsSummary() (*model.AlertAnalyticsSummary, error) {
	summary := &model.AlertAnalyticsSummary{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	totalAlerts, err := db.countRows("alerts")
	if err != nil {
		return nil, err
	}
	summary.TotalAlerts = totalAlerts

	openAlerts, err := db.countAlertsByStatus("open")
	if err != nil {
		return nil, err
	}
	summary.OpenAlerts = openAlerts

	closedAlerts, err := db.countAlertsByStatus("closed")
	if err != nil {
		return nil, err
	}
	summary.ClosedAlerts = closedAlerts

	typeRows, err := db.sqlDB.Query(
		`SELECT alert_type, COUNT(*)
		 FROM alerts
		 GROUP BY alert_type`,
	)
	if err != nil {
		return nil, err
	}
	defer typeRows.Close()

	for typeRows.Next() {
		var (
			alertType string
			count     int
		)
		if err := typeRows.Scan(&alertType, &count); err != nil {
			return nil, err
		}
		summary.ByType[alertType] = count
	}

	if err := typeRows.Err(); err != nil {
		return nil, err
	}

	severityRows, err := db.sqlDB.Query(
		`SELECT severity, COUNT(*)
		 FROM alerts
		 GROUP BY severity`,
	)
	if err != nil {
		return nil, err
	}
	defer severityRows.Close()

	for severityRows.Next() {
		var (
			severity string
			count    int
		)
		if err := severityRows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		summary.BySeverity[severity] = count
	}

	if err := severityRows.Err(); err != nil {
		return nil, err
	}

	// TODO: add date range filters, chart-ready aggregation, and weekly/monthly grouping.
	return summary, nil
}

func (db *DB) GetPolicy() (*model.SecurityPolicy, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, low_score_threshold, multiple_login_failures_threshold, long_token_hours_threshold, updated_at
		 FROM policies
		 WHERE id = 1`,
	)

	policy, err := scanPolicyFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			defaultPolicy := model.DefaultSecurityPolicy()
			return &defaultPolicy, nil
		}
		return nil, err
	}

	return policy, nil
}

func (db *DB) ListAPIAuditLogs() ([]model.APIAuditLog, error) {
	return db.ListAPIAuditLogsFiltered("", nil, nil, nil, "")
}

func (db *DB) ListAPIAuditLogsFiltered(method string, statusCode *int, success *bool, apiKeyUsed *bool, path string) ([]model.APIAuditLog, error) {
	query := `SELECT id, timestamp, method, path, status_code, client_ip, user_agent, api_key_used, success
		 FROM api_audit_logs`
	conditions := make([]string, 0)
	args := make([]any, 0)

	if method != "" {
		conditions = append(conditions, "method = ?")
		args = append(args, method)
	}

	if statusCode != nil {
		conditions = append(conditions, "status_code = ?")
		args = append(args, *statusCode)
	}

	if success != nil {
		successValue := 0
		if *success {
			successValue = 1
		}
		conditions = append(conditions, "success = ?")
		args = append(args, successValue)
	}

	if apiKeyUsed != nil {
		apiKeyValue := "false"
		if *apiKeyUsed {
			apiKeyValue = "true"
		}
		conditions = append(conditions, "api_key_used = ?")
		args = append(args, apiKeyValue)
	}

	if path != "" {
		conditions = append(conditions, "path = ?")
		args = append(args, path)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY id DESC"

	rows, err := db.sqlDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	auditLogs := make([]model.APIAuditLog, 0)
	for rows.Next() {
		auditLog, scanErr := scanAPIAuditLog(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		auditLogs = append(auditLogs, auditLog)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TODO: add pagination, date range filters, and sorting options for larger audit datasets.
	return auditLogs, nil
}

func (db *DB) GetLatestAPIAuditLog() (*model.APIAuditLog, error) {
	row := db.sqlDB.QueryRow(
		`SELECT id, timestamp, method, path, status_code, client_ip, user_agent, api_key_used, success
		 FROM api_audit_logs
		 ORDER BY id DESC
		 LIMIT 1`,
	)

	auditLog, err := scanAPIAuditLogFromRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return auditLog, nil
}

func (db *DB) UpdatePolicy(policy *model.SecurityPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy is nil")
	}

	if policy.ID == 0 {
		policy.ID = 1
	}
	if policy.UpdatedAt.IsZero() {
		policy.UpdatedAt = time.Now()
	}

	_, err := db.execWrite(
		`UPDATE policies
		 SET low_score_threshold = ?, multiple_login_failures_threshold = ?, long_token_hours_threshold = ?, updated_at = ?
		 WHERE id = ?`,
		policy.LowScoreThreshold,
		policy.MultipleLoginFailuresThreshold,
		policy.LongTokenHoursThreshold,
		policy.UpdatedAt.Format(time.RFC3339),
		policy.ID,
	)
	return err
}

func (db *DB) CloseAlert(id int64) error {
	result, err := db.execWrite(`UPDATE alerts SET status = 'closed' WHERE id = ?`, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	// TODO: support alert suppression and richer state transitions later.
	return nil
}

func (db *DB) countRows(tableName string) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	if err := db.sqlDB.QueryRow(query).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (db *DB) countAlertsByStatus(status string) (int, error) {
	var count int
	if err := db.sqlDB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE status = ?`, status).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (db *DB) scanReportFromRow(row *sql.Row) (*model.ScanReport, error) {
	var (
		id                  int64
		platform            string
		scanTimeText        string
		targetPath          string
		totalScore          int
		triggeredRulesCount int
	)

	if err := row.Scan(&id, &platform, &scanTimeText, &targetPath, &totalScore, &triggeredRulesCount); err != nil {
		return nil, err
	}

	scanTime, err := time.Parse(time.RFC3339, scanTimeText)
	if err != nil {
		return nil, err
	}

	risks, err := db.listRiskItemsByScanReportID(id)
	if err != nil {
		return nil, err
	}

	return &model.ScanReport{
		ID:                  id,
		Platform:            platform,
		ScanTime:            scanTime,
		TargetPath:          targetPath,
		TotalScore:          totalScore,
		TriggeredRulesCount: triggeredRulesCount,
		Risks:               risks,
	}, nil
}

func (db *DB) scanReportSummaryFromRows(rows *sql.Rows) (model.ScanReportSummary, error) {
	var (
		summary      model.ScanReportSummary
		scanTimeText string
	)

	if err := rows.Scan(
		&summary.ID,
		&summary.Platform,
		&scanTimeText,
		&summary.TargetPath,
		&summary.TotalScore,
		&summary.TriggeredRulesCount,
	); err != nil {
		return model.ScanReportSummary{}, err
	}

	scanTime, err := time.Parse(time.RFC3339, scanTimeText)
	if err != nil {
		return model.ScanReportSummary{}, err
	}

	summary.ScanTime = scanTime
	return summary, nil
}

func (db *DB) ensurePlatformColumn() error {
	hasPlatformColumn, err := db.scanReportsHasColumn("platform")
	if err != nil {
		return err
	}

	if hasPlatformColumn {
		_, err = db.execWrite(`UPDATE scan_reports SET platform = 'openlist' WHERE platform = '' OR platform IS NULL`)
		return err
	}

	if _, err := db.execWrite(`ALTER TABLE scan_reports ADD COLUMN platform TEXT NOT NULL DEFAULT 'openlist'`); err != nil {
		return err
	}

	_, err = db.execWrite(`UPDATE scan_reports SET platform = 'openlist' WHERE platform = '' OR platform IS NULL`)
	return err
}

func (db *DB) ensureDefaultPolicy() error {
	var count int
	if err := db.sqlDB.QueryRow(`SELECT COUNT(*) FROM policies WHERE id = 1`).Scan(&count); err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	defaultPolicy := model.DefaultSecurityPolicy()
	_, err := db.execWrite(
		`INSERT INTO policies (id, low_score_threshold, multiple_login_failures_threshold, long_token_hours_threshold, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		defaultPolicy.ID,
		defaultPolicy.LowScoreThreshold,
		defaultPolicy.MultipleLoginFailuresThreshold,
		defaultPolicy.LongTokenHoursThreshold,
		defaultPolicy.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

func (db *DB) scanReportsHasColumn(columnName string) (bool, error) {
	rows, err := db.sqlDB.Query(`PRAGMA table_info(scan_reports)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal any
			pk         int
		)

		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return false, err
		}

		if name == columnName {
			return true, nil
		}
	}

	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

func (db *DB) listRiskItemsByScanReportID(scanReportID int64) ([]model.RiskItem, error) {
	rows, err := db.sqlDB.Query(
		`SELECT rule_id, title, severity, description, recommendation
		 FROM risk_items
		 WHERE scan_report_id = ?
		 ORDER BY id ASC`,
		scanReportID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	risks := make([]model.RiskItem, 0)
	for rows.Next() {
		var risk model.RiskItem
		if err := rows.Scan(
			&risk.RuleID,
			&risk.Title,
			&risk.Severity,
			&risk.Description,
			&risk.Recommendation,
		); err != nil {
			return nil, err
		}

		risks = append(risks, risk)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return risks, nil
}

func scanSecurityEvent(rowScanner interface {
	Scan(dest ...any) error
}) (model.SecurityEvent, error) {
	var (
		event         model.SecurityEvent
		eventTimeText string
	)

	if err := rowScanner.Scan(
		&event.ID,
		&event.Platform,
		&eventTimeText,
		&event.EventType,
		&event.Severity,
		&event.Actor,
		&event.Target,
		&event.SourceIP,
		&event.RawMessage,
	); err != nil {
		return model.SecurityEvent{}, err
	}

	parsedTime, err := time.Parse(time.RFC3339, eventTimeText)
	if err != nil {
		return model.SecurityEvent{}, err
	}

	event.EventTime = parsedTime
	return event, nil
}

func scanSecurityEventFromRow(row *sql.Row) (*model.SecurityEvent, error) {
	event, err := scanSecurityEvent(row)
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func scanAlert(rowScanner interface {
	Scan(dest ...any) error
}) (model.Alert, error) {
	var (
		alert         model.Alert
		createdAtText string
	)

	if err := rowScanner.Scan(
		&alert.ID,
		&alert.SourceType,
		&alert.SourceRef,
		&alert.AlertType,
		&alert.Severity,
		&alert.Message,
		&alert.Status,
		&createdAtText,
	); err != nil {
		return model.Alert{}, err
	}

	createdAt, err := time.Parse(time.RFC3339, createdAtText)
	if err != nil {
		return model.Alert{}, err
	}

	alert.CreatedAt = createdAt
	return alert, nil
}

func scanAlertFromRow(row *sql.Row) (*model.Alert, error) {
	alert, err := scanAlert(row)
	if err != nil {
		return nil, err
	}

	return &alert, nil
}

func scanRecommendation(rowScanner interface {
	Scan(dest ...any) error
}) (model.Recommendation, error) {
	var (
		recommendation model.Recommendation
		createdAtText  string
	)

	if err := rowScanner.Scan(
		&recommendation.ID,
		&recommendation.ScanReportID,
		&recommendation.RuleID,
		&recommendation.Title,
		&recommendation.Priority,
		&recommendation.Recommendation,
		&recommendation.Status,
		&createdAtText,
	); err != nil {
		return model.Recommendation{}, err
	}

	createdAt, err := time.Parse(time.RFC3339, createdAtText)
	if err != nil {
		return model.Recommendation{}, err
	}

	recommendation.CreatedAt = createdAt
	return recommendation, nil
}

func scanRecommendationFromRow(row *sql.Row) (*model.Recommendation, error) {
	recommendation, err := scanRecommendation(row)
	if err != nil {
		return nil, err
	}

	return &recommendation, nil
}

func scanPolicy(rowScanner interface {
	Scan(dest ...any) error
}) (model.SecurityPolicy, error) {
	var (
		policy        model.SecurityPolicy
		updatedAtText string
	)

	if err := rowScanner.Scan(
		&policy.ID,
		&policy.LowScoreThreshold,
		&policy.MultipleLoginFailuresThreshold,
		&policy.LongTokenHoursThreshold,
		&updatedAtText,
	); err != nil {
		return model.SecurityPolicy{}, err
	}

	updatedAt, err := time.Parse(time.RFC3339, updatedAtText)
	if err != nil {
		return model.SecurityPolicy{}, err
	}

	policy.UpdatedAt = updatedAt
	return policy, nil
}

func scanPolicyFromRow(row *sql.Row) (*model.SecurityPolicy, error) {
	policy, err := scanPolicy(row)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func scanSecurityRule(rowScanner interface {
	Scan(dest ...any) error
}) (model.SecurityRule, error) {
	var (
		rule          model.SecurityRule
		enabledValue  int
		updatedAtText string
	)

	if err := rowScanner.Scan(
		&rule.ID,
		&rule.RuleID,
		&rule.Platform,
		&rule.Title,
		&rule.Severity,
		&enabledValue,
		&rule.Description,
		&rule.Recommendation,
		&updatedAtText,
	); err != nil {
		return model.SecurityRule{}, err
	}

	updatedAt, err := time.Parse(time.RFC3339, updatedAtText)
	if err != nil {
		return model.SecurityRule{}, err
	}

	rule.Enabled = enabledValue == 1
	rule.UpdatedAt = updatedAt
	return rule, nil
}

func scanSecurityRuleFromRow(row *sql.Row) (*model.SecurityRule, error) {
	rule, err := scanSecurityRule(row)
	if err != nil {
		return nil, err
	}

	return &rule, nil
}

func scanAPIAuditLog(rowScanner interface {
	Scan(dest ...any) error
}) (model.APIAuditLog, error) {
	var (
		auditLog      model.APIAuditLog
		timestampText string
		apiKeyUsed    string
		successValue  int
	)

	if err := rowScanner.Scan(
		&auditLog.ID,
		&timestampText,
		&auditLog.Method,
		&auditLog.Path,
		&auditLog.StatusCode,
		&auditLog.ClientIP,
		&auditLog.UserAgent,
		&apiKeyUsed,
		&successValue,
	); err != nil {
		return model.APIAuditLog{}, err
	}

	timestamp, err := time.Parse(time.RFC3339, timestampText)
	if err != nil {
		return model.APIAuditLog{}, err
	}

	auditLog.Timestamp = timestamp
	auditLog.APIKeyUsed = apiKeyUsed == "true"
	auditLog.Success = successValue == 1
	return auditLog, nil
}

func scanAPIAuditLogFromRow(row *sql.Row) (*model.APIAuditLog, error) {
	auditLog, err := scanAPIAuditLog(row)
	if err != nil {
		return nil, err
	}

	return &auditLog, nil
}

func (db *DB) Close() error {
	if db == nil || db.sqlDB == nil {
		return nil
	}

	return db.sqlDB.Close()
}
