# Screenshot Checklist for Thesis Evidence

Use this checklist after starting both services:

- Backend: `go run ./cmd/server`
- Frontend: `cd frontend && npm run dev`

Before taking screenshots, run the evaluation fixtures or manually create enough demo data so pages are not empty.

## 1. Dashboard

- Screenshot file name: `dashboard_overview.png`
- Page URL: http://localhost:5173/
- Purpose: Show system summary, latest score, scans, events, alerts, and risk trend.
- Data to prepare:
  - Run at least one configuration scan.
  - Import at least one log file.
  - Ensure at least one alert exists.
  - Ensure analytics/risk trend data is visible.
- What the screenshot proves:
  - The platform provides a high-level security posture overview.
  - Scan, event, alert, and trend information are aggregated into one dashboard.
- Thesis chapter:
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results

## 2. Scan History / Findings

- Screenshot file names:
  - `scan_history_overview.png`
  - `scan_result_findings.png`
- Page URL: http://localhost:5173/scans
- Purpose: Show scan list, latest scan, rule_id, severity, evidence, recommendation, and scoring breakdown if visible.
- Data to prepare:
  - Run scans using the evaluation config files.
  - Use at least one risky config such as `evaluation/configs/config_critical_weak_secret.json`.
  - Confirm scan API responses include `risks`, `evidence`, and `scoring_breakdown`.
- What the screenshot proves:
  - The platform can scan OpenList configuration files.
  - Findings include rule IDs, severity, evidence, recommendations, and score information.
- Thesis chapter:
  - Chapter 3: Methodology and Scoring Design
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results

## 3. Alerts

- Screenshot file name: `alerts_page.png`
- Page URL: http://localhost:5173/alerts
- Purpose: Show latest alert, alert filters, alert table, severity, status, and alert source.
- Data to prepare:
  - Run a risky configuration scan that triggers a low score or critical-risk alert.
  - Import logs that trigger high severity events or repeated login failures.
  - Keep several alerts open so status and severity badges are visible.
- What the screenshot proves:
  - The platform converts important scan and event conditions into actionable alerts.
  - Alert filtering and status handling are available.
- Thesis chapter:
  - Chapter 3: Alert Trigger Logic
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results

## 4. API Audit Logs

- Screenshot file name: `api_audit_logs.png`
- Page URL: http://localhost:5173/audit
- Purpose: Show authorized and unauthorized API access records.
- Data to prepare:
  - Make at least one authorized API request using `X-API-Key: change-me-dev-key`.
  - Make at least one unauthorized API request without `X-API-Key`.
  - Run `python3 evaluation/test_api_auth.py` if available.
- What the screenshot proves:
  - The platform records API access activity.
  - Both successful and failed/unauthorized requests can be audited.
- Thesis chapter:
  - Chapter 4: Security Controls
  - Chapter 5: Evaluation and Results

## 5. Policies

- Screenshot file name: `policies_page.png`
- Page URL: http://localhost:5173/policies
- Purpose: Show policy thresholds and editable policy form.
- Data to prepare:
  - Ensure the backend database has initialized the default policy.
  - Optionally run `python3 evaluation/test_policy_threshold.py` to demonstrate before-after policy behavior.
  - Restore normal threshold values before final screenshots if needed.
- What the screenshot proves:
  - Security thresholds are configurable through the management UI.
  - Policy settings can influence scan interpretation or alerting behavior.
- Thesis chapter:
  - Chapter 3: Policy and Rule Configuration
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results

## 6. Analytics / Risk Trends

- Screenshot file name: `analytics_risk_trends.png`
- Page URL: http://localhost:5173/analytics
- Purpose: Show risk trend, alert summary, alert severity/type, and top risk rules.
- Data to prepare:
  - Run multiple configuration scans so the risk trend has several points.
  - Import logs and generate alerts so alert summary charts are populated.
  - Ensure top risk rules table has triggered rule data.
- What the screenshot proves:
  - The platform supports trend analysis and aggregated security analytics.
  - Frequently triggered rules and alert distributions can be reviewed visually.
- Thesis chapter:
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results

## 7. Floating AI Assistant

- Screenshot file names:
  - `floating_assistant_closed.png`
  - `floating_assistant_open.png`
- Page URL: Any frontend page, for example http://localhost:5173/
- Purpose: Show the floating robot widget, chat panel, mode badge, sources, and suggested actions.
- Data to prepare:
  - Ensure the backend is running.
  - Ask a question such as `What should I fix first?`.
  - Use local mode by default, or OpenAI mode if backend environment variables are configured.
  - Confirm the response shows mode, sources, and suggested actions.
- What the screenshot proves:
  - The platform includes a globally available AI-style security assistant.
  - The assistant can explain local security data without exposing API keys in the frontend.
- Thesis chapter:
  - Chapter 4: System Implementation
  - Chapter 5: Evaluation and Results
