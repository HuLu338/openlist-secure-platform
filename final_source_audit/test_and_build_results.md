# Test and Build Results

Audit date: 2026-07-07

## Commands Run

| Command | Result | Output summary |
|---|---|---|
| `go test ./...` | Pass | All Go packages passed; some packages have no test files. |
| `go build ./cmd/server` | Pass | Backend server target built successfully. Generated root `server` binary was removed as a build artifact. |
| `cd frontend && npm install` | Pass | `up to date in 613ms`; npm package manager detected from `package-lock.json`. |
| `cd frontend && npm run build` | Pass | `tsc -b && vite build` succeeded; 46 modules transformed. |
| `python3 evaluation/test_api_auth.py` | Pass | 8 total tests, 8 passed, 0 failed. |
| `python3 evaluation/test_policy_threshold.py` | Pass | Test passed and original policy restored. |
| `python3 evaluation/evaluate_security_scenarios.py` | Pass | 12 scenarios passed, 0 failed. |

## Backend Test Coverage Observed

| Area | Test file | Coverage note |
|---|---|---|
| Scoring | `internal/core/scoring/scoring_test.go` | Severity weights and score floor. |
| Config scanner | `internal/adapters/openlist/config_scanner_test.go` | Risky/safe configs, disabled rules, severity change, policy token threshold, WebDAV evidence/category. |
| Log parser | `internal/adapters/openlist/log_parser_test.go` | Login, file, admin, WebDAV, token, unknown events. |
| Scan service | `internal/core/service/scan_service_test.go` | Recommendations and scan alert generation. |
| Event service | `internal/core/service/event_service_test.go` | Multiple login failures, WebDAV/admin alert types. |
| Assistant service | `internal/core/service/assistant_service_test.go` | Intent/fallback/fix-priority behavior. |
| Router | `internal/httpapi/router_test.go` | Route/middleware behavior coverage. |

## Evaluation Script Results

| Script | Result | Output file |
|---|---|---|
| `evaluation/test_api_auth.py` | 8/8 pass | `evaluation/results/api_auth_test_results.json` |
| `evaluation/test_policy_threshold.py` | Pass, policy restored | `evaluation/results/policy_threshold_test_results.json` |
| `evaluation/evaluate_security_scenarios.py` | 12/12 pass | `evaluation/results/evaluation_matrix.csv`, `evaluation/results/evaluation_summary.json` |

## Evaluation Matrix Summary

| Scenario | Status |
|---|---|
| `config_safe` | Pass |
| `config_critical_weak_secret` | Pass |
| `config_transport_insecure` | Pass |
| `config_logging_disabled` | Pass |
| `config_protocol_exposure` | Pass |
| `config_webdav_risky` | Pass |
| `log_normal_activity` | Pass |
| `log_repeated_login_failures` | Pass |
| `log_admin_sensitive_actions` | Pass |
| `log_mixed_security_events` | Pass |
| `log_webdav_activity` | Pass |
| `log_token_activity` | Pass |

## Frontend Build Check

| Check | Result |
|---|---|
| Package manager | npm (`frontend/package-lock.json`) |
| Dependencies install | Pass |
| TypeScript build | Pass |
| Vite build | Pass |
| Pages present | Dashboard, Scan History, Events, Alerts, Rules, Policies, Recommendations, Audit Logs, Analytics |
| Floating assistant | Present globally via `FloatingAssistant` |
