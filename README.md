# OpenList Secure Platform

A risk-based security assessment and management dashboard for OpenList-based self-hosted file systems.

**Author:** Gong Bingyan | **Stack:** Go, SQLite, React, TypeScript, Vite

## Highlights

- Configuration scanning with configurable rules, finding categories, evidence, remediation advice, and a per-rule scoring breakdown.
- Security event import, filtering, statistics, and policy-driven alerts for representative OpenList, WebDAV, and token scenarios.
- Scan history, remediation workflows, editable policies/rules, audit trails, and risk analytics in a web dashboard.
- API key protection, unified error responses, SQLite persistence, and automated tests and scenario evaluation.
- A floating assistant using local deterministic guidance by default, with optional backend-only OpenAI integration.

This is a final-year project prototype, not a production security product. OpenList config/log coverage is representative rather than exhaustive. Management APIs accept server-local file paths and include development reset endpoints; run the demo locally and do not expose it directly to the public internet. The browser's admin key is visible to browser users and is not a substitute for user authentication.

## Project Description

OpenList Secure Platform is a final-year project prototype for security management of OpenList-based self-hosted file systems. It provides backend and frontend support for configuration scanning, structured findings, weighted risk scoring, scan history, security event importing, policy-driven alerts, remediation recommendations, API audit records, API key protection, analytics, dashboard visualization, and a local floating AI assistant.

The current implementation focuses on OpenList. The core architecture is intentionally designed so future adapters, such as other self-hosted file systems, can be added without rewriting the generic security-management logic.

## Architecture Overview

- Backend: Go's standard `net/http` package, with SQLite through `modernc.org/sqlite`; no Gin or ORM framework.
- OpenList adapter layer: `internal/adapters/openlist` contains OpenList-specific configuration reading, rule matching, and log parsing.
- Security core layer: `internal/core` contains platform-generic models, contracts, scoring, services, alerts, policies, recommendations, assistant logic, and analytics concepts.
- SQLite storage layer: `internal/storage/sqlite` persists scan reports, risk findings, security events, alerts, policies, rules, recommendations, and API audit logs.
- REST API layer: `internal/httpapi` exposes protected management APIs and the public health check.
- Frontend management interface: `frontend` is a React + TypeScript + Vite dashboard that consumes backend APIs.

```text
cmd/server/                   Server entry point
internal/adapters/openlist/   Config rules and log parser
internal/core/                Shared models, contracts, scoring, services
internal/httpapi/             Routing, validation, auth and audit middleware
internal/storage/sqlite/      SQL persistence and migrations
frontend/src/                 Dashboard pages and reusable components
evaluation/                   Fixtures and Python evaluation scripts
final_source_audit/           Historical project audit notes
```

## Backend Setup

```bash
go mod download
go run ./cmd/server
```

The backend listens on `http://localhost:8080` by default.

## Backend Tests

```bash
go test ./...
```

To build the backend server target:

```bash
go build ./cmd/server
```

## Frontend Setup

This project uses npm because `frontend/package-lock.json` is present.

```bash
cd frontend
npm install
npm run dev
```

The Vite development server normally runs at `http://localhost:5173`.

Keep the backend running in a separate terminal. Vite forwards `/backend-api` requests to port 8080 so frontend routes remain on port 5173. Backend setup requires Go 1.25 or newer; use Node.js 22.12 or newer for the Vite frontend.

To check both builds:

```bash
go test ./...
go build ./...
cd frontend
npm run build
```

## Local Demo

1. Start the backend and frontend using the commands above.
2. In Scan History, scan `evaluation/configs/config_safe.json`, then `evaluation/configs/config_critical_weak_secret.json` (paths are resolved by the backend from its working directory).
3. In Events, import `evaluation/logs/log_mixed_security_events.log`.
4. Review findings, scoring breakdown, alerts, recommendations, audit logs, and Analytics. Open the floating assistant to ask what to fix first.

Evaluation also creates scan/event/alert records and temporarily updates policies or rules. Use a disposable local demo database for evaluation; do not run it against important operational data. Generated results stay in `evaluation/results/` and are not committed.

## API Key Usage

All management APIs require the `X-API-Key` request header. The only public endpoint is:

```text
GET /health
```

For local development and evaluation, the backend reads the API key from:

```bash
export OPENLIST_SECURITY_API_KEY=your-own-key
```

If `OPENLIST_SECURITY_API_KEY` is not set, the backend uses a clearly labelled local development/testing fallback key: `change-me-dev-key`. This fallback is not a production secret and should be changed for any packaged demo or deployment.

For the frontend, set the matching Vite environment variable when needed:

```bash
cd frontend
VITE_ADMIN_API_KEY=your-own-key npm run dev
```

Do not commit real API keys, OpenAI keys, or production secrets. Optional OpenAI assistant mode reads `OPENAI_API_KEY` only on the Go backend side.

## Main API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/scan/start` | Run an OpenList configuration scan. |
| GET | `/scans` | List scan history summaries. |
| GET | `/scans/latest` | Get the latest scan report. |
| POST | `/events/import` | Import and parse an OpenList log file. |
| GET | `/events` | List security events. |
| GET | `/events/stats` | Get event statistics. |
| GET | `/alerts` | List generated alerts. |
| GET | `/alerts/latest` | Get latest alert. |
| GET | `/policies` | Get active policy thresholds. |
| PATCH | `/policies` | Update active policy thresholds. |
| GET | `/dashboard/summary` | Get dashboard summary data. |
| GET | `/audit/api` | List API audit logs. |
| GET | `/api/docs` | Get static API documentation grouped by module. |

Additional implemented modules include rules, recommendations, analytics, assistant, and development reset endpoints.

## Implemented Security Coverage

Representative OpenList configuration rules include:

- TLS certificate verification skipped: `openlist-tls-skip-verify`
- Weak JWT secret: `openlist-jwt-secret-weak`
- Token validity too long: `openlist-token-validity-too-long`
- HTTPS disabled: `openlist-https-disabled`
- Logging disabled: `openlist-logging-disabled`
- FTP/SFTP protocol exposure: `openlist-ftp-enabled`, `openlist-sftp-enabled`
- Risky WebDAV access: `openlist-webdav-risky-access`
- Public deployment with Sign All / direct link signing disabled: `openlist-sign-all-disabled`

The signing-related rule is a representative prototype rule. It checks supported fixture-style keys such as `security.sign_all=false` combined with public exposure keys such as `deployment.public=true`. It should not be interpreted as full production coverage of every OpenList signing option.

## Evaluation Commands

Start the backend first:

```bash
go run ./cmd/server
```

Then run:

```bash
python3 evaluation/test_api_auth.py
python3 evaluation/test_policy_threshold.py
python3 evaluation/evaluate_security_scenarios.py
python3 evaluation/check_dashboard_consistency.py
```

The evaluation scripts use the Python standard library only. They write generated evidence under `evaluation/results/`.

## Database Notes

SQLite is used for local persistence. By default, runtime data is created at:

```text
./data/scan_history.db
```

The database directory and tables are created automatically. SQLite runtime database files are generated during testing/runtime and may be excluded from final source submission unless runtime evidence is specifically required.

## Source Submission Notes

The final source package should include source code, fixtures, evaluation scripts, README files, and audit documentation. It should not include:

- `.git/`
- `frontend/node_modules/`
- frontend build output such as `frontend/dist/`
- Go build binaries such as `server`
- runtime SQLite database files under `data/` unless explicitly required
- real API keys, OpenAI keys, or private credentials

## Useful Local URLs

- Backend health: `http://localhost:8080/health`
- Frontend dev server: `http://localhost:5173/`
- API docs endpoint: `http://localhost:8080/api/docs` with `X-API-Key`
