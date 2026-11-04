Project Title:
Design and Implementation of a Risk-Based Security Assessment and Management Platform for OpenList-Based Self-Hosted File System

Student:
Gong Bingyan

Run Backend:
go mod tidy
go run ./cmd/server

Run Frontend:
cd frontend
npm install
npm run dev
npm run build

Run Backend Tests:
go test ./...
go build ./cmd/server

Run Evaluation Scripts:
Start the backend first with: go run ./cmd/server
Then run:
python3 evaluation/test_api_auth.py
python3 evaluation/test_policy_threshold.py
python3 evaluation/evaluate_security_scenarios.py
python3 evaluation/check_dashboard_consistency.py

API Key Note:
Management APIs require X-API-Key. Set OPENLIST_SECURITY_API_KEY for backend runs. If unset, the project uses the local development/testing fallback key change-me-dev-key. Do not submit real production secrets.

Submission Exclusion Notes:
Do not include .git, frontend/node_modules, frontend/dist, generated Go binaries, or runtime SQLite database files unless specifically required. Runtime SQLite files are generated automatically during testing and execution.
