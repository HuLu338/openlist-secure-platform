# Endpoint Coverage Check

Audit date: 2026-07-07

## API Security Summary

| Check | Result | Evidence |
|---|---|---|
| Public endpoints | `/health` only | API key middleware bypasses `/health`. |
| Protected endpoints | All management APIs | Middleware wraps router and rejects missing/invalid `X-API-Key`. |
| Missing API key | HTTP 401 | Manual check: `GET /dashboard/summary` returned 401. |
| Invalid API key | HTTP 401 | Manual check with wrong key returned 401. |
| Valid API key | HTTP 200 | Manual check with valid local key returned 200. |
| Audit logging | Implemented | `auditMiddleware` writes `api_audit_logs` after each request except audit reset. |
| API key source | Default in config; frontend/evaluation fallback | Local demo key is hardcoded as fallback. Should be documented/replaced for packaging. |

## Missing / Invalid / Valid API Key Table

| Case | Endpoint | Expected | Actual | Status |
|---|---|---:|---:|---|
| Missing key | `GET /dashboard/summary` | 401 | 401 | Pass |
| Invalid key | `GET /dashboard/summary` | 401 | 401 | Pass |
| Valid key | `GET /dashboard/summary` | 200 | 200 | Pass |

## Endpoint Matrix

| Endpoint | Method | Purpose | Protected by API key? | Tested? | Status |
|---|---|---|---:|---:|---|
| `/health` | GET | Health check | No | Manual/API status | **Implemented** |
| `/scan/start` | POST | Run config scan | Yes | Evaluation | **Implemented** |
| `/scans` | GET | List scans with filters | Yes | API auth/frontend | **Implemented** |
| `/scans/latest` | GET | Latest scan | Yes | Frontend/manual coverage | **Implemented** |
| `/scans/{id}` | GET | Scan detail | Yes | Partial | **Implemented** |
| `/events/import` | POST | Import log file | Yes | Evaluation | **Implemented** |
| `/events` | GET/DELETE | List/filter events; dev clear | Yes | Evaluation/frontend | **Implemented** |
| `/events/latest` | GET | Latest event | Yes | Frontend | **Implemented** |
| `/events/{id}` | GET | Event detail | Yes | Partial | **Implemented** |
| `/events/stats` | GET | Event statistics | Yes | Evaluation optional context/frontend | **Implemented** |
| `/alerts` | GET | List/filter alerts | Yes | API auth/frontend/evaluation | **Implemented** |
| `/alerts/latest` | GET | Latest alert | Yes | Frontend | **Implemented** |
| `/alerts/{id}` | GET | Alert detail | Yes | Partial | **Implemented** |
| `/alerts/{id}/close` | PATCH | Close alert | Yes | Frontend action | **Implemented** |
| `/policies` | GET/PATCH | Policy view/update | Yes | Policy script/frontend | **Implemented** |
| `/rules` | GET | List rules | Yes | Evaluation setup/frontend | **Implemented** |
| `/rules/{rule_id}` | GET/PATCH | Rule detail/update | Yes | Evaluation setup/frontend | **Implemented** |
| `/recommendations` | GET | List/filter recommendations | Yes | Frontend | **Implemented** |
| `/recommendations/latest` | GET | Latest scan recommendations | Yes | Frontend | **Implemented** |
| `/recommendations/scan/{id}` | GET | Recommendations by scan | Yes | Frontend/API client | **Implemented** |
| `/recommendations/{id}/status` | PATCH | Update recommendation status | Yes | Frontend action | **Implemented** |
| `/dashboard/summary` | GET | Dashboard aggregate | Yes | API auth/frontend | **Implemented** |
| `/audit/api` | GET | List/filter API audit logs | Yes | API auth/frontend | **Implemented** |
| `/audit/api/latest` | GET | Latest API audit log | Yes | Frontend | **Implemented** |
| `/analytics/risk-trends` | GET | Scan score trend | Yes | Frontend/API client | **Implemented** |
| `/analytics/risk-rules/top` | GET | Frequent risk rules | Yes | Frontend/API client | **Implemented** |
| `/analytics/alerts/summary` | GET | Alert analytics | Yes | Frontend/API client | **Implemented** |
| `/assistant/chat` | POST | Floating assistant chat | Yes | Frontend/build; service unit tests | **Implemented** |
| `/assistant/ask` | POST | Local assistant ask | Yes | Unit tests/service | **Implemented** |
| `/assistant/suggestions` | GET | Suggested questions | Yes | API docs/client | **Implemented** |
| `/assistant/context` | GET | Assistant context counts | Yes | API docs/client | **Implemented** |
| `/api/docs` | GET | Static API documentation | Yes | Router evidence | **Implemented** |
| `/admin/reset/events` | DELETE | Dev reset events | Yes | API client/evaluator optional reset | **Implemented** |
| `/admin/reset/alerts` | DELETE | Dev reset alerts | Yes | API client/evaluator optional reset | **Implemented** |
| `/admin/reset/audit` | DELETE | Dev reset audit logs | Yes | API client/evaluator optional reset | **Implemented** |
| `/admin/reset/recommendations` | DELETE | Dev reset recommendations | Yes | API client/evaluator optional reset | **Implemented** |

## Notes

- The endpoint surface is broad and consistent with the thesis prototype.
- Some detail/latest endpoints are implemented and consumed by frontend/API client but are not all separately asserted by a dedicated script.
- Development reset endpoints should remain documented as development-only and restricted/disabled for production-like deployment.
