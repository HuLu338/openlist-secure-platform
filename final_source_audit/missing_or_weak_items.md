# Missing or Weak Items

Audit date: 2026-07-07

## Must Fix Before Packaging

| Item | Why it matters | Recommended action |
|---|---|---|
| Root README is missing | Thesis submission/package needs clear setup, run, test, and evaluation instructions. | Add `README.md` at project root covering backend, frontend, env vars, DB, API key, evaluation, screenshots, and project structure. |
| Frontend README is default Vite text | Does not explain the OpenList Secure Platform frontend. | Replace with project-specific frontend instructions or consolidate into root README. |
| Development API key default is hardcoded | Fine for local demo, but weak for public packaging/security explanation. | Add `.env.example`, document `X-API-Key`, and state `change-***-dev-key` is local-only. Prefer env override. |
| Signing-related configuration is not a distinct rule | Contribution text mentions signing-related configuration if applicable. | Either add a representative signing rule or revise thesis wording so it does not overclaim. |

## Should Fix If Time Allows

| Item | Why it matters | Recommended action |
|---|---|---|
| Dashboard consistency not evaluated by a dedicated script | Objective 4 mentions frontend/dashboard verification. | Add a small script or screenshot workflow proving dashboard values after evaluation. |
| Evaluation scripts add data on each run | Repeated runs accumulate scans/events/alerts unless reset is used. | Document `--reset` and explain it is development-only. |
| WebDAV coverage is representative | The scanner/parser does not claim full OpenList WebDAV schema coverage. | Document representative rule scope in README/thesis. |
| API docs only runtime/static endpoint | Useful but not enough for offline project review. | Add endpoint list to README/docs. |
| Frontend platform selector/future platform params are UI-side only | Backend is OpenList-only by design. | Avoid claiming real multi-platform support; document as future-ready UI. |

## Nice To Have

| Item | Benefit |
|---|---|
| CI workflow | Reproducible build/test evidence. |
| Browser/e2e frontend tests | Stronger frontend verification beyond build. |
| More exact OpenList log schema support | Stronger production relevance. |
| More rule categories and rule metadata | Better thesis traceability. |
| Stronger auth than shared API key | Better production security story. |
| Pagination/date filters across all heavy endpoints | Better scalability. |

## Not Blocking

- Backend tests pass.
- Frontend build passes.
- Evaluation scripts pass.
- SQLite schema supports scans, findings, events, alerts, policies, rules, audit logs, and recommendations.
- API security works for missing, invalid, and valid API key checks.
