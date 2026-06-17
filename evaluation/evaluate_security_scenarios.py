#!/usr/bin/env python3
"""Run OpenList Secure Platform evaluation scenarios.

This script assumes the Go backend is already running at http://localhost:8080.
It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BACKEND_BASE_URL = "http://localhost:8080"
API_KEY = "change-me-dev-key"
ROOT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = ROOT_DIR / "configs"
LOG_DIR = ROOT_DIR / "logs"
RESULTS_DIR = ROOT_DIR / "results"
MATRIX_PATH = RESULTS_DIR / "evaluation_matrix.csv"
SUMMARY_PATH = RESULTS_DIR / "evaluation_summary.json"


CONFIG_SCENARIOS = [
    {
        "scenario_id": "config_safe",
        "input_file": CONFIG_DIR / "config_safe.json",
        "expected_findings": [],
    },
    {
        "scenario_id": "config_critical_weak_secret",
        "input_file": CONFIG_DIR / "config_critical_weak_secret.json",
        "expected_findings": [
            "openlist-jwt-secret-weak",
            "openlist-token-validity-too-long",
        ],
    },
    {
        "scenario_id": "config_transport_insecure",
        "input_file": CONFIG_DIR / "config_transport_insecure.json",
        "expected_findings": [
            "openlist-https-disabled",
        ],
    },
    {
        "scenario_id": "config_logging_disabled",
        "input_file": CONFIG_DIR / "config_logging_disabled.json",
        "expected_findings": [
            "openlist-logging-disabled",
        ],
    },
    {
        "scenario_id": "config_protocol_exposure",
        "input_file": CONFIG_DIR / "config_protocol_exposure.json",
        "expected_findings": [
            "openlist-ftp-enabled",
            "openlist-sftp-enabled",
        ],
    },
]


LOG_SCENARIOS = [
    {
        "scenario_id": "log_normal_activity",
        "input_file": LOG_DIR / "log_normal_activity.log",
        "expected_events": 3,
        "expected_alerts": 0,
    },
    {
        "scenario_id": "log_repeated_login_failures",
        "input_file": LOG_DIR / "log_repeated_login_failures.log",
        "expected_events": 5,
        "expected_alerts": 1,
    },
    {
        "scenario_id": "log_admin_sensitive_actions",
        "input_file": LOG_DIR / "log_admin_sensitive_actions.log",
        "expected_events": 3,
        "expected_alerts": 3,
    },
    {
        "scenario_id": "log_mixed_security_events",
        "input_file": LOG_DIR / "log_mixed_security_events.log",
        "expected_events": 6,
        "expected_alerts": 1,
    },
]


def api_request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    body = None
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    request = Request(
        BACKEND_BASE_URL + path,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urlopen(request, timeout=30) as response:
            raw_body = response.read().decode("utf-8")
            return response.status, json.loads(raw_body) if raw_body else None
    except HTTPError as exc:
        raw_body = exc.read().decode("utf-8")
        try:
            parsed_body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            parsed_body = raw_body
        return exc.code, parsed_body
    except URLError as exc:
        raise RuntimeError(f"failed to reach backend at {BACKEND_BASE_URL}: {exc}") from exc


def safe_reset() -> None:
    reset_paths = [
        "/admin/reset/events",
        "/admin/reset/alerts",
        "/admin/reset/recommendations",
        "/admin/reset/audit",
    ]

    print("Resetting development data where supported...")
    for path in reset_paths:
        status, _ = api_request("DELETE", path)
        if 200 <= status < 300:
            print(f"  reset ok: {path}")
        else:
            print(f"  reset skipped: {path} returned HTTP {status}")


def run_config_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    input_file = scenario["input_file"]
    status, response = api_request("POST", "/scan/start", {"config_path": str(input_file)})

    if status < 200 or status >= 300:
        return failed_row(
            scenario,
            "config",
            notes=f"/scan/start returned HTTP {status}: {response}",
        )

    risks = response.get("risks", [])
    detected_findings = sorted(risk.get("rule_id", "") for risk in risks if risk.get("rule_id"))
    expected_findings = sorted(scenario["expected_findings"])
    scoring_breakdown = response.get("scoring_breakdown", {})
    score = response.get("total_score", "")
    total_penalty = scoring_breakdown.get("total_penalty", "")
    passed = detected_findings == expected_findings
    notes = "ok" if passed else "detected findings did not match expected findings"

    return {
        "scenario_id": scenario["scenario_id"],
        "scenario_type": "config",
        "input_file": str(input_file),
        "expected_findings": join_values(expected_findings),
        "detected_findings": join_values(detected_findings),
        "expected_events": "",
        "detected_events": "",
        "expected_alerts": "",
        "detected_alerts": "",
        "score": score,
        "total_penalty": total_penalty,
        "passed": passed,
        "notes": notes,
        "raw_response": response,
    }


def run_log_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    input_file = scenario["input_file"]
    alerts_before = get_alert_count()
    status, response = api_request("POST", "/events/import", {"log_path": str(input_file)})
    alerts_after = get_alert_count()

    if status < 200 or status >= 300:
        return failed_row(
            scenario,
            "log",
            notes=f"/events/import returned HTTP {status}: {response}",
        )

    detected_events = response.get("imported_count", 0)
    detected_alerts = max(alerts_after - alerts_before, 0)
    expected_events = scenario["expected_events"]
    expected_alerts = scenario["expected_alerts"]
    passed = detected_events == expected_events and detected_alerts == expected_alerts
    notes = "ok" if passed else "detected event or alert count did not match expected count"

    return {
        "scenario_id": scenario["scenario_id"],
        "scenario_type": "log",
        "input_file": str(input_file),
        "expected_findings": "",
        "detected_findings": "",
        "expected_events": expected_events,
        "detected_events": detected_events,
        "expected_alerts": expected_alerts,
        "detected_alerts": detected_alerts,
        "score": "",
        "total_penalty": "",
        "passed": passed,
        "notes": notes,
        "raw_response": response,
    }


def get_alert_count() -> int:
    status, response = api_request("GET", "/alerts")
    if 200 <= status < 300 and isinstance(response, list):
        return len(response)
    return 0


def query_optional_context() -> dict[str, Any]:
    context: dict[str, Any] = {}

    status, response = api_request("GET", "/events/stats")
    if 200 <= status < 300:
        context["events_stats"] = response
    else:
        context["events_stats_error"] = f"HTTP {status}"

    status, response = api_request("GET", "/alerts")
    if 200 <= status < 300:
        context["alerts"] = response
    else:
        context["alerts_error"] = f"HTTP {status}"

    return context


def failed_row(scenario: dict[str, Any], scenario_type: str, notes: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario["scenario_id"],
        "scenario_type": scenario_type,
        "input_file": str(scenario["input_file"]),
        "expected_findings": join_values(scenario.get("expected_findings", "")),
        "detected_findings": "",
        "expected_events": scenario.get("expected_events", ""),
        "detected_events": "",
        "expected_alerts": scenario.get("expected_alerts", ""),
        "detected_alerts": "",
        "score": "",
        "total_penalty": "",
        "passed": False,
        "notes": notes,
        "raw_response": None,
    }


def join_values(values: Any) -> str:
    if values == "":
        return ""
    if isinstance(values, list):
        return "|".join(str(value) for value in values)
    return str(values)


def write_matrix(rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "scenario_id",
        "scenario_type",
        "input_file",
        "expected_findings",
        "detected_findings",
        "expected_events",
        "detected_events",
        "expected_alerts",
        "detected_alerts",
        "score",
        "total_penalty",
        "passed",
        "notes",
    ]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with MATRIX_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def write_summary(rows: list[dict[str, Any]], optional_context: dict[str, Any]) -> None:
    total_scenarios = len(rows)
    passed_scenarios = sum(1 for row in rows if row["passed"])
    failed_scenarios = total_scenarios - passed_scenarios
    config_rows = [row for row in rows if row["scenario_type"] == "config"]
    log_rows = [row for row in rows if row["scenario_type"] == "log"]
    config_scores = [
        int(row["score"])
        for row in config_rows
        if isinstance(row.get("score"), int) or str(row.get("score", "")).isdigit()
    ]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend_base_url": BACKEND_BASE_URL,
        "total_scenarios": total_scenarios,
        "passed_scenarios": passed_scenarios,
        "failed_scenarios": failed_scenarios,
        "pass_rate": round(passed_scenarios / total_scenarios, 4) if total_scenarios else 0,
        "average_config_score": round(sum(config_scores) / len(config_scores), 2)
        if config_scores
        else None,
        "config_scenarios": summarize_rows(config_rows),
        "log_scenarios": summarize_rows(log_rows),
        "optional_context": optional_context,
        "output_files": {
            "evaluation_matrix_csv": str(MATRIX_PATH),
            "evaluation_summary_json": str(SUMMARY_PATH),
        },
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with SUMMARY_PATH.open("w", encoding="utf-8") as json_file:
        json.dump(summary, json_file, indent=2)


def summarize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": row["scenario_id"],
            "passed": row["passed"],
            "score": row["score"],
            "notes": row["notes"],
        }
        for row in rows
    ]


def print_results(rows: list[dict[str, Any]]) -> None:
    print("\nScenario results:")
    for row in rows:
        status = "PASS" if row["passed"] else "FAIL"
        print(f"  [{status}] {row['scenario_id']} - {row['notes']}")

    print("\nOutput files:")
    print(f"  {MATRIX_PATH}")
    print(f"  {SUMMARY_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate OpenList Secure Platform scenarios.")
    parser.add_argument("--reset", action="store_true", help="Reset development data before evaluation.")
    args = parser.parse_args()

    if args.reset:
        safe_reset()

    rows: list[dict[str, Any]] = []

    for scenario in CONFIG_SCENARIOS:
        rows.append(run_config_scenario(scenario))

    for scenario in LOG_SCENARIOS:
        rows.append(run_log_scenario(scenario))

    optional_context = query_optional_context()
    write_matrix(rows)
    write_summary(rows, optional_context)
    print_results(rows)

    return 0 if all(row["passed"] for row in rows) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
