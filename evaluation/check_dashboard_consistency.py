#!/usr/bin/env python3
"""Check dashboard summary consistency against underlying backend APIs.

This script assumes the Go backend is already running at http://localhost:8080.
It uses only the Python standard library.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BACKEND_BASE_URL = "http://localhost:8080"
API_KEY = os.getenv("OPENLIST_SECURITY_API_KEY", "change-me-dev-key")
RESULTS_PATH = Path(__file__).resolve().parent / "results" / "dashboard_consistency_result.json"


def api_request(path: str) -> tuple[int, Any]:
    request = Request(
        BACKEND_BASE_URL + path,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
        method="GET",
    )

    try:
        with urlopen(request, timeout=30) as response:
            raw_body = response.read().decode("utf-8")
            return response.status, json.loads(raw_body) if raw_body else None
    except HTTPError as exc:
        raw_body = exc.read().decode("utf-8")
        try:
            parsed_body = json.loads(raw_body) if raw_body else raw_body
        except json.JSONDecodeError:
            parsed_body = raw_body
        return exc.code, parsed_body
    except URLError as exc:
        raise RuntimeError(f"failed to reach backend at {BACKEND_BASE_URL}: {exc}") from exc


def require_ok(path: str) -> Any:
    status, response = api_request(path)
    if status != 200:
        raise RuntimeError(f"GET {path} returned HTTP {status}: {response}")
    return response


def compare(name: str, dashboard_value: Any, source_value: Any, notes: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "dashboard_value": dashboard_value,
        "source_value": source_value,
        "passed": dashboard_value == source_value,
        "notes": notes,
    }


def main() -> int:
    dashboard = require_ok("/dashboard/summary")
    scans = require_ok("/scans")
    latest_scan = None
    latest_status, latest_response = api_request("/scans/latest")
    if latest_status == 200:
        latest_scan = latest_response
    elif latest_status != 404:
        raise RuntimeError(f"GET /scans/latest returned HTTP {latest_status}: {latest_response}")

    event_stats = require_ok("/events/stats")
    alerts = require_ok("/alerts")

    scan_summary = dashboard.get("scan_summary", {})
    event_summary = dashboard.get("event_summary", {})
    alert_summary = dashboard.get("alert_summary", {})

    open_alerts = sum(1 for alert in alerts if alert.get("status") == "open")
    closed_alerts = sum(1 for alert in alerts if alert.get("status") == "closed")
    latest_alert_type = alerts[0].get("alert_type", "") if alerts else ""
    severity_counts = event_stats.get("by_severity", {}) if isinstance(event_stats, dict) else {}

    comparisons = [
        compare("total_scans", scan_summary.get("total_scans"), len(scans)),
        compare("total_events", event_summary.get("total_events"), event_stats.get("total_events")),
        compare("high_severity_events", event_summary.get("high_severity_events"), severity_counts.get("high", 0)),
        compare("medium_severity_events", event_summary.get("medium_severity_events"), severity_counts.get("medium", 0)),
        compare("low_severity_events", event_summary.get("low_severity_events"), severity_counts.get("low", 0)),
        compare("total_alerts", alert_summary.get("total_alerts"), len(alerts)),
        compare("open_alerts", alert_summary.get("open_alerts"), open_alerts),
        compare("closed_alerts", alert_summary.get("closed_alerts"), closed_alerts),
        compare("latest_alert_type", alert_summary.get("latest_alert_type", ""), latest_alert_type),
    ]

    if latest_scan is not None:
        comparisons.extend(
            [
                compare("latest_score", scan_summary.get("latest_score"), latest_scan.get("total_score")),
                compare(
                    "latest_triggered_rules_count",
                    scan_summary.get("latest_triggered_rules_count"),
                    latest_scan.get("triggered_rules_count"),
                ),
                compare("latest_scan_time", scan_summary.get("latest_scan_time"), latest_scan.get("scan_time")),
            ]
        )
    else:
        comparisons.append(compare("latest_scan_absent", scan_summary.get("total_scans"), 0, "No latest scan exists."))

    passed = all(item["passed"] for item in comparisons)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend_base_url": BACKEND_BASE_URL,
        "passed": passed,
        "total_comparisons": len(comparisons),
        "passed_comparisons": sum(1 for item in comparisons if item["passed"]),
        "failed_comparisons": sum(1 for item in comparisons if not item["passed"]),
        "comparisons": comparisons,
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)

    print(f"dashboard consistency passed: {passed}")
    print(f"comparisons passed: {payload['passed_comparisons']}/{payload['total_comparisons']}")
    print(f"output file: {RESULTS_PATH}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
