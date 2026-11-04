#!/usr/bin/env python3
"""Evaluate API key authorization behavior.

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
RESULTS_PATH = Path(__file__).resolve().parent / "results" / "api_auth_test_results.json"
ENDPOINTS = [
    "/dashboard/summary",
    "/scans",
    "/alerts",
    "/audit/api",
]


def request_endpoint(endpoint: str, use_api_key: bool) -> tuple[int, str]:
    headers = {}
    if use_api_key:
        headers["X-API-Key"] = API_KEY

    request = Request(BACKEND_BASE_URL + endpoint, headers=headers, method="GET")

    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return response.status, preview(body)
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, preview(body)
    except URLError as exc:
        raise RuntimeError(f"failed to reach backend at {BACKEND_BASE_URL}: {exc}") from exc


def preview(body: str) -> str:
    compact = " ".join(body.split())
    if len(compact) <= 180:
        return compact
    return compact[:177] + "..."


def run_tests() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for endpoint in ENDPOINTS:
        actual_status, response_preview = request_endpoint(endpoint, use_api_key=False)
        results.append(
            {
                "endpoint": endpoint,
                "auth_mode": "unauthorized",
                "expected_status": 401,
                "actual_status": actual_status,
                "passed": actual_status == 401,
                "response_preview": response_preview,
            }
        )

    for endpoint in ENDPOINTS:
        actual_status, response_preview = request_endpoint(endpoint, use_api_key=True)
        results.append(
            {
                "endpoint": endpoint,
                "auth_mode": "authorized",
                "expected_status": 200,
                "actual_status": actual_status,
                "passed": actual_status == 200,
                "response_preview": response_preview,
            }
        )

    return results


def write_results(results: list[dict[str, Any]]) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend_base_url": BACKEND_BASE_URL,
        "total_tests": len(results),
        "passed_tests": sum(1 for item in results if item["passed"]),
        "failed_tests": sum(1 for item in results if not item["passed"]),
        "results": results,
    }
    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def print_summary(results: list[dict[str, Any]]) -> None:
    total_tests = len(results)
    passed_tests = sum(1 for item in results if item["passed"])
    failed_tests = total_tests - passed_tests

    print(f"total tests: {total_tests}")
    print(f"passed tests: {passed_tests}")
    print(f"failed tests: {failed_tests}")
    print(f"output file: {RESULTS_PATH}")


def main() -> int:
    results = run_tests()
    write_results(results)
    print_summary(results)
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
