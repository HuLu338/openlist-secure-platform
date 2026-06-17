#!/usr/bin/env python3
"""Evaluate policy threshold before-after behavior.

This script assumes the Go backend is already running at http://localhost:8080.
It uses only the Python standard library.
"""

from __future__ import annotations

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
CONFIG_PATH = ROOT_DIR / "configs" / "config_critical_weak_secret.json"
RESULTS_PATH = ROOT_DIR / "results" / "policy_threshold_test_results.json"


def api_request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(BACKEND_BASE_URL + path, data=body, headers=headers, method=method)

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


def get_policy() -> dict[str, Any]:
    status, response = api_request("GET", "/policies")
    if status != 200:
        raise RuntimeError(f"GET /policies returned HTTP {status}: {response}")
    return response


def patch_policy(policy: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "low_score_threshold": int(policy["low_score_threshold"]),
        "multiple_login_failures_threshold": int(policy["multiple_login_failures_threshold"]),
        "long_token_hours_threshold": int(policy["long_token_hours_threshold"]),
    }
    status, response = api_request("PATCH", "/policies", payload)
    if status != 200:
        raise RuntimeError(f"PATCH /policies returned HTTP {status}: {response}")
    return response


def run_scan() -> dict[str, Any]:
    status, response = api_request("POST", "/scan/start", {"config_path": str(CONFIG_PATH)})
    if status != 200:
        raise RuntimeError(f"POST /scan/start returned HTTP {status}: {response}")
    return response


def get_alert_count() -> int | None:
    status, response = api_request("GET", "/alerts")
    if status == 200 and isinstance(response, list):
        return len(response)
    return None


def triggered_rules(scan_response: dict[str, Any]) -> list[str]:
    return sorted(
        risk.get("rule_id", "")
        for risk in scan_response.get("risks", [])
        if risk.get("rule_id")
    )


def write_result(result: dict[str, Any]) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend_base_url": BACKEND_BASE_URL,
        **result,
    }
    with RESULTS_PATH.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def main() -> int:
    original_policy = get_policy()
    restored_policy = None
    result: dict[str, Any] = {
        "original_policy": original_policy,
        "modified_policy": None,
        "before_scan_score": None,
        "after_scan_score": None,
        "before_triggered_rules": [],
        "after_triggered_rules": [],
        "before_alert_count": None,
        "after_alert_count": None,
        "expected_behavior": "Stricter long_token_hours_threshold should keep or trigger openlist-token-validity-too-long for the same config.",
        "passed": False,
        "notes": "",
        "original_policy_restored": False,
    }

    try:
        before_alert_count = get_alert_count()
        before_scan = run_scan()
        before_rules = triggered_rules(before_scan)

        modified_policy_request = dict(original_policy)
        modified_policy_request["long_token_hours_threshold"] = 12
        modified_policy = patch_policy(modified_policy_request)

        after_scan = run_scan()
        after_rules = triggered_rules(after_scan)
        after_alert_count = get_alert_count()

        result.update(
            {
                "modified_policy": modified_policy,
                "before_scan_score": before_scan.get("total_score"),
                "after_scan_score": after_scan.get("total_score"),
                "before_triggered_rules": before_rules,
                "after_triggered_rules": after_rules,
                "before_alert_count": before_alert_count,
                "after_alert_count": after_alert_count,
            }
        )

        token_rule_before = "openlist-token-validity-too-long" in before_rules
        token_rule_after = "openlist-token-validity-too-long" in after_rules
        threshold_changed = int(modified_policy["long_token_hours_threshold"]) == 12
        result["passed"] = threshold_changed and token_rule_after and set(before_rules).issubset(set(after_rules))
        result["notes"] = (
            "policy threshold changed and token validity rule was present after scan"
            if result["passed"]
            else f"token_rule_before={token_rule_before}, token_rule_after={token_rule_after}, threshold_changed={threshold_changed}"
        )
    finally:
        try:
            restored_policy = patch_policy(original_policy)
            result["original_policy_restored"] = (
                int(restored_policy["low_score_threshold"]) == int(original_policy["low_score_threshold"])
                and int(restored_policy["multiple_login_failures_threshold"])
                == int(original_policy["multiple_login_failures_threshold"])
                and int(restored_policy["long_token_hours_threshold"])
                == int(original_policy["long_token_hours_threshold"])
            )
        except Exception as exc:  # noqa: BLE001 - script should record restore failures plainly.
            result["original_policy_restored"] = False
            result["notes"] = f"{result.get('notes', '')}; failed to restore original policy: {exc}".strip("; ")

        write_result(result)

    print(f"before score: {result['before_scan_score']}")
    print(f"after score: {result['after_scan_score']}")
    print(f"before rules: {result['before_triggered_rules']}")
    print(f"after rules: {result['after_triggered_rules']}")
    print(f"test passed: {result['passed']}")
    print(f"original policy restored: {result['original_policy_restored']}")
    print(f"output file: {RESULTS_PATH}")

    return 0 if result["passed"] and result["original_policy_restored"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
