"""Strict validation for externally pinned evidence artifacts.

The pin file is an operator-supplied trust input. This module checks identity,
freshness, schema, digest and requested values; it does not authenticate who
created either the pin file or evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIN_SCHEMA = "violet.evidence-validation/v1"
# Named `benchmark` artifacts use `violet.benchmark/v1`: an aware generated_at,
# nonempty unique results [{"name": str, "passed": bool}], plus total,
# passed, and all_passed values that exactly match those per-case outcomes.
BENCHMARK_SCHEMA = "violet.benchmark/v1"


def _reject_constant(value: str):
    raise ValueError(f"non-finite JSON number: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _strict_loads(content: bytes) -> Any:
    return json.loads(content, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def _finite_number(value: Any) -> bool:
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def validate_evidence_manifest(manifest_path: Path | None, now: datetime | None = None) -> dict:
    """Validate every pinned artifact. Missing or malformed inputs are unavailable."""
    if manifest_path is None:
        return {"status": "UNAVAILABLE", "reason": "no explicit evidence pin manifest supplied", "artifacts": {}}
    try:
        raw = manifest_path.read_bytes()
        manifest = _strict_loads(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        return {"status": "INVALID", "reason": f"pin manifest unreadable: {type(exc).__name__}", "artifacts": {}}
    if not isinstance(manifest, dict) or manifest.get("schema") != PIN_SCHEMA:
        return {"status": "INVALID", "reason": "pin manifest schema mismatch", "artifacts": {}}
    manifest_time = _parse_time(manifest.get("generated_at"))
    manifest_max_age = manifest.get("max_age_seconds")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (manifest_time is None or not _finite_number(manifest_max_age) or manifest_max_age < 0
            or (now - manifest_time).total_seconds() < 0
            or (now - manifest_time).total_seconds() > manifest_max_age):
        return {"status": "STALE", "reason": "pin manifest missing, future-dated, or expired", "artifacts": {}}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        return {"status": "INVALID", "reason": "pin manifest has no artifacts", "artifacts": {}}
    result: dict[str, dict] = {}
    all_valid = True
    for name, pin in artifacts.items():
        status, details = "INVALID", {}
        if not isinstance(name, str) or not isinstance(pin, dict):
            details["reason"] = "malformed artifact pin"
        else:
            rel = pin.get("path")
            digest = pin.get("sha256")
            expected_schema = pin.get("schema")
            max_age = pin.get("max_age_seconds")
            pin_time = _parse_time(pin.get("generated_at"))
            expected_counts = pin.get("counts")
            counts_valid = (
                isinstance(expected_counts, dict) and bool(expected_counts)
                and all(isinstance(key, str) and bool(key) and type(value) is int and value >= 0
                        for key, value in expected_counts.items())
            )
            if (not isinstance(rel, str) or not rel or not isinstance(digest, str) or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest.lower())
                    or not isinstance(expected_schema, str) or not _finite_number(max_age)
                    or max_age < 0 or pin_time is None or not counts_valid
                    or (name == "benchmark" and expected_schema != BENCHMARK_SCHEMA)):
                details["reason"] = "pin fields invalid"
            else:
                target = (manifest_path.parent / rel).resolve()
                try:
                    target.relative_to(manifest_path.parent.resolve())
                    content = target.read_bytes()
                    data = _strict_loads(content)
                    if hashlib.sha256(content).hexdigest() != digest.lower():
                        details["reason"] = "digest mismatch"
                    elif not isinstance(data, dict) or data.get("schema") != expected_schema:
                        details["reason"] = "evidence schema mismatch"
                    else:
                        ev_time = _parse_time(data.get("generated_at"))
                        age = (now - ev_time).total_seconds() if ev_time else None
                        pin_age = (now - pin_time).total_seconds()
                        if ev_time is None or age is None or age < 0 or pin_age < 0 or age > max_age:
                            status, details = "STALE", {"reason": "evidence missing, future-dated, or expired"}
                        elif ev_time != pin_time:
                            details["reason"] = "evidence time differs from supplied pin"
                        else:
                            if any(not _count_matches(data, key, value) for key, value in expected_counts.items()):
                                details["reason"] = "count pin mismatch"
                            elif name == "benchmark" and not _validate_benchmark(data):
                                details["reason"] = "benchmark schema or result counts disagree"
                            else:
                                status, details = "VERIFIED_INTEGRITY", {
                                    "sha256": digest.lower(), "schema": expected_schema,
                                    "generated_at": ev_time.isoformat(), "counts": expected_counts,
                                    "integrity_only": True,
                                }
                                if name == "benchmark":
                                    total = len(data["results"])
                                    passed = sum(result["passed"] is True for result in data["results"])
                                    details["benchmark"] = {
                                        "status": "RECORDED_LOCAL_RESULTS",
                                        "total": total,
                                        "passed": passed,
                                        "all_passed": passed == total,
                                        "integrity_only": True,
                                    }
                except (OSError, UnicodeError, ValueError) as exc:
                    details["reason"] = f"artifact unavailable or invalid: {type(exc).__name__}"
        if status != "VERIFIED_INTEGRITY":
            all_valid = False
            details["status"] = status
        else:
            details["status"] = status
        result[name] = details
    return {"status": "VERIFIED_INTEGRITY" if all_valid else "INVALID_OR_UNAVAILABLE", "artifacts": result,
            "trust": "supplied pins establish integrity checks only; they do not establish external identity or compliance"}


def _path_get(data: dict, dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _count_matches(data: dict, dotted: str, expected: int) -> bool:
    present, actual = _path_get_present(data, dotted)
    return present and type(actual) is int and actual == expected


def _path_get_present(data: dict, dotted: str) -> tuple[bool, Any]:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _validate_benchmark(data: dict) -> bool:
    results = data.get("results")
    total = data.get("total")
    passed = data.get("passed")
    all_passed = data.get("all_passed")
    if not isinstance(results, list) or not results or type(total) is not int or type(passed) is not int:
        return False
    names = []
    actual_passed = 0
    for result in results:
        if not isinstance(result, dict):
            return False
        name, outcome = result.get("name"), result.get("passed")
        if not isinstance(name, str) or not name.strip() or type(outcome) is not bool:
            return False
        names.append(name)
        actual_passed += outcome is True
    return (
        len(set(names)) == len(names)
        and total == len(results)
        and passed == actual_passed
        and type(all_passed) is bool
        and all_passed is (actual_passed == len(results))
        and total >= 0 and 0 <= passed <= total
    )
