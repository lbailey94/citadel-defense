"""Strict validation for externally pinned evidence artifacts.

The pin file is an operator-supplied trust input. This module checks identity,
freshness, schema, digest and requested values; it does not authenticate who
created either the pin file or evidence.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PIN_SCHEMA = "violet.evidence-validation/v1"


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
        manifest = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"status": "INVALID", "reason": f"pin manifest unreadable: {type(exc).__name__}", "artifacts": {}}
    if not isinstance(manifest, dict) or manifest.get("schema") != PIN_SCHEMA:
        return {"status": "INVALID", "reason": "pin manifest schema mismatch", "artifacts": {}}
    manifest_time = _parse_time(manifest.get("generated_at"))
    manifest_max_age = manifest.get("max_age_seconds")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (manifest_time is None or not isinstance(manifest_max_age, (int, float)) or manifest_max_age < 0
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
            if (not isinstance(rel, str) or not rel or not isinstance(digest, str) or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest.lower())
                    or not isinstance(expected_schema, str) or not isinstance(max_age, (int, float))
                    or max_age < 0 or pin_time is None):
                details["reason"] = "pin fields invalid"
            else:
                target = (manifest_path.parent / rel).resolve()
                try:
                    target.relative_to(manifest_path.parent.resolve())
                    content = target.read_bytes()
                    data = json.loads(content)
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
                            expected_counts = pin.get("counts", {})
                            if not isinstance(expected_counts, dict):
                                details["reason"] = "count pins malformed"
                            elif any(_path_get(data, key) != value for key, value in expected_counts.items()):
                                details["reason"] = "count pin mismatch"
                            else:
                                status, details = "VERIFIED_INTEGRITY", {
                                    "sha256": digest.lower(), "schema": expected_schema,
                                    "generated_at": ev_time.isoformat(), "counts": expected_counts,
                                    "integrity_only": True,
                                }
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
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
