#!/usr/bin/env python3
"""Focused truth-contract smoke tests; all stores and keys live in temp directories."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_IMPORT_TMP = tempfile.TemporaryDirectory(prefix="violet-truth-import-")
_ROOT = Path(_IMPORT_TMP.name)
os.environ["VIOLET_STATE_DIR"] = str(_ROOT / "state")
os.environ["VIOLET_KEY_PATH"] = str(_ROOT / "keys" / "canary.key")
os.environ["VIOLET_PQC_KEY_PATH"] = str(_ROOT / "keys" / "pqc.key")

from canary_manager import CanaryManager  # noqa: E402
import canary_manager  # noqa: E402
from evidence_validation import PIN_SCHEMA, validate_evidence_manifest  # noqa: E402
from violet_insurability_pack import generate_insurability_pack, verify_insurability_pack  # noqa: E402


class EvidenceTruthSmoke(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="violet-truth-case-")
        self.root = Path(self.temp.name)
        canary_manager.BLUE_OPS_CHAIN = self.root / "blue-ops.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def manager(self, secret=True):
        key = self.root / "secrets" / "node.key"
        if secret:
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text("test-only-secret", encoding="utf-8")
        return CanaryManager(self.root / "state" / "canaries.json", key)

    def test_canary_requires_mac_or_registered_record(self):
        cm = self.manager()
        good = cm.mint_token("smoke", "openai_key", persist=False)
        self.assertTrue(cm.check_token(good)["is_canary"])
        self.assertEqual(cm.check_token(good)["authentication"], "cryptographically_verified")
        fake = "sk-proj-canary-smoke-abcdef012345-" + "0" * 24
        wrong_mac = cm.check_token(fake)
        self.assertFalse(wrong_mac["is_canary"])
        self.assertEqual(wrong_mac["classification"], "format_like_unverified")
        prefix_only = "sk-proj-canary-this-is-only-a-prefix-looking-value"
        self.assertEqual(cm.check_token(prefix_only)["classification"], "format_like_unverified")
        self.assertFalse(cm.check_token("ASIACANARY1234567890")["is_canary"])
        registered = cm.mint_token("registered", "generic", persist=True)
        no_secret = CanaryManager(self.root / "state" / "canaries.json", self.root / "missing.key")
        self.assertEqual(no_secret.check_token(registered)["authentication"], "registered")
        unseen = self.manager(secret=True).mint_token("unseen", "openai_key", persist=False)
        self.assertFalse(no_secret.check_token(unseen)["is_canary"])
        with self.assertRaises(RuntimeError):
            no_secret.mint_token("forbidden", persist=False)
        self.assertFalse((self.root / "missing.key").exists())

    def _make_pinned_artifact(self, age_seconds=0):
        now = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        stamp = now.isoformat()
        artifact = {"schema": "test.receipt/v1", "generated_at": stamp, "receipts": {"count": 2}}
        path = self.root / "receipt.json"
        raw = json.dumps(artifact, sort_keys=True).encode()
        path.write_bytes(raw)
        manifest = {
            "schema": PIN_SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(),
            "max_age_seconds": 3600,
            "artifacts": {"receipt": {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
                                       "schema": "test.receipt/v1", "generated_at": stamp,
                                       "max_age_seconds": 60, "counts": {"receipts.count": 2}}},
        }
        pin_path = self.root / "pins.json"
        pin_path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, pin_path

    def test_evidence_requires_explicit_fresh_matching_pins(self):
        self.assertEqual(validate_evidence_manifest(None)["status"], "UNAVAILABLE")
        artifact, pins = self._make_pinned_artifact()
        self.assertEqual(validate_evidence_manifest(pins)["status"], "VERIFIED_INTEGRITY")
        artifact.write_text('{"schema":', encoding="utf-8")
        self.assertEqual(validate_evidence_manifest(pins)["status"], "INVALID_OR_UNAVAILABLE")
        artifact, pins = self._make_pinned_artifact(age_seconds=120)
        self.assertEqual(validate_evidence_manifest(pins)["status"], "INVALID_OR_UNAVAILABLE")
        artifact, pins = self._make_pinned_artifact()
        artifact.write_text(artifact.read_text(encoding="utf-8").replace('"count": 2', '"count": 3'), encoding="utf-8")
        self.assertEqual(validate_evidence_manifest(pins)["status"], "INVALID_OR_UNAVAILABLE")
        _, missing_pins = self._make_pinned_artifact()
        missing_pins.unlink()
        self.assertEqual(validate_evidence_manifest(missing_pins)["status"], "INVALID")

    def test_pack_signs_integrity_but_never_claims_live_compliance(self):
        _, pins = self._make_pinned_artifact()
        out = self.root / "pack"
        result = generate_insurability_pack("smoke", out, pins)
        path = Path(result["manifest_json"])
        self.assertFalse((out / ".operator-keys").exists())
        self.assertTrue((_ROOT / "state" / "keys" / "redops.key").exists())
        self.assertTrue(verify_insurability_pack(path))
        bundle = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(bundle["self_verified_integrity_only"])
        self.assertFalse(bundle["trusted_external_peer"])
        self.assertEqual(bundle["pack"]["benchmark"]["status"], "UNAVAILABLE")
        self.assertEqual(bundle["pack"]["compliance_status"], "NOT_ASSESSED")
        report = Path(result["report_md"]).read_text(encoding="utf-8")
        self.assertNotIn("**LIVE**", report)
        self.assertNotIn("8/8", report)
        bundle["pack"]["benchmark"]["status"] = "PASS"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        self.assertFalse(verify_insurability_pack(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
