"""Regressions for false-green internal reports, not product security tests."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import practice_audit_battery as audit


def result(stdout="", returncode=0, elapsed_ms=500):
    return {"returncode": returncode, "stdout": stdout, "stderr": "", "elapsed_ms": elapsed_ms}


def verdict(name="TRUSTED", codes=()):
    return json.dumps({"verdict": name, "errors": [{"code": code} for code in codes]})


class ReportingRegressionTests(unittest.TestCase):
    def cpr_fixture(self, root):
        for name in ("continuity_receipt/verify.py", "js/dist/cli.js",
                     "rust/target/debug/continuity-receipt-verify", "vectors/case.json"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}")
        (root / "rust/target/debug/continuity-receipt-verify").chmod(0o700)
        for name in ("manifest.json", "manifest-0.5.json", "manifest-0.6.json"):
            entries = [{"file": "case.json", "expected_verdict": "UNTRUSTED",
                        "expected_code": "bad_sig", "require_anchor": False}] if name == "manifest.json" else []
            (root / "vectors" / name).write_text(json.dumps({"vectors": entries}))

    def test_missing_engine_is_not_evaluated_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.cpr_fixture(root)
            (root / "rust/target/debug/continuity-receipt-verify").unlink()
            with patch.object(audit, "command_result") as run:
                check = audit.audit_differential(root)
            self.assertEqual(check["status"], "NOT_EVALUATED")
            self.assertEqual(check["compared_vectors"], 0)
            run.assert_not_called()

    def test_equal_engine_errors_cannot_count_as_agreement(self):
        invalid = [result("", 0), result("{}", 1), result("", -11),
                   result(verdict("TRUSTED"), 1), result(verdict("ERROR"), 0),
                   result('{"verdict":"TRUSTED","errors":[{}]}', 0)]
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.cpr_fixture(root)
            for observation in invalid:
                with self.subTest(observation=observation), \
                     patch.object(audit.shutil, "which", return_value="/bin/true"), \
                     patch.object(audit, "command_result", return_value=observation):
                    check = audit.audit_differential(root)
                self.assertEqual(check["status"], "FAIL")
                self.assertEqual(check["agreeing_vectors"], 0)
                self.assertEqual(check["compared_vectors"], 0)

    def test_valid_rejection_is_comparable_but_error_code_divergence_fails(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.cpr_fixture(root)
            for codes, expected in ((("bad_sig",) * 3, "PASS"),
                                    (("bad_sig", "bad_sig", "malformed"), "FAIL")):
                observations = [result(verdict("UNTRUSTED", (code,)), 1) for code in codes]
                with self.subTest(codes=codes), \
                     patch.object(audit.shutil, "which", return_value="/bin/true"), \
                     patch.object(audit, "command_result", side_effect=observations), \
                     patch.object(audit, "git_identity", return_value={}):
                    check = audit.audit_differential(root)
                self.assertEqual(check["status"], expected)
                self.assertEqual(check["compared_vectors"], 1)

    def test_missing_bend_is_not_a_pass(self):
        self.assertEqual(audit.audit_bend(None, Path("unused"))["status"], "NOT_EVALUATED")

    def test_agreement_on_wrong_verdict_does_not_pass(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.cpr_fixture(root)
            with patch.object(audit.shutil, "which", return_value="/bin/true"), \
                 patch.object(audit, "command_result", return_value=result(verdict())), \
                 patch.object(audit, "git_identity", return_value={}):
                check = audit.audit_differential(root)
            self.assertEqual(check["status"], "FAIL")
            self.assertEqual(check["agreeing_vectors"], 1)
            self.assertFalse(check["records"][0]["matches_expected"])

    def test_manifest_anchor_requirement_reaches_every_engine(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.cpr_fixture(root)
            manifest = root / "vectors/manifest.json"
            payload = json.loads(manifest.read_text())
            payload["vectors"][0]["require_anchor"] = True
            manifest.write_text(json.dumps(payload))
            with patch.object(audit.shutil, "which", return_value="/bin/true"), \
                 patch.object(audit, "command_result", return_value=result(verdict("UNTRUSTED", ("bad_sig",)), 1)) as run, \
                 patch.object(audit, "git_identity", return_value={}):
                check = audit.audit_differential(root)
            self.assertEqual(check["status"], "PASS")
            self.assertEqual(run.call_count, 3)
            for call in run.call_args_list:
                self.assertIn("--require-anchor", call.args[0])

    def test_failed_bend_process_cannot_pass_by_printing_a_marker(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            binary = root / "bend"
            binary.write_text("fixture")
            (root / "citta_pac_laws.bend").write_text("law example:\n")
            for laws_code, fold_code in ((1, 0), (0, 1)):
                observations = [result("Bend fixture"), result("ALL PROOFS CHECK", laws_code), result("kernel checked"),
                                result("BATCH_CPR_DAG_VERIFIED=123\n", fold_code),
                                result("SWARM_WARRANT_DIGEST=456\n")]
                with self.subTest(laws_code=laws_code, fold_code=fold_code), \
                     patch.object(audit, "command_result", side_effect=observations):
                    check = audit.audit_bend(binary, root)
                self.assertEqual(check["status"], "FAIL")
                self.assertEqual(check["folds"]["swarm_named_arithmetic_fold"]["synthetic_leaves_per_second"], 8388608)

    def test_missing_kernel_is_not_evaluated_despite_frontend_pass(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            binary = root / "bend"
            binary.write_text("fixture")
            (root / "citta_pac_laws.bend").write_text("law example:\n")
            observations = [result("Bend fixture"), result("ALL PROOFS CHECK"),
                            result("Error: BendTT infrastructure: lean unavailable", 1),
                            result("BATCH_CPR_DAG_VERIFIED=123\n"),
                            result("SWARM_WARRANT_DIGEST=456\n")]
            with patch.object(audit, "command_result", side_effect=observations):
                check = audit.audit_bend(binary, root)
            self.assertEqual(check["laws"]["status"], "PASS")
            self.assertEqual(check["kernel_recheck"]["status"], "NOT_EVALUATED")
            self.assertEqual(check["status"], "NOT_EVALUATED")

    def test_rate_uses_matching_elapsed_time(self):
        self.assertEqual(audit.leaf_rate(1000, 250), 4000)
        self.assertEqual(audit.leaf_rate(1000, 500), 2000)
        for elapsed in (0, -1, float("nan"), float("inf")):
            self.assertIsNone(audit.leaf_rate(1000, elapsed))

    def test_failure_precedes_missing_and_missing_is_incomplete(self):
        self.assertEqual(audit.selected_status({}), "INCOMPLETE")
        self.assertEqual(audit.selected_status({"check": {"status": "NOT_EVALUATED"}}), "INCOMPLETE")
        self.assertEqual(audit.selected_status({"a": {"status": "FAIL"}, "b": {"status": "NOT_EVALUATED"}}), "FAIL")

    def test_cli_exit_and_report_preserve_selected_check_state(self):
        for status, expected_code in (("PASS", 0), ("FAIL", 1), ("NOT_EVALUATED", 2)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as scratch, \
                 patch.object(audit, "audit_bend", return_value={"status": status, "scope": "fixture"}), \
                 patch.object(audit, "git_identity", return_value={}):
                code = audit.main(["--checks", "bend", "--output-dir", scratch])
                report = json.loads((Path(scratch) / "practice-audit-report.json").read_text())
                self.assertEqual(code, expected_code)
                self.assertEqual(report["selected_status"], "INCOMPLETE" if status == "NOT_EVALUATED" else status)
                self.assertNotIn("composite_score", report)
                self.assertEqual(report["checks"]["memory_crystals"]["status"], "NOT_EVALUATED")


if __name__ == "__main__":
    unittest.main()
