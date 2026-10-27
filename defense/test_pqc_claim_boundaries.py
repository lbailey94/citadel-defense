"""Disclosure and exit-status checks for the experimental signature fixture."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import violet_pqc as pqc


class ExperimentalSignatureReportingTests(unittest.TestCase):
    def test_combined_digest_does_not_claim_a_quantum_margin(self):
        result = pqc.GroverProofDualLedger.compute_dual_hash("0" * 64, "fixture")
        self.assertEqual(len(result["composite_hash"]), 64)
        self.assertIsNone(result["quantum_security_margin_bits"])
        self.assertEqual(result["security_evaluation"], "not_established")

    def test_signature_fixture_is_explicitly_experimental(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            signer = pqc.HybridCompositeSigner(root / "classical.key", root / "hash.key")
            envelope = signer.sign_hybrid(b"isolated audit fixture")
            self.assertEqual(envelope["security_status"], "experimental_not_fips_validated")
            self.assertTrue(pqc.HybridCompositeSigner.verify_hybrid(b"isolated audit fixture", envelope))
            self.assertFalse(pqc.HybridCompositeSigner.verify_hybrid(b"altered fixture", envelope))

    def test_cli_fails_when_selected_fixture_checks_fail(self):
        for valid, expected_rc in ((False, 1), (True, 0)):
            output = io.StringIO()
            fixture = {"tamper_tests": {"authentic_composite_verifies": valid}}
            with self.subTest(valid=valid), \
                 patch.object(pqc, "run_pqc_benchmark", return_value=(0.001, fixture, valid)), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(pqc.main(), expected_rc)
            self.assertIn("Quantum Security Margin      : NOT ESTABLISHED", output.getvalue())
            self.assertIn("FIPS Conformance             : NOT ESTABLISHED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
