#!/usr/bin/env python3
"""Generate a cautious evidence inventory; cryptographic integrity is not compliance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFENSE_DIR = Path(__file__).resolve().parent
if str(DEFENSE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENSE_DIR))

from evidence_validation import validate_evidence_manifest  # noqa: E402
from violet_pqc import GroverProofDualLedger, HybridCompositeSigner  # noqa: E402

STATE_DIR = Path(os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic")))


def generate_insurability_pack(
    client_name: str,
    out_dir: Path | None = None,
    evidence_manifest: Path | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in client_name.lower()) or "client"
    target_dir = out_dir or (STATE_DIR / "insurability-packs" / f"INSURABILITY_PACK_{slug}_{now:%Y-%m-%d}")
    target_dir.mkdir(parents=True, exist_ok=True)
    evidence = validate_evidence_manifest(evidence_manifest, now=now)
    benchmark_record = evidence.get("artifacts", {}).get("benchmark", {})
    if benchmark_record.get("status") == "VERIFIED_INTEGRITY":
        benchmark = benchmark_record["benchmark"]
    elif benchmark_record:
        benchmark = {"status": "INVALID_OR_UNAVAILABLE", "reason": benchmark_record.get("reason", "benchmark evidence invalid")}
    elif evidence.get("status") in {"INVALID", "STALE", "INVALID_OR_UNAVAILABLE"}:
        benchmark = {"status": "INVALID_OR_UNAVAILABLE", "reason": evidence.get("reason", "evidence manifest invalid or unavailable")}
    else:
        benchmark = {"status": "UNAVAILABLE", "reason": "no benchmark artifact was supplied and validated"}
    pack = {
        "schema": "violet.insurability-pack/v2",
        "client": client_name,
        "generated_at": now.isoformat(),
        "evidence_manifest": str(evidence_manifest.resolve()) if evidence_manifest else None,
        "evidence_validation": evidence,
        "benchmark": benchmark,
        "compliance_mappings": {
            "AIUC_1": ["E015.4", "S004.2"],
            "EU_AI_ACT": ["Article 12", "Article 50"],
            "NIST_800_53": ["AU-9", "AU-10", "SC-7"],
        },
        "compliance_status": "NOT_ASSESSED",
        "honest_limits_disclosure": [
            "A local signature and digest show integrity relative to the key and bytes used; they do not prove an external trusted peer, semantic truth, or compliance.",
            "The supplied pin manifest is an input trust anchor. It is not independently authenticated by this pack.",
            "Missing, stale, truncated, malformed, or modified evidence remains invalid or unavailable and is not counted as passing.",
        ],
    }
    canonical = json.dumps(pack, sort_keys=True, separators=(",", ":")).encode()
    dual_hash = GroverProofDualLedger.compute_dual_hash("0" * 64, canonical.decode())
    # Use the configured private state store; never put private signing keys in the export bundle.
    signer = HybridCompositeSigner(
        key_path=STATE_DIR / "keys" / "redops.key",
        pqc_key_path=STATE_DIR / "keys" / "redops_pqc.key",
    )
    signature = signer.sign_hybrid(canonical)
    self_verified = HybridCompositeSigner.verify_hybrid(canonical, signature)
    bundle = {
        "pack": pack,
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "dual_ledger_commitment": dual_hash,
        "operator_attestation": signature,
        "self_verified_integrity_only": self_verified,
        "trusted_external_peer": False,
    }
    json_path = target_dir / "INSURABILITY_PACK_MANIFEST.json"
    json_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    md = [
        f"# VIOLET Evidence Inventory — `{client_name}`", "",
        f"- Generated: `{now.isoformat()}`",
        f"- Evidence validation: `{evidence['status']}`",
        f"- Benchmark: `{benchmark['status']}`" + (
            f" ({benchmark.get('passed')}/{benchmark.get('total')} recorded cases passed; local integrity only)"
            if benchmark.get("status") == "RECORDED_LOCAL_RESULTS" else f" ({benchmark.get('reason')})"
        ),
        f"- Local signature: `{'VERIFIED_INTEGRITY_ONLY' if self_verified else 'FAILED'}`",
        "- External trusted peer: `NOT ESTABLISHED`",
        "- Compliance assessment: `NOT ASSESSED`", "",
        "## Supplied evidence", "",
        "| Artifact | Status | Details |", "|---|---|---|",
    ]
    for name, item in evidence.get("artifacts", {}).items():
        details = item.get("reason", item.get("sha256", ""))
        md.append(f"| `{name}` | `{item.get('status', 'INVALID')}` | `{details}` |")
    if not evidence.get("artifacts"):
        md.append("| none | `UNAVAILABLE` | no validated artifact pins |")
    md.extend(["", "## Scope limits", ""])
    md.extend(f"- {item}" for item in pack["honest_limits_disclosure"])
    md.extend(["", "## Offline integrity check", "", "```bash",
               f"python3 {Path(__file__).name} --verify \"{json_path}\"", "```", ""])
    md_path = target_dir / "INSURABILITY_PACK_REPORT.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return {"target_dir": str(target_dir), "manifest_json": str(json_path), "report_md": str(md_path),
            "verified": self_verified, "evidence_status": evidence["status"], "compliance_status": "NOT_ASSESSED"}


def verify_insurability_pack(manifest_path: Path) -> bool:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        pack = data["pack"]
        canonical = json.dumps(pack, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(canonical).hexdigest() != data.get("canonical_sha256"):
            return False
        commitment = GroverProofDualLedger.compute_dual_hash("0" * 64, canonical.decode())
        if commitment != data.get("dual_ledger_commitment"):
            return False
        return HybridCompositeSigner.verify_hybrid(canonical, data["operator_attestation"])
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate or verify a VIOLET evidence inventory.")
    parser.add_argument("--client", default="whitemagic-sovereign")
    parser.add_argument("--out", default=None)
    parser.add_argument("--evidence-manifest", default=None, help="Explicit JSON pin manifest for local evidence")
    parser.add_argument("--verify", default=None)
    args = parser.parse_args()
    if args.verify:
        ok = verify_insurability_pack(Path(args.verify))
        print(json.dumps({"integrity_verified": ok, "trust": "local self-signature only"}, indent=2))
        sys.exit(0 if ok else 1)
    result = generate_insurability_pack(args.client, Path(args.out) if args.out else None,
                                        Path(args.evidence_manifest) if args.evidence_manifest else None)
    print(json.dumps(result, indent=2))
