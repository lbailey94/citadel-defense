#!/usr/bin/env python3
"""Run selected internal checks and report their actual scope.

This is a reproduction aid, not a security audit or assurance score. Unsupported
legacy lanes remain NOT_EVALUATED. No product modules, keys, or personal stores
are loaded. Reports are written only to the explicitly supplied output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CITADEL_DIR = Path(__file__).resolve().parent.parent
VERDICTS = {"TRUSTED", "UNTRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE"}
UNSUPPORTED = {
    "citadel_defense": (
        "NOT_EVALUATED",
        "Legacy XDP nanoseconds time Python simulate_xdp_eval, not a loaded kernel "
        "program. The legacy CTF score is assigned constants. Its cost ratio uses "
        "assumed prices; it is not a measured adversarial cost comparison. The "
        "custom hash-chain signature prototype is not a FIPS 205 SLH-DSA implementation.",
    ),
    "kernel_confinement": (
        "NOT_EVALUATED",
        "The legacy escape battery counts any nonzero process exit as blocking, "
        "without proving startup, readable controls, or the enforcement cause. "
        "Independent positive/negative controls and kernel identity are required.",
    ),
    "memory_crystals": (
        "NOT_EVALUATED",
        "The legacy lane was a hardcoded anchor-location truth table. No memory "
        "store, agmi attacks, encryption, read path, or erasure was exercised.",
    ),
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command_result(command: list[str], *, cwd: Path, env=None, timeout=30) -> dict:
    """Preserve a failed process as a failure, including its diagnostic output."""
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed_ms": (time.perf_counter() - started) * 1000,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": command,
            "returncode": None,
            "error": str(exc),
            "stdout": "", "stderr": "",
            "elapsed_ms": (time.perf_counter() - started) * 1000,
        }


def leaf_rate(leaf_count: int, elapsed_ms: float) -> float | None:
    """Compute leaves/second from this process wall time, including check/startup."""
    if not math.isfinite(elapsed_ms) or elapsed_ms <= 0:
        return None
    return leaf_count * 1000 / elapsed_ms


def git_identity(root: Path) -> dict:
    """Record checkout identity without equating an existing binary to that source."""
    identity = {}
    for name, args in (("commit", ["rev-parse", "HEAD"]),
                       ("tree", ["rev-parse", "HEAD^{tree}"]),
                       ("working_tree", ["status", "--porcelain"])):
        result = command_result(["git", *args], cwd=root)
        identity[name] = result["stdout"].strip() if result["returncode"] == 0 else None
    return identity


def audit_bend(bend_bin: Path | None, proof_dir: Path) -> dict:
    scope = (
        "Bool/Nat algebraic lemmas checked by Bend and separately rechecked with "
        "its kernel when available, plus two synthetic U32 "
        "tree folds. No runtime permission model, signatures, receipt parsing, "
        "cryptographic hashes, storage, or rollback attacker is represented."
    )
    if bend_bin is None or not bend_bin.is_file():
        return {"status": "NOT_EVALUATED", "scope": scope, "reason": "Bend executable unavailable"}
    version = command_result([str(bend_bin), "version"], cwd=proof_dir)
    laws_file = proof_dir / "citta_pac_laws.bend"
    laws = command_result([str(bend_bin), str(laws_file), "--check-only"], cwd=proof_dir)
    laws["status"] = "PASS" if laws["returncode"] == 0 else "FAIL"
    laws["law_count"] = len(re.findall(r"^law ", laws_file.read_text(), re.MULTILINE))
    kernel = command_result([str(bend_bin), str(laws_file), "--verdict"], cwd=proof_dir)
    if kernel["returncode"] == 0:
        kernel["status"] = "PASS"
    elif "BendTT infrastructure:" in kernel["stdout"] + kernel["stderr"]:
        kernel["status"] = "NOT_EVALUATED"
    else:
        kernel["status"] = "FAIL"
    folds = {}
    for name, filename, prefix, leaves in (
        ("receipt_named_arithmetic_fold", "cpr_batch.bend", "BATCH_CPR_DAG_VERIFIED", 1 << 20),
        ("swarm_named_arithmetic_fold", "citta_pac_swarm.bend", "SWARM_WARRANT_DIGEST", 1 << 22),
    ):
        result = command_result([str(bend_bin), str(proof_dir / filename)], cwd=proof_dir)
        marker_found = re.search(rf"^{prefix}=\d+$", result["stdout"], re.MULTILINE) is not None
        result.update({
            "status": "PASS" if result["returncode"] == 0 and marker_found else "FAIL",
            "leaf_count": leaves,
            "leaf_count_basis": "fixed-depth program tree; not a measured executed-operation counter",
            "tree_node_count": 2 * leaves - 1,
            "synthetic_leaves_per_second": leaf_rate(leaves, result["elapsed_ms"]),
            "timing_scope": "process wall time, including Bend checking and startup",
        })
        folds[name] = result
    statuses = [laws["status"], kernel["status"], *(result["status"] for result in folds.values())]
    status = "FAIL" if "FAIL" in statuses else ("NOT_EVALUATED" if "NOT_EVALUATED" in statuses else "PASS")
    return {
        "status": status,
        "scope": scope,
        "compiler_sha256": sha256_file(bend_bin),
        "compiler_version": version,
        "source_sha256": {path.name: sha256_file(path) for path in sorted(proof_dir.glob("*.bend"))},
        "laws": laws, "kernel_recheck": kernel, "folds": folds,
    }


def verifier_observation(result: dict) -> tuple[str, tuple[str, ...]] | None:
    """Agreement between crashes, empty output, or invalid verdicts is not parity."""
    if result["returncode"] not in (0, 1):
        return None
    try:
        payload = json.loads(result["stdout"])
        verdict = payload["verdict"]
        errors = payload["errors"]
        if verdict not in VERDICTS or not isinstance(errors, list):
            return None
        if any(not isinstance(error, dict) or not isinstance(error.get("code"), str) for error in errors):
            return None
        if result["returncode"] != (0 if verdict == "TRUSTED" else 1):
            return None
        return verdict, tuple(sorted(error["code"] for error in errors))
    except (ValueError, KeyError, TypeError):
        return None


def audit_differential(cpr_dir: Path | None) -> dict:
    scope = (
        "Verdict and error-code agreement across all three same-project verifier "
        "implementations on the three declared bundle manifests, with their "
        "require-anchor options and expected verdict/code checks. Agreement is not an "
        "independent correctness oracle, a fuzz campaign, or runtime enforcement."
    )
    if cpr_dir is None:
        return {"status": "NOT_EVALUATED", "scope": scope, "reason": "Supply --cpr-dir to select source and built engines"}
    cpr_dir = cpr_dir.resolve()
    rust = cpr_dir / "rust/target/debug/continuity-receipt-verify"
    js = cpr_dir / "js/dist/cli.js"
    node = shutil.which("node")
    missing = [name for name, present in (
        ("python source", (cpr_dir / "continuity_receipt/verify.py").is_file()),
        ("rust executable", rust.is_file() and os.access(rust, os.X_OK)),
        ("node runtime", node is not None),
        ("javascript built CLI", js.is_file()),
    ) if not present]
    manifests = [cpr_dir / "vectors" / name for name in
                 ("manifest.json", "manifest-0.5.json", "manifest-0.6.json")]
    missing += [path.name for path in manifests if not path.is_file()]
    if missing:
        return {
            "status": "NOT_EVALUATED", "scope": scope,
            "reason": "Unavailable inputs: " + ", ".join(missing),
            "total_vectors": 0, "compared_vectors": 0,
        }
    cases = []
    vector_root = (cpr_dir / "vectors").resolve()
    for manifest in manifests:
        entries = json.loads(manifest.read_text())["vectors"]
        for entry in entries:
            vector = (vector_root / entry["file"]).resolve()
            if not vector.is_relative_to(vector_root) or not vector.is_file():
                raise ValueError(f"missing or out-of-scope vector in {manifest.name}: {entry['file']}")
            if entry["expected_verdict"] not in VERDICTS or type(entry["require_anchor"]) is not bool:
                raise ValueError(f"invalid expected result in {manifest.name}: {entry['file']}")
            cases.append((manifest.name, vector, entry))
    if not cases:
        return {"status": "NOT_EVALUATED", "scope": scope,
                "reason": "Bundle manifests contain no cases", "total_vectors": 0,
                "compared_vectors": 0}
    env = os.environ.copy()
    env["PYTHONPATH"] = str(cpr_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    records = []
    for manifest_name, vector, entry in cases:
        engines = {}
        observations = []
        for name, command in (
            ("python", [sys.executable, "-m", "continuity_receipt.verify", str(vector)]),
            ("rust", [str(rust), str(vector)]),
            ("javascript", [node, str(js), str(vector)]),
        ):
            if entry["require_anchor"]:
                command.append("--require-anchor")
            result = command_result(command, cwd=cpr_dir, env=env, timeout=5)
            observation = verifier_observation(result)
            result["valid_observation"] = observation is not None
            result["matches_expected"] = (
                observation is not None and observation[0] == entry["expected_verdict"]
                and (entry.get("expected_code") is None or entry["expected_code"] in observation[1])
            )
            engines[name] = result
            observations.append(observation)
        comparable = all(observation is not None for observation in observations)
        agreement = comparable and len(set(observations)) == 1
        records.append({
            "manifest": manifest_name, "vector": vector.name, "sha256": sha256_file(vector),
            "expected_verdict": entry["expected_verdict"], "require_anchor": entry["require_anchor"],
            "comparable": comparable, "agreement": agreement,
            "matches_expected": all(result["matches_expected"] for result in engines.values()),
            "engines": engines,
        })
    return {
        "status": "PASS" if all(record["agreement"] and record["matches_expected"] for record in records) else "FAIL",
        "scope": scope, "total_vectors": len(cases),
        "manifest_sha256": {path.name: sha256_file(path) for path in manifests},
        "source_identity": git_identity(cpr_dir),
        "build_provenance": "Existing built engines were selected and hashed; source-to-binary correspondence was not established by this command",
        "python_source_sha256": {str(path.relative_to(cpr_dir)): sha256_file(path)
                                 for path in sorted((cpr_dir / "continuity_receipt").glob("*.py"))},
        "javascript_module_sha256": {str(path.relative_to(cpr_dir)): sha256_file(path)
                                     for path in sorted((cpr_dir / "js/dist").rglob("*.js"))},
        "compared_vectors": sum(record["comparable"] for record in records),
        "agreeing_vectors": sum(record["agreement"] for record in records),
        "engine_sha256": {"python": sha256_file(Path(sys.executable).resolve()),
                          "rust": sha256_file(rust), "node": sha256_file(Path(node).resolve()),
                          "javascript_cli": sha256_file(js)},
        "records": records,
    }


def selected_status(checks: dict) -> str:
    """Missing checks are incomplete; an actual failure takes precedence."""
    statuses = [check["status"] for check in checks.values()]
    if "FAIL" in statuses:
        return "FAIL"
    if not statuses or any(status != "PASS" for status in statuses):
        return "INCOMPLETE"
    return "PASS"


def markdown_report(report: dict) -> str:
    lines = [
        "# Citadel selected internal checks", "",
        f"Generated: {report['timestamp']}",
        f"Selected checks: {', '.join(report['selected_checks'])}",
        f"Selected-check status: **{report['selected_status']}**", "",
        "This is a maintainer-run reproduction report. PASS applies only to the "
        "named checks. It is not an independent audit, assurance percentage, "
        "production qualification, or evidence of untested security properties.", "",
        "| Check | Status | Scope |", "|---|---|---|",
    ]
    for name, check in report["checks"].items():
        lines.append(f"| {name} | {check['status']} | {check.get('scope', check.get('reason', ''))} |")
    bend = report["checks"].get("bend", {})
    if "laws" in bend:
        lines += ["", "## Bend measurements", "",
                  f"Front-end lemma check: {bend['laws']['status']} ({bend['laws']['law_count']} declarations).",
                  f"Separate kernel recheck: {bend['kernel_recheck']['status']}.", "",
                  "| Synthetic fold | Leaves | Wall time (ms) | Leaves/s | Status |",
                  "|---|---:|---:|---:|---|"]
        for name, fold in bend["folds"].items():
            rate = fold["synthetic_leaves_per_second"]
            lines.append(f"| {name} | {fold['leaf_count']} | {fold['elapsed_ms']:.3f} | "
                         f"{f'{rate:.3f}' if rate is not None else 'unavailable'} | {fold['status']} |")
        lines += ["", "Times include Bend checking and process startup. Leaves are synthetic "
                  "arithmetic tree positions, not measured executed-operation counts, agents, "
                  "or cryptographically verified receipts."]
    for name, check in report["checks"].items():
        if check.get("reason"):
            lines += ["", f"{name}: {check['reason']}"]
    lines += ["", "See the paired JSON for command outputs, failures, source hashes, "
              "compiler identity, and per-vector observations. See docs/AUDIT_SCOPE.md "
              "in the source checkout for the remaining review work.", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checks", nargs="+", choices=("bend", "differential"), default=["bend"])
    parser.add_argument("--bend-bin", type=Path, default=Path(shutil.which("bend")) if shutil.which("bend") else None)
    parser.add_argument("--cpr-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    selected = list(dict.fromkeys(args.checks))
    checks = {}
    for name in selected:
        try:
            checks[name] = audit_bend(args.bend_bin, CITADEL_DIR / "proofs") if name == "bend" else audit_differential(args.cpr_dir)
        except Exception as exc:
            checks[name] = {"status": "FAIL", "reason": f"Check failed to complete: {type(exc).__name__}: {exc}"}
    for name in ("bend", "differential"):
        checks.setdefault(name, {"status": "NOT_SELECTED", "reason": "Not requested in this invocation"})
    for name, (status, reason) in UNSUPPORTED.items():
        checks[name] = {"status": status, "reason": reason}
    status = selected_status({name: checks[name] for name in selected})
    report = {
        "schema": "citadel-internal-checks/1", "timestamp": datetime.now(timezone.utc).isoformat(),
        "selected_checks": selected, "selected_status": status,
        "scope": "Selected internal checks; no independent security audit or overall assurance score",
        "host": {"system": os.uname().sysname, "release": os.uname().release, "machine": os.uname().machine},
        "generator_sha256": sha256_file(Path(__file__)), "checks": checks,
        "source_identity": git_identity(CITADEL_DIR),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "practice-audit-report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output_dir / "practice-audit-report.md").write_text(markdown_report(report))
    for name, check in checks.items():
        print(f"{name}: {check['status']}")
    print(f"Selected-check status: {status}; report directory: {args.output_dir}")
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
