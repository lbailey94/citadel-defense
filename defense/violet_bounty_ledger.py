#!/usr/bin/env python3
"""violet_bounty_ledger.py — Offensive Monetized Lanes Treasury & Bandit Bounty Ledger.

Tracks, records, and audits real and simulated counter-economic profits extracted
from adversaries and automated rogue swarms across Citadel's monetized defense lanes:

  [Lane 1] Crypto Gas Sweeps (violet_gas_trap):
           Native gas deposited by sweeper bots into honey-wallets, front-run to treasury.
  [Lane 2] Cognitive Token Sponge (violet_digital_twin):
           Adversarial LLM agent compute/token costs burned via synthetic system responses.
  [Lane 3] Proof-of-Work Computational Tax (violet_pow_gate):
           Forced client puzzle compute cycles and electrical energy extracted from scanners.
  [Lane 4] Paid x402 Micropayments & Session Passes (authd):
           Direct USDC on Base collected from reconnaissance agents purchasing evaluation passes.
  [Lane 5] Tarpit Time Dilation & Socket Exhaustion (wm-flytrap):
           Connection hold-time and memory allocation wasted on automated botnets.

Cryptographic Assurance:
  - Dual-hash audit chain: SHA-384 + BLAKE2b-512 chained hash for every entry.
  - Fail-closed tamper detection.
  - Real-time JSON summary and ASCII terminal dashboard.

Lineage: Edgerunner Violet Counter-Economics & Asymmetric Warfare.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
from typing import Any

# Default storage paths
DEFAULT_STATE_DIR = pathlib.Path(
    os.environ.get("WM_DEFENSE_STATE_DIR", "/var/lib/whitemagic-hosted/defense")
)
DEFAULT_LEDGER_PATH = DEFAULT_STATE_DIR / "bounty_ledger.jsonl"
DEFAULT_SUMMARY_PATH = DEFAULT_STATE_DIR / "bounty_summary.json"

# Pricing reference models (conservative baseline estimates)
DEFAULT_ETH_PRICE_USD = float(os.environ.get("CITADEL_ETH_PRICE_USD", "2500.00"))
DEFAULT_LLM_INPUT_COST_PER_M = float(os.environ.get("CITADEL_LLM_INPUT_COST_M", "3.00"))
DEFAULT_LLM_OUTPUT_COST_PER_M = float(os.environ.get("CITADEL_LLM_OUTPUT_COST_M", "15.00"))
DEFAULT_CPU_HOUR_COST_USD = float(os.environ.get("CITADEL_CPU_HOUR_COST_USD", "0.04"))  # ~$0.04/vCPU-hr


class BountyCategory:
    CRYPTO_GAS_SWEEP = "crypto_gas_sweep"
    COGNITIVE_TOKEN_SPONGE = "cognitive_token_sponge"
    POW_COMPUTATIONAL_TAX = "pow_computational_tax"
    X402_RECON_REVENUE = "x402_recon_revenue"
    TARPIT_TIME_DILATION = "tarpit_time_dilation"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _compute_dual_hash(preimage: str) -> str:
    data = preimage.encode("utf-8")
    h_sha = hashlib.sha384(data).hexdigest()
    h_blake = hashlib.blake2b(data, digest_size=64).hexdigest()
    return hashlib.sha256((h_sha + h_blake).encode("utf-8")).hexdigest()


class BountyLedger:
    """Thread-safe, tamper-evident dual-hash accounting ledger for Citadel offensive lanes."""

    def __init__(
        self,
        ledger_path: pathlib.Path | None = None,
        summary_path: pathlib.Path | None = None,
        treasury_address: str = "0xCitadelDefenseTreasury888888888888888888",
    ):
        if ledger_path is None:
            # Fallback for non-root local runs
            if DEFAULT_LEDGER_PATH.parent.exists() and os.access(DEFAULT_LEDGER_PATH.parent, os.W_OK):
                self.ledger_path = DEFAULT_LEDGER_PATH
                self.summary_path = summary_path or DEFAULT_SUMMARY_PATH
            else:
                user_state = pathlib.Path.home() / ".local/state/whitemagic/defense"
                self.ledger_path = user_state / "bounty_ledger.jsonl"
                self.summary_path = summary_path or (user_state / "bounty_summary.json")
        else:
            self.ledger_path = pathlib.Path(ledger_path)
            self.summary_path = pathlib.Path(summary_path or (self.ledger_path.parent / "bounty_summary.json"))

        self.treasury_address = treasury_address
        self._lock = threading.Lock()
        self._ensure_paths()
        self._last_id = 0
        self._last_hash = "0" * 64
        self._totals = self._blank_totals()
        self._initialize_state()

    def _ensure_paths(self) -> None:
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _blank_totals(self) -> dict[str, Any]:
        return {
            "generated_at": _now_iso(),
            "treasury_address": self.treasury_address,
            "total_counter_economic_value_usd": 0.0,
            "direct_crypto_loot": {
                "total_eth": 0.0,
                "total_usd": 0.0,
                "sweep_count": 0,
            },
            "cognitive_token_sponge": {
                "total_tokens_burned": 0,
                "total_usd_burned": 0.0,
                "sponge_count": 0,
            },
            "pow_computational_tax": {
                "total_hashes_extracted": 0,
                "estimated_joules": 0.0,
                "total_usd_value": 0.0,
                "challenge_count": 0,
            },
            "x402_recon_revenue": {
                "total_usdc": 0.0,
                "tx_count": 0,
            },
            "tarpit_time_dilation": {
                "total_seconds_wasted": 0.0,
                "connection_count": 0,
            },
            "total_entries": 0,
            "latest_entry_hash": "0" * 64,
            "chain_valid": True,
        }

    def _initialize_state(self) -> None:
        """Scan existing ledger once on startup to initialize last_id, last_hash, and totals."""
        if not self.ledger_path.exists() or self.ledger_path.stat().st_size == 0:
            return

        with self._lock:
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            doc = json.loads(line)
                            self._last_id = int(doc.get("entry_id", self._last_id))
                            self._last_hash = str(doc.get("entry_hash", self._last_hash))
                            self._accumulate_totals_locked(doc)
                        except Exception:
                            continue
            except Exception:
                pass

    def _accumulate_totals_locked(self, doc: dict[str, Any]) -> None:
        cat = doc.get("category")
        usd = float(doc.get("usd_value", 0.0))
        amt = float(doc.get("loot_amount", 0.0))

        self._totals["total_entries"] += 1
        self._totals["total_counter_economic_value_usd"] += usd
        self._totals["latest_entry_hash"] = doc.get("entry_hash", "")
        self._totals["generated_at"] = _now_iso()

        if cat == BountyCategory.CRYPTO_GAS_SWEEP:
            self._totals["direct_crypto_loot"]["total_eth"] += amt
            self._totals["direct_crypto_loot"]["total_usd"] += usd
            self._totals["direct_crypto_loot"]["sweep_count"] += 1
        elif cat == BountyCategory.COGNITIVE_TOKEN_SPONGE:
            self._totals["cognitive_token_sponge"]["total_tokens_burned"] += int(amt)
            self._totals["cognitive_token_sponge"]["total_usd_burned"] += usd
            self._totals["cognitive_token_sponge"]["sponge_count"] += 1
        elif cat == BountyCategory.POW_COMPUTATIONAL_TAX:
            self._totals["pow_computational_tax"]["total_hashes_extracted"] += int(amt)
            self._totals["pow_computational_tax"]["estimated_joules"] += doc.get("details", {}).get("estimated_joules", 0.0)
            self._totals["pow_computational_tax"]["total_usd_value"] += usd
            self._totals["pow_computational_tax"]["challenge_count"] += 1
        elif cat == BountyCategory.X402_RECON_REVENUE:
            self._totals["x402_recon_revenue"]["total_usdc"] += amt
            self._totals["x402_recon_revenue"]["tx_count"] += 1
        elif cat == BountyCategory.TARPIT_TIME_DILATION:
            self._totals["tarpit_time_dilation"]["total_seconds_wasted"] += amt
            self._totals["tarpit_time_dilation"]["connection_count"] += 1

    def _flush_summary_locked(self) -> None:
        """Atomically persist bounty_summary.json."""
        try:
            self.summary_path.parent.mkdir(parents=True, exist_ok=True)
            # Make a clean copy with rounded floats
            clean = json.loads(json.dumps(self._totals))
            clean["total_counter_economic_value_usd"] = round(clean["total_counter_economic_value_usd"], 4)
            clean["direct_crypto_loot"]["total_eth"] = round(clean["direct_crypto_loot"]["total_eth"], 6)
            clean["direct_crypto_loot"]["total_usd"] = round(clean["direct_crypto_loot"]["total_usd"], 2)
            clean["cognitive_token_sponge"]["total_usd_burned"] = round(clean["cognitive_token_sponge"]["total_usd_burned"], 4)
            clean["pow_computational_tax"]["estimated_joules"] = round(clean["pow_computational_tax"]["estimated_joules"], 2)
            clean["pow_computational_tax"]["total_usd_value"] = round(clean["pow_computational_tax"]["total_usd_value"], 4)
            clean["x402_recon_revenue"]["total_usdc"] = round(clean["x402_recon_revenue"]["total_usdc"], 4)
            clean["tarpit_time_dilation"]["total_seconds_wasted"] = round(clean["tarpit_time_dilation"]["total_seconds_wasted"], 1)

            fd, tmp = tempfile.mkstemp(prefix=".bounty_summary.", dir=str(self.summary_path.parent))
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(clean, tmp_file, indent=2)
            os.replace(tmp, self.summary_path)
        except Exception:
            pass

    def _append_entry(
        self,
        category: str,
        loot_amount: float,
        loot_units: str,
        usd_value: float,
        source_ip: str = "unknown",
        attacker_id: str = "unknown",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an entry with cryptographic dual-hash linkage in O(1) time."""
        with self._lock:
            self._last_id += 1
            entry_id = self._last_id
            last_hash = self._last_hash
            now_str = _now_iso()
            details = details or {}

            preimage = (
                f"{entry_id}:{now_str}:{category}:{loot_amount:.8f}:{usd_value:.4f}:"
                f"{source_ip}:{attacker_id}:{last_hash}"
            )
            entry_hash = _compute_dual_hash(preimage)
            self._last_hash = entry_hash

            record = {
                "entry_id": entry_id,
                "timestamp": now_str,
                "category": category,
                "source_ip": source_ip,
                "attacker_id": attacker_id,
                "loot_amount": round(loot_amount, 8),
                "loot_units": loot_units,
                "usd_value": round(usd_value, 4),
                "prev_hash": last_hash,
                "entry_hash": entry_hash,
                "details": details,
            }

            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

            self._accumulate_totals_locked(record)
            self._flush_summary_locked()
            return record

    def record_crypto_sweep(
        self,
        trap_address: str,
        attacker_address: str,
        deposit_wei: int,
        swept_wei: int,
        priority_fee_wei: int,
        tx_hash: str,
        source_ip: str = "unknown",
    ) -> dict[str, Any]:
        """Record an on-chain sweeper bot gas extraction."""
        swept_eth = swept_wei / 1e18
        usd_value = swept_eth * DEFAULT_ETH_PRICE_USD

        details = {
            "trap_address": trap_address,
            "attacker_address": attacker_address,
            "deposit_wei": deposit_wei,
            "swept_wei": swept_wei,
            "priority_fee_wei": priority_fee_wei,
            "swept_eth": swept_eth,
            "tx_hash": tx_hash,
            "treasury_destination": self.treasury_address,
            "attacker_result": "reverted_out_of_gas",
        }
        return self._append_entry(
            category=BountyCategory.CRYPTO_GAS_SWEEP,
            loot_amount=swept_eth,
            loot_units="ETH",
            usd_value=usd_value,
            source_ip=source_ip,
            attacker_id=attacker_address,
            details=details,
        )

    def record_token_sponge(
        self,
        endpoint: str,
        completion_tokens: int,
        prompt_tokens: int = 32,
        model: str = "gpt-4o",
        source_ip: str = "unknown",
    ) -> dict[str, Any]:
        """Record cognitive tokens burned on an adversarial crawler."""
        total_tokens = completion_tokens + prompt_tokens
        # Cost imposed on attacker using market LLM pricing
        cost_usd = (
            (prompt_tokens / 1_000_000) * DEFAULT_LLM_INPUT_COST_PER_M
            + (completion_tokens / 1_000_000) * DEFAULT_LLM_OUTPUT_COST_PER_M
        )

        details = {
            "endpoint": endpoint,
            "model_emulated": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }
        return self._append_entry(
            category=BountyCategory.COGNITIVE_TOKEN_SPONGE,
            loot_amount=float(total_tokens),
            loot_units="tokens",
            usd_value=cost_usd,
            source_ip=source_ip,
            attacker_id=f"crawler_{source_ip}",
            details=details,
        )

    def record_pow_tax(
        self,
        difficulty: int,
        iterations: int,
        source_ip: str = "unknown",
        solve_time_sec: float | None = None,
    ) -> dict[str, Any]:
        """Record computational labor extracted via client puzzle gates."""
        # Baseline: 1 hash = ~100 CPU instructions.
        # Compute cost estimate based on vCPU-seconds
        cpu_time = solve_time_sec or (iterations / 1_000_000.0)  # ~1M h/s reference
        cost_usd = (cpu_time / 3600.0) * DEFAULT_CPU_HOUR_COST_USD

        details = {
            "difficulty": difficulty,
            "iterations": iterations,
            "solve_time_sec": round(cpu_time, 4),
            "estimated_joules": round(iterations * 0.00005, 4),
        }
        return self._append_entry(
            category=BountyCategory.POW_COMPUTATIONAL_TAX,
            loot_amount=float(iterations),
            loot_units="hashes",
            usd_value=cost_usd,
            source_ip=source_ip,
            attacker_id=f"scanner_{source_ip}",
            details=details,
        )

    def record_x402_revenue(
        self,
        amount_usd: float,
        payer_id: str,
        tx_hash: str,
        endpoint: str,
        source_ip: str = "unknown",
    ) -> dict[str, Any]:
        """Record direct x402 micropayments captured from external crawlers/agents."""
        details = {
            "payer_id": payer_id,
            "tx_hash": tx_hash,
            "endpoint": endpoint,
            "chain": "base_mainnet",
        }
        return self._append_entry(
            category=BountyCategory.X402_RECON_REVENUE,
            loot_amount=amount_usd,
            loot_units="USDC",
            usd_value=amount_usd,
            source_ip=source_ip,
            attacker_id=payer_id,
            details=details,
        )

    def record_tarpit_dilation(
        self,
        hold_seconds: float,
        bytes_trickled: int,
        source_ip: str = "unknown",
    ) -> dict[str, Any]:
        """Record adversary connection hold-time and state memory exhausted."""
        # Bot connection cost estimate (~$0.0001 per connection-minute)
        cost_usd = (hold_seconds / 60.0) * 0.0001

        details = {
            "hold_seconds": round(hold_seconds, 2),
            "bytes_trickled": bytes_trickled,
        }
        return self._append_entry(
            category=BountyCategory.TARPIT_TIME_DILATION,
            loot_amount=round(hold_seconds, 2),
            loot_units="seconds",
            usd_value=cost_usd,
            source_ip=source_ip,
            attacker_id=f"tarpitted_{source_ip}",
            details=details,
        )

    def get_summary(self) -> dict[str, Any]:
        """Retrieve the latest summary (reads cache or returns in-memory state)."""
        if self.summary_path.exists():
            try:
                return json.loads(self.summary_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        with self._lock:
            self._flush_summary_locked()
            return dict(self._totals)

    def verify_chain(self) -> tuple[bool, str, int]:
        """Cryptographically verify the unbroken continuity of the dual-hash ledger."""
        if not self.ledger_path.exists():
            return True, "ledger_empty", 0

        prev_hash = "0" * 64
        count = 0

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except Exception as exc:
                    return False, f"json_parse_error_at_line_{idx}: {exc}", count

                expected_prev = doc.get("prev_hash")
                if expected_prev != prev_hash:
                    return (
                        False,
                        f"broken_chain_at_entry_{doc.get('entry_id')}: expected prev {prev_hash}, got {expected_prev}",
                        count,
                    )

                # Recompute dual hash
                entry_id = doc.get("entry_id")
                now_str = doc.get("timestamp")
                category = doc.get("category")
                loot_amount = float(doc.get("loot_amount", 0.0))
                usd_value = float(doc.get("usd_value", 0.0))
                source_ip = doc.get("source_ip", "")
                attacker_id = doc.get("attacker_id", "")

                preimage = (
                    f"{entry_id}:{now_str}:{category}:{loot_amount:.8f}:{usd_value:.4f}:"
                    f"{source_ip}:{attacker_id}:{prev_hash}"
                )
                computed_hash = _compute_dual_hash(preimage)
                if computed_hash != doc.get("entry_hash"):
                    return (
                        False,
                        f"tampered_hash_at_entry_{entry_id}: expected {computed_hash}, got {doc.get('entry_hash')}",
                        count,
                    )

                prev_hash = computed_hash
                count += 1

        return True, "verified", count

    def format_ascii_dashboard(self) -> str:
        """Render a formatted terminal dashboard of Citadel's counter-economic profits."""
        summary = self.get_summary()
        chain_ok, chain_msg, verified_count = self.verify_chain()

        c_loot = summary.get("direct_crypto_loot", {})
        t_sponge = summary.get("cognitive_token_sponge", {})
        p_tax = summary.get("pow_computational_tax", {})
        x_rev = summary.get("x402_recon_revenue", {})
        tp_dil = summary.get("tarpit_time_dilation", {})
        total_usd = summary.get("total_counter_economic_value_usd", 0.0)

        lines = [
            "═" * 76,
            " CITADEL OFFENSIVE MONETIZED LANES — BANDIT BOUNTY & PROFIT LEDGER",
            "═" * 76,
            f"Treasury Address : {summary.get('treasury_address')}",
            f"Audit Timestamp  : {summary.get('generated_at')}",
            f"Ledger Integrity : {'PASS (Unbroken Dual-Hash Chain)' if chain_ok else 'FAIL (' + chain_msg + ')'} ({verified_count} events verified)",
            "─" * 76,
            f"{'Monetized Lane / Extraction Category':<40} | {'Loot Extracted':<18} | {'Est. USD Value'}",
            "─" * 76,
            f"{'Lane 1: Web3 Sweeper Gas Trap':<40} | {c_loot.get('total_eth', 0.0):>10.4f} ETH       | ${c_loot.get('total_usd', 0.0):>10.2f}",
            f"{'  ↳ Sweeps Front-Run Into Treasury':<40} | {c_loot.get('sweep_count', 0):>10} sweeps    | 100% Sweeper Loss",
            f"{'Lane 2: Cognitive Token Sponge':<40} | {t_sponge.get('total_tokens_burned', 0):>10,} tokens    | ${t_sponge.get('total_usd_burned', 0.0):>10.2f}",
            f"{'  ↳ Deceptive Crawl Responses':<40} | {t_sponge.get('sponge_count', 0):>10} hits      | Adversary LLM Cost",
            f"{'Lane 3: PoW Computational Tax':<40} | {p_tax.get('total_hashes_extracted', 0):>10,} hashes    | ${p_tax.get('total_usd_value', 0.0):>10.4f}",
            f"{'  ↳ Forced Energy Expenditure':<40} | {p_tax.get('estimated_joules', 0.0):>10.1f} Joules    | {p_tax.get('challenge_count', 0)} Challenges",
            f"{'Lane 4: Paid x402 Recon Revenue':<40} | {x_rev.get('total_usdc', 0.0):>10.4f} USDC      | ${x_rev.get('total_usdc', 0.0):>10.2f}",
            f"{'  ↳ Voluntary Pass Purchases':<40} | {x_rev.get('tx_count', 0):>10} txs       | Base Settlement",
            f"{'Lane 5: Tarpit Time Dilation':<40} | {tp_dil.get('total_seconds_wasted', 0.0):>10.1f} sec       | {tp_dil.get('connection_count', 0)} Trapped IPs",
            "═" * 76,
            f"{'CUMULATIVE BANDIT PROFIT & REVERSAL IMPACT:':<40} | {'TOTAL EXTRACTION':<18} | ${total_usd:>10.2f}",
            "═" * 76,
        ]
        return "\n".join(lines)


def run_simulated_harvest(ledger: BountyLedger, count: int = 5) -> None:
    """Simulate an active harvest cycle catching bandits across all 5 lanes."""
    import secrets

    print(f"\n[+] Executing Simulated Bandit Harvest Cycle ({count} events per lane)...")

    # 1. Sweeper gas trap harvest
    for i in range(count):
        trap_addr = f"0xDecoyVault{secrets.token_hex(14)}"
        bot_addr = f"0xBanditBot{secrets.token_hex(15)}"
        deposit_wei = int(0.005 * 1e18)  # 0.005 ETH deposit
        swept_wei = int(0.0045 * 1e18)   # 90% net after 10% miner bribe
        ledger.record_crypto_sweep(
            trap_address=trap_addr,
            attacker_address=bot_addr,
            deposit_wei=deposit_wei,
            swept_wei=swept_wei,
            priority_fee_wei=deposit_wei - swept_wei,
            tx_hash="0x" + secrets.token_hex(32),
            source_ip=f"198.51.100.{10 + i}",
        )

    # 2. Token sponge harvest
    for i in range(count * 2):
        ledger.record_token_sponge(
            endpoint="/v1/chat/completions",
            completion_tokens=48,
            prompt_tokens=32,
            source_ip=f"203.0.113.{20 + i}",
        )

    # 3. PoW computational tax harvest
    for i in range(count):
        ledger.record_pow_tax(
            difficulty=4,
            iterations=65536 + secrets.randbelow(10000),
            source_ip=f"192.0.2.{30 + i}",
            solve_time_sec=0.15,
        )

    # 4. x402 revenue harvest
    for i in range(max(1, count // 2)):
        ledger.record_x402_revenue(
            amount_usd=0.01,
            payer_id=f"0xAgentRecon{secrets.token_hex(14)}",
            tx_hash="0x" + secrets.token_hex(32),
            endpoint="/mcp/memory_recall",
            source_ip=f"198.51.100.{50 + i}",
        )

    # 5. Tarpit dilation harvest
    for i in range(count):
        ledger.record_tarpit_dilation(
            hold_seconds=120.0 + secrets.randbelow(60),
            bytes_trickled=14,
            source_ip=f"198.51.100.{80 + i}",
        )

    print("[✓] Harvest simulation complete! Ledger updated with cryptographic dual-hash seals.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Citadel Offensive Monetized Lanes & Bounty Ledger")
    parser.add_argument("command", choices=["status", "summary", "verify-chain", "simulate-harvest", "json"],
                        nargs="?", default="status", help="Command to run")
    parser.add_argument("--ledger", type=pathlib.Path, default=None, help="Path to bounty_ledger.jsonl")
    parser.add_argument("--summary-file", type=pathlib.Path, default=None, help="Path to bounty_summary.json")
    parser.add_argument("--count", type=int, default=5, help="Number of events for simulate-harvest")
    args = parser.parse_args()

    ledger = BountyLedger(ledger_path=args.ledger, summary_path=args.summary_file)

    if args.command in ("status", "summary"):
        print(ledger.format_ascii_dashboard())
        return 0

    if args.command == "verify-chain":
        valid, reason, count = ledger.verify_chain()
        if valid:
            print(f"✓ Chain integrity verified: {count} entries validated with SHA-384 + BLAKE2b-512 dual hash.")
            return 0
        else:
            print(f"✗ Chain verification failed: {reason}")
            return 1

    if args.command == "simulate-harvest":
        run_simulated_harvest(ledger, count=args.count)
        print("\nUpdated Bounty Dashboard:")
        print(ledger.format_ascii_dashboard())
        return 0

    if args.command == "json":
        summary = ledger.get_summary()
        print(json.dumps(summary, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
