"""test_bounty_ledger.py — Comprehensive Unit Tests for Citadel Bounty Ledger."""

import json
import pathlib
import tempfile
import pytest

import violet_bounty_ledger as vbl
import violet_gas_trap as gas_trap
import violet_pow_gate as pow_gate
import violet_digital_twin as dt


@pytest.fixture
def temp_ledger(tmp_path):
    ledger_path = tmp_path / "test_bounty_ledger.jsonl"
    summary_path = tmp_path / "test_bounty_summary.json"
    return vbl.BountyLedger(
        ledger_path=ledger_path,
        summary_path=summary_path,
        treasury_address="0xTestTreasury00000000000000000000000000",
    )


class TestBountyLedger:
    def test_empty_ledger_state(self, temp_ledger):
        summary = temp_ledger.get_summary()
        assert summary["total_entries"] == 0
        assert summary["total_counter_economic_value_usd"] == 0.0
        valid, status, count = temp_ledger.verify_chain()
        assert valid is True
        assert count == 0

    def test_record_crypto_sweep(self, temp_ledger):
        deposit = int(0.01 * 1e18)
        swept = int(0.009 * 1e18)
        fee = int(0.001 * 1e18)
        rec = temp_ledger.record_crypto_sweep(
            trap_address="0xTrap123",
            attacker_address="0xBandit456",
            deposit_wei=deposit,
            swept_wei=swept,
            priority_fee_wei=fee,
            tx_hash="0xTx789",
            source_ip="198.51.100.1",
        )
        assert rec["entry_id"] == 1
        assert rec["loot_units"] == "ETH"
        assert rec["loot_amount"] == 0.009
        assert rec["usd_value"] == 0.009 * vbl.DEFAULT_ETH_PRICE_USD

        summary = temp_ledger.get_summary()
        assert summary["total_entries"] == 1
        assert summary["direct_crypto_loot"]["total_eth"] == 0.009
        assert summary["direct_crypto_loot"]["sweep_count"] == 1

        valid, status, count = temp_ledger.verify_chain()
        assert valid is True
        assert count == 1

    def test_record_multiple_lanes_and_chain_continuity(self, temp_ledger):
        # 1. Sweep
        temp_ledger.record_crypto_sweep(
            trap_address="0xTrap1",
            attacker_address="0xBot1",
            deposit_wei=int(0.005 * 1e18),
            swept_wei=int(0.0045 * 1e18),
            priority_fee_wei=int(0.0005 * 1e18),
            tx_hash="0xTx1",
            source_ip="198.51.100.1",
        )
        # 2. Token sponge
        temp_ledger.record_token_sponge(
            endpoint="/v1/chat/completions",
            completion_tokens=60,
            prompt_tokens=30,
            source_ip="198.51.100.2",
        )
        # 3. PoW Tax
        temp_ledger.record_pow_tax(
            difficulty=4,
            iterations=65536,
            source_ip="198.51.100.3",
            solve_time_sec=0.2,
        )
        # 4. x402 revenue
        temp_ledger.record_x402_revenue(
            amount_usd=0.05,
            payer_id="0xReconAgent",
            tx_hash="0xTx4",
            endpoint="/mcp",
            source_ip="198.51.100.4",
        )
        # 5. Tarpit dilation
        temp_ledger.record_tarpit_dilation(
            hold_seconds=180.0,
            bytes_trickled=20,
            source_ip="198.51.100.5",
        )

        summary = temp_ledger.get_summary()
        assert summary["total_entries"] == 5
        assert summary["direct_crypto_loot"]["sweep_count"] == 1
        assert summary["cognitive_token_sponge"]["sponge_count"] == 1
        assert summary["pow_computational_tax"]["challenge_count"] == 1
        assert summary["x402_recon_revenue"]["tx_count"] == 1
        assert summary["tarpit_time_dilation"]["connection_count"] == 1
        assert summary["total_counter_economic_value_usd"] > 0

        valid, status, count = temp_ledger.verify_chain()
        assert valid is True
        assert count == 5

    def test_tamper_detection_fails_closed(self, temp_ledger):
        for i in range(3):
            temp_ledger.record_token_sponge(
                endpoint="/v1/messages",
                completion_tokens=50,
                source_ip=f"198.51.100.{i}",
            )

        # Tamper with entry 2 in the ledger file
        lines = temp_ledger.ledger_path.read_text(encoding="utf-8").splitlines()
        doc = json.loads(lines[1])
        doc["loot_amount"] = 999999.0  # Tampered amount
        lines[1] = json.dumps(doc)
        temp_ledger.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, reason, count = temp_ledger.verify_chain()
        assert valid is False
        assert "tampered_hash_at_entry_2" in reason


class TestBountyIntegrations:
    def test_gas_trap_integration(self, tmp_path):
        ledger = vbl.BountyLedger(
            ledger_path=tmp_path / "gas_bounty.jsonl",
            summary_path=tmp_path / "gas_summary.json",
        )
        pot = gas_trap.GasTrapHoneypot(bounty_ledger=ledger)
        trap = pot.deploy_trap("test_vault", "USDC", 5000.0)

        receipt = pot.simulate_attacker_deposit_and_counter_sweep(
            trap["address"], "0xAttacker", int(0.005 * 1e18)
        )
        assert receipt["result"] == "ATTACKER_FUNDS_CAPTURED"

        summary = ledger.get_summary()
        assert summary["direct_crypto_loot"]["sweep_count"] == 1
        assert summary["direct_crypto_loot"]["total_eth"] == 0.0045

    def test_digital_twin_token_sponge_integration(self, tmp_path):
        ledger = vbl.BountyLedger(
            ledger_path=tmp_path / "twin_bounty.jsonl",
            summary_path=tmp_path / "twin_summary.json",
        )
        twin = dt.ProceduralDigitalTwin(bounty_ledger=ledger)
        resp = twin.provider_decoy("/v1/chat/completions", method="POST", src_ip="198.51.100.99")
        assert resp is not None
        assert "choices" in resp

        summary = ledger.get_summary()
        assert summary["cognitive_token_sponge"]["sponge_count"] == 1
        assert summary["cognitive_token_sponge"]["total_tokens_burned"] > 0

    def test_pow_gate_integration(self, tmp_path):
        ledger = vbl.BountyLedger(
            ledger_path=tmp_path / "pow_bounty.jsonl",
            summary_path=tmp_path / "pow_summary.json",
        )
        gate = pow_gate.PoWGate(bounty_ledger=ledger)
        chal = gate.generate_challenge("198.51.100.88", difficulty=3)
        nonce, _, _ = pow_gate.PoWGate.solve(chal)
        assert nonce is not None

        ok, reason = gate.verify_solution(chal, nonce, "198.51.100.88")
        assert ok is True

        summary = ledger.get_summary()
        assert summary["pow_computational_tax"]["challenge_count"] == 1
        assert summary["pow_computational_tax"]["total_hashes_extracted"] == 16 ** 3
