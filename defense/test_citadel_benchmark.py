"""test_citadel_benchmark.py — Unit test wrapper for citadel_comprehensive_benchmark."""

import pytest
import citadel_comprehensive_benchmark as bench


def test_pow_gate_benchmark_invariants():
    results = bench.benchmark_pow_gate()
    assert results["verification_ops_per_sec"] > 10_000
    assert results["peak_cost_asymmetry_ratio"] > 100
    assert results["rejection_invariants_pass"] is True


def test_digital_twin_and_token_sponge_invariants():
    results = bench.benchmark_digital_twin_and_token_sponge()
    assert results["token_generation_rate"] > 100_000
    assert results["mean_sponge_tokens"] > 10
    assert results["attacker_cost_per_10k_usd"] > 0.50
    assert results["dotenv_generation_ops_per_sec"] > 500


def test_canary_tokens_and_dual_ledger_invariants():
    results = bench.benchmark_canary_tokens_and_dual_ledger()
    assert results["minting_ops_per_sec"] > 5_000
    assert results["verify_ops_per_sec"] > 10_000
    assert results["dual_ledger_hash_rate"] > 20_000
    assert results["verified_tokens_ratio"] == 1.0


def test_web3_gas_trap_invariants():
    results = bench.benchmark_web3_gas_trap()
    assert results["sweeps_per_sec"] > 5_000
    assert results["treasury_captured_eth"] > 0
    assert results["reverted_ratio"] == 1.0


def test_venus_flytrap_taxonomy_invariants():
    results = bench.benchmark_venus_flytrap_taxonomy()
    assert results["classification_ops_per_sec"] > 50_000
    assert results["two_touch_invariant_pass"] is True
    assert results["protected_ip_immunity_pass"] is True


def test_spa_gate_invariants():
    results = bench.benchmark_spa_pre_socket_gate()
    if results.get("available"):
        assert results["knock_generation_ops_per_sec"] > 1_000
        assert results["replay_protection_verified"] is True
