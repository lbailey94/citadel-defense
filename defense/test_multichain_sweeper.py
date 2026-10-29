"""test_multichain_sweeper.py — Unit tests for Citadel Multi-Chain Gas Sweeper."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import violet_bounty_ledger as vbl
import violet_multichain_sweeper as vms


@pytest.fixture
def temp_state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "defense_state"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ==============================================================================
# Solana Sweeper Tests
# ==============================================================================

def test_solana_wallet_generation_and_reload(temp_state_dir: Path):
    """Verify fresh Solana bait keypair generation and deterministic reload."""
    sweeper1 = vms.SolanaGasSweeper(state_dir=temp_state_dir)
    addr1 = sweeper1.address
    assert len(addr1) >= 32 and len(addr1) <= 44
    assert sweeper1.wallet_file.exists()

    # Re-instantiate: must load the exact same address
    sweeper2 = vms.SolanaGasSweeper(state_dir=temp_state_dir)
    assert sweeper2.address == addr1
    assert sweeper2.priv_b58 == sweeper1.priv_b58


def test_solana_transfer_tx_building(temp_state_dir: Path):
    """Verify Solana SystemProgram transfer transaction serialization."""
    sweeper = vms.SolanaGasSweeper(state_dir=temp_state_dir)
    dest_address = "raakfKn96zVmXqKwRTDTH5K3j5eTBp1hPy"
    # Ensure valid 32-byte dest
    dest_b58 = vms.b58encode(b"\x02" * 32)
    fake_blockhash = vms.b58encode(b"\x09" * 32)

    tx_b64 = sweeper.build_transfer_tx(dest_b58, 50_000, fake_blockhash)
    assert isinstance(tx_b64, str)
    assert len(tx_b64) > 100


def test_solana_counter_sweep_mock(temp_state_dir: Path):
    """Verify complete Solana sweep when hostile deposit lands."""
    ledger = vbl.BountyLedger(
        ledger_path=temp_state_dir / "bounty_ledger.jsonl",
        summary_path=temp_state_dir / "bounty_summary.json",
    )
    sweeper = vms.SolanaGasSweeper(state_dir=temp_state_dir, bounty_ledger=ledger)

    dest_b58 = vms.b58encode(b"\x03" * 32)
    sweeper.treasury_address = dest_b58
    fake_blockhash = vms.b58encode(b"\x09" * 32)

    # Mock RPC responses
    with patch.object(sweeper, "get_balance", return_value=1_000_000):  # 0.001 SOL
        with patch.object(sweeper, "get_latest_blockhash", return_value=fake_blockhash):
            with patch.object(sweeper, "rpc_call", return_value="5KtPnMockSolanaTxSignature"):
                res = sweeper.sweep()

    assert res is not None
    assert res["chain"] == "solana"
    assert res["lamports"] == 995_000  # 1_000_000 - 5000 fee
    assert res["sol_swept"] == 0.000995
    assert res["tx_hash"] == "5KtPnMockSolanaTxSignature"

    # Verify recorded into BountyLedger
    summary = ledger.get_summary()
    assert summary["direct_crypto_loot"]["sweep_count"] == 1
    assert summary["direct_crypto_loot"]["total_eth"] > 0


# ==============================================================================
# Tron Sweeper Tests
# ==============================================================================

def test_tron_wallet_generation_and_reload(temp_state_dir: Path):
    """Verify Tron secp256k1 key generation and address format."""
    sweeper1 = vms.TronGasSweeper(state_dir=temp_state_dir)
    addr1 = sweeper1.address
    assert addr1.startswith("T")
    assert len(addr1) == 34
    assert sweeper1.wallet_file.exists()

    # Re-instantiate: must load same address
    sweeper2 = vms.TronGasSweeper(state_dir=temp_state_dir)
    assert sweeper2.address == addr1
    assert sweeper2.priv_key_hex == sweeper1.priv_key_hex


def test_tron_counter_sweep_mock(temp_state_dir: Path):
    """Verify complete Tron sweep when hostile deposit lands."""
    ledger = vbl.BountyLedger(
        ledger_path=temp_state_dir / "bounty_ledger.jsonl",
        summary_path=temp_state_dir / "bounty_summary.json",
    )
    sweeper = vms.TronGasSweeper(state_dir=temp_state_dir, bounty_ledger=ledger)

    mock_tx_raw = {
        "txID": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "raw_data": {"contract": []},
    }

    # Mock get_balance returning 25,000,000 sun (25 TRX)
    with patch.object(sweeper, "get_balance", return_value=25_000_000):
        with patch.object(sweeper, "http_post") as mock_post:
            def side_effect(endpoint, data):
                if endpoint == "wallet/createtransaction":
                    return mock_tx_raw.copy()
                if endpoint == "wallet/broadcasttransaction":
                    return {"result": True}
                return {}
            mock_post.side_effect = side_effect

            res = sweeper.sweep()

    assert res is not None
    assert res["chain"] == "tron"
    assert res["sun"] == 24_000_000  # 25M - 1M fee
    assert res["trx_swept"] == 24.0
    assert res["tx_hash"] == mock_tx_raw["txID"]

    summary = ledger.get_summary()
    assert summary["direct_crypto_loot"]["sweep_count"] == 1
    assert summary["direct_crypto_loot"]["total_eth"] > 0


def test_multichain_daemon_poll_cycle(temp_state_dir: Path):
    """Verify unified poll cycle handles both chains cleanly."""
    daemon = vms.MultiChainSweeperDaemon(state_dir=temp_state_dir)
    with patch.object(daemon.solana, "sweep", return_value={"chain": "solana", "sol_swept": 0.05}):
        with patch.object(daemon.tron, "sweep", return_value={"chain": "tron", "trx_swept": 15.0}):
            cycle_res = daemon.poll_cycle()

    assert "solana" in cycle_res
    assert "tron" in cycle_res
    assert cycle_res["solana"]["sol_swept"] == 0.05
    assert cycle_res["tron"]["trx_swept"] == 15.0
