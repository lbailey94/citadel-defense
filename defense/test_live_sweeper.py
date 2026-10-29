"""test_live_sweeper.py — Unit tests for Citadel Web3 Live Sweeper & Gas Trap Daemon."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from eth_account import Account

import violet_bounty_ledger as vbl
import violet_live_sweeper as vls


@pytest.fixture
def temp_state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "defense_state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_bait_wallet_initialization(temp_state_dir: Path):
    """Verify fresh bait wallet generation and subsequent re-loading."""
    sweeper = vls.LiveGasSweeper(state_dir=temp_state_dir)
    addr1 = sweeper.bait_address
    assert addr1.startswith("0x")
    assert len(addr1) == 42
    assert sweeper.wallet_file.exists()

    # Re-instantiate: must load the exact same address
    sweeper2 = vls.LiveGasSweeper(state_dir=temp_state_dir)
    assert sweeper2.bait_address == addr1


def test_sweeper_check_dust_or_empty(temp_state_dir: Path):
    """Verify that zero balance or balance below gas threshold does not trigger sweep."""
    sweeper = vls.LiveGasSweeper(state_dir=temp_state_dir)

    with patch.object(sweeper, "get_bait_balance_wei", return_value=0):
        result = sweeper.check_and_sweep()
        assert result is None

    # Dust balance below 21,000 gas * 2 gwei = 42,000,000,000,000 wei
    with patch.object(sweeper, "get_bait_balance_wei", return_value=1000):
        with patch("violet_live_sweeper.rpc_call", return_value={"baseFeePerGas": "0x3b9aca00"}):
            result = sweeper.check_and_sweep()
            assert result is None


def test_sweeper_successful_counter_sweep(temp_state_dir: Path):
    """Verify that incoming funds trigger EIP-1559 sweep and record to bounty ledger."""
    ledger_path = temp_state_dir / "bounty_ledger.jsonl"
    summary_path = temp_state_dir / "bounty_summary.json"
    ledger = vbl.BountyLedger(ledger_path=ledger_path, summary_path=summary_path)

    sweeper = vls.LiveGasSweeper(state_dir=temp_state_dir, bounty_ledger=ledger)

    deposit_wei = int(0.005 * 1e18)  # 0.005 ETH deposit
    with patch.object(sweeper, "get_bait_balance_wei", return_value=deposit_wei):
        with patch("violet_live_sweeper.rpc_call") as mock_rpc:
            def rpc_side_effect(method, params, rpc_url=None):
                if method == "eth_getBlockByNumber":
                    return {"baseFeePerGas": "0x1000000"}  # ~0.016 gwei
                elif method == "eth_getTransactionCount":
                    return "0x0"
                elif method == "eth_sendRawTransaction":
                    return "0xMockedTxHash777777777777777777777777777777777777777777777777777777"
                return None

            mock_rpc.side_effect = rpc_side_effect

            receipt = sweeper.check_and_sweep(dry_run=False)
            assert receipt is not None
            assert receipt["status"] == "swept"
            assert receipt["swept_wei"] > 0
            assert receipt["tx_hash"].startswith("0xMockedTxHash")

            # Verify recorded in BountyLedger
            summary = ledger.get_summary()
            assert summary["direct_crypto_loot"]["sweep_count"] == 1
            assert summary["direct_crypto_loot"]["total_eth"] > 0.0049
            assert summary["chain_valid"] is True
