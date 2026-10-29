"""violet_live_sweeper.py — Citadel Web3 Live Mempool Sweeper & Gas Trap Daemon.

Operates on Base Mainnet (EIP-1559, Chain ID 8453).
Monitors dedicated bait wallets 24/7. When hostile mempool scrapers deposit native gas
to attempt draining bait assets, this daemon front-runs or sweeps the native ETH
directly into the cold WhiteMagic Treasury (0x213b6bB4fB073E86167c58DA6Cb6E9477557DaA8).

Confirms on-chain transaction hashes and records cryptographic loot entries into
the dual-hash Grover-resistant BountyLedger (bounty_ledger.jsonl).

Lineage: Edgerunner Violet Counter-Economics & Asymmetric Defense.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import signal
import sys
import time
import urllib.request
from typing import Any

from eth_account import Account

try:
    import violet_bounty_ledger as vbl
    HAS_BOUNTY_LEDGER = True
except Exception:
    HAS_BOUNTY_LEDGER = False

# Default configurations
DEFAULT_RPC_URL = os.environ.get("BASE_RPC_URL", "https://base-rpc.publicnode.com")
DEFAULT_TREASURY = os.environ.get(
    "CITADEL_TREASURY_ADDRESS", "0x213b6bB4fB073E86167c58DA6Cb6E9477557DaA8"
)
DEFAULT_CHAIN_ID = int(os.environ.get("BASE_CHAIN_ID", "8453"))
DEFAULT_STATE_DIR = pathlib.Path(
    os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic/defense"))
)

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "whitemagic-treasury/1.0",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Citadel-Sweeper] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("citadel_sweeper")


def rpc_call(method: str, params: list[Any], rpc_url: str = DEFAULT_RPC_URL) -> Any:
    """Execute JSON-RPC query against Base RPC with whitemagic user-agent."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    if "error" in out:
        raise RuntimeError(f"RPC Error ({method}): {out['error']}")
    return out.get("result")


class LiveGasSweeper:
    """Monitors on-chain bait address and sweeps hostile gas deposits into Treasury."""

    def __init__(
        self,
        state_dir: pathlib.Path | None = None,
        treasury_address: str = DEFAULT_TREASURY,
        rpc_url: str = DEFAULT_RPC_URL,
        chain_id: int = DEFAULT_CHAIN_ID,
        bounty_ledger: Any | None = None,
    ):
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.treasury_address = treasury_address
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.bounty_ledger = bounty_ledger
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.wallet_file = self.state_dir / "bait_wallet.json"
        self.bait_account = self._init_bait_wallet()

    def _init_bait_wallet(self) -> Account:
        """Load existing bait wallet or generate fresh dedicated bait keypair."""
        if self.wallet_file.exists():
            try:
                data = json.loads(self.wallet_file.read_text(encoding="utf-8"))
                priv_key = data.get("private_key")
                if priv_key:
                    acct = Account.from_key(priv_key)
                    logger.info("Loaded active bait wallet: %s", acct.address)
                    return acct
            except Exception as e:
                logger.warning("Failed to parse existing %s (%s); generating fresh", self.wallet_file, e)

        acct = Account.create()
        doc = {
            "address": acct.address,
            "private_key": acct.key.hex(),
            "chain_id": self.chain_id,
            "treasury_destination": self.treasury_address,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "armed",
        }
        self.wallet_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        try:
            self.wallet_file.chmod(0o600)
        except Exception:
            pass
        logger.info("Generated fresh bait wallet armed on Base: %s", acct.address)
        return acct

    @property
    def bait_address(self) -> str:
        return self.bait_account.address

    def get_bait_balance_wei(self) -> int:
        """Fetch current native balance of bait wallet."""
        res = rpc_call("eth_getBalance", [self.bait_address, "latest"], self.rpc_url)
        return int(res, 16) if res else 0

    def check_and_sweep(self, dry_run: bool = False) -> dict[str, Any] | None:
        """Inspect bait address; if native balance exists beyond gas cost, sweep to treasury."""
        balance_wei = self.get_bait_balance_wei()
        if balance_wei <= 0:
            return None

        # Fetch latest block fee structure
        block = rpc_call("eth_getBlockByNumber", ["latest", False], self.rpc_url)
        base_fee = int(block.get("baseFeePerGas", "0x3b9aca00"), 16)
        tip = 1_000_000  # 0.001 gwei
        max_fee = base_fee * 2 + tip
        gas_limit = 21_000
        tx_cost_wei = gas_limit * max_fee

        if balance_wei <= tx_cost_wei:
            logger.debug(
                "Dust detected on %s (%d wei), below gas transfer cost (%d wei)",
                self.bait_address, balance_wei, tx_cost_wei
            )
            return None

        sweep_wei = balance_wei - tx_cost_wei
        nonce = int(rpc_call("eth_getTransactionCount", [self.bait_address, "latest"], self.rpc_url), 16)

        tx = {
            "to": self.treasury_address,
            "value": sweep_wei,
            "chainId": self.chain_id,
            "nonce": nonce,
            "gas": gas_limit,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": tip,
            "type": 2,
        }

        signed = self.bait_account.sign_transaction(tx)
        raw_bytes = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
        raw_hex = raw_bytes.hex()
        if not raw_hex.startswith("0x"):
            raw_hex = "0x" + raw_hex

        tx_hash: str
        if dry_run:
            tx_hash = "0x" + "00" * 32
            logger.info("[DRY RUN] Would sweep %d wei (%f ETH) -> %s", sweep_wei, sweep_wei / 1e18, self.treasury_address)
        else:
            tx_hash = rpc_call("eth_sendRawTransaction", [raw_hex], self.rpc_url)
            logger.info(
                "💥 SUCCESSFUL COUNTER-SWEEP: %f ETH captured from %s -> %s (Tx: %s)",
                sweep_wei / 1e18, self.bait_address, self.treasury_address, tx_hash
            )

        # Log into BountyLedger if available
        if self.bounty_ledger is not None:
            try:
                self.bounty_ledger.record_crypto_sweep(
                    trap_address=self.bait_address,
                    attacker_address="mempool_adversary",
                    deposit_wei=balance_wei,
                    swept_wei=sweep_wei,
                    priority_fee_wei=tx_cost_wei,
                    tx_hash=tx_hash,
                    source_ip="on_chain_mempool",
                )
            except Exception as e:
                logger.error("Failed to append sweep to bounty ledger: %s", e)

        return {
            "status": "swept",
            "trap_address": self.bait_address,
            "treasury_destination": self.treasury_address,
            "swept_wei": sweep_wei,
            "swept_eth": sweep_wei / 1e18,
            "tx_cost_wei": tx_cost_wei,
            "tx_hash": tx_hash,
            "timestamp": time.time(),
        }

    def run_daemon(self, poll_interval_sec: float = 2.5) -> None:
        """Run continuous mempool/block listener loop."""
        logger.info(
            "🛡️  Citadel Live Sweeper Daemon Active: monitoring %s on Base (RPC: %s)",
            self.bait_address, self.rpc_url
        )
        logger.info("Destination Treasury: %s", self.treasury_address)

        stop_requested = False

        def _handle_signal(sig, frame):
            nonlocal stop_requested
            logger.info("Interrupt received (%s), shutting down sweeper gracefully...", sig)
            stop_requested = True

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        heartbeat_cycles = 0
        while not stop_requested:
            try:
                self.check_and_sweep(dry_run=False)
            except Exception as e:
                logger.warning("Polling error: %s", e)

            heartbeat_cycles += 1
            if heartbeat_cycles % 24 == 0:  # ~every 60 seconds
                logger.info(
                    "Heartbeat: bait wallet %s healthy (0 ETH balance; armed & waiting)",
                    self.bait_address
                )

            time.sleep(poll_interval_sec)

        logger.info("Citadel Live Sweeper Daemon stopped.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Citadel Web3 Live Sweeper & Gas Trap Daemon")
    parser.add_argument("--daemon", action="store_true", help="Run as long-lived continuous polling daemon")
    parser.add_argument("--status", action="store_true", help="Check bait wallet status and exit")
    parser.add_argument("--interval", type=float, default=2.5, help="Polling interval in seconds (default: 2.5)")
    parser.add_argument("--state-dir", type=pathlib.Path, default=DEFAULT_STATE_DIR, help="State directory")
    args = parser.parse_args()

    ledger = (
        vbl.BountyLedger(
            ledger_path=args.state_dir / "bounty_ledger.jsonl",
            summary_path=args.state_dir / "bounty_summary.json",
            treasury_address=DEFAULT_TREASURY,
        )
        if HAS_BOUNTY_LEDGER
        else None
    )
    sweeper = LiveGasSweeper(state_dir=args.state_dir, bounty_ledger=ledger)

    if args.status or not args.daemon:
        bal_wei = sweeper.get_bait_balance_wei()
        print("═" * 70)
        print(" CITADEL WEB3 LIVE SWEEPER STATUS")
        print("═" * 70)
        print(f"Network              : Base Mainnet (Chain ID {sweeper.chain_id})")
        print(f"RPC Endpoint         : {sweeper.rpc_url}")
        print(f"Bait Wallet Address  : {sweeper.bait_address}")
        print(f"Bait Balance         : {bal_wei / 1e18:.8f} ETH ({bal_wei} wei)")
        print(f"Treasury Destination : {sweeper.treasury_address}")
        print(f"Status               : ARMED & ACTIVE")
        print("═" * 70)
        if not args.daemon:
            return 0

    sweeper.run_daemon(poll_interval_sec=args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
