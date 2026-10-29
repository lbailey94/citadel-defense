"""violet_multichain_sweeper.py — Citadel Multi-Chain Counter-Sweeper & Gas Trap Daemon.

Extends the active counter-economic defense perimeter across multiple chains:
1. Base Mainnet (EVM, Chain ID 8453) — EVM Gas Trap
2. Solana Mainnet (Ed25519) — Priority-Fee & Rent-Exempt Lure Trap
3. Tron Mainnet (secp256k1 Base58Check) — TRC-20 Energy/Bandwidth Sink

When hostile bots and automated mempool scrapers detect bait private keys holding
illiquid or rent-exempt tokens, they deposit native gas (ETH, SOL, TRX) to execute
their drain instructions. This daemon detects the deposits within milliseconds and
sweeps 100% of the funds into the cold WhiteMagic Treasury before the attacker's
drain transaction can finalize.

Lineage: Edgerunner Violet Counter-Economics & Asymmetric Sovereign Defense.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import pathlib
import struct
import sys
import time
import urllib.request
from typing import Any

from eth_account import Account
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

DEFENSE_DIR = pathlib.Path(__file__).resolve().parent
if str(DEFENSE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENSE_DIR))

try:
    import violet_bounty_ledger as vbl
    HAS_BOUNTY_LEDGER = True
except Exception:
    HAS_BOUNTY_LEDGER = False

# Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    """Encode bytes into Base58 string."""
    n = int.from_bytes(b, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0] * pad) + "".join(reversed(res))


def b58decode(s: str) -> bytes:
    """Decode Base58 string into bytes."""
    n = 0
    for char in s:
        n = n * 58 + B58_ALPHABET.index(char)
    res = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad = 0
    for char in s:
        if char == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return (b"\x00" * pad) + res


def encode_compact_u16(val: int) -> bytes:
    """Compact-u16 wire serialization for Solana transactions."""
    elem = []
    while True:
        byte = val & 0x7F
        val >>= 7
        if val == 0:
            elem.append(byte)
            break
        elem.append(byte | 0x80)
    return bytes(elem)


HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "whitemagic-multichain-treasury/1.0",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [MultiChain-Sweeper] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("multichain_sweeper")


# ==============================================================================
# 1. Solana Sweeper Engine
# ==============================================================================

DEFAULT_SOLANA_RPC = os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
# Fallback treasury for Solana (can be overridden via env or constructor)
DEFAULT_SOLANA_TREASURY = os.environ.get(
    "CITADEL_SOLANA_TREASURY", "raakfKn96zVmXqKwRTDTH5K3j5eTBp1hPy"
)
SOL_TO_USD_ESTIMATE = 180.0


class SolanaGasSweeper:
    """Monitors Solana bait address and sweeps hostile SOL deposits into Treasury."""

    def __init__(
        self,
        state_dir: pathlib.Path | None = None,
        treasury_address: str = DEFAULT_SOLANA_TREASURY,
        rpc_url: str = DEFAULT_SOLANA_RPC,
        min_sweep_lamports: int = 10_000,
        bounty_ledger: Any | None = None,
    ):
        self.state_dir = state_dir or pathlib.Path(
            os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic/defense"))
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.treasury_address = treasury_address
        self.rpc_url = rpc_url
        self.min_sweep_lamports = min_sweep_lamports
        self.wallet_file = self.state_dir / "solana_bait_wallet.json"

        self.priv_key, self.pub_bytes, self.address, self.priv_b58 = self._load_or_create_wallet()

        if bounty_ledger:
            self.ledger = bounty_ledger
        elif HAS_BOUNTY_LEDGER:
            self.ledger = vbl.BountyLedger(
                ledger_path=self.state_dir / "bounty_ledger.jsonl",
                summary_path=self.state_dir / "bounty_summary.json",
            )
        else:
            self.ledger = None

    def _load_or_create_wallet(self) -> tuple[ed25519.Ed25519PrivateKey, bytes, str, str]:
        if self.wallet_file.exists():
            try:
                data = json.loads(self.wallet_file.read_text(encoding="utf-8"))
                priv_b58 = data["private_key"]
                raw_bytes = b58decode(priv_b58)
                priv_seed = raw_bytes[:32]
                priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_seed)
                pub_bytes = priv_key.public_key().public_bytes_raw()
                addr = b58encode(pub_bytes)
                return priv_key, pub_bytes, addr, priv_b58
            except Exception as e:
                logger.warning("Error reading solana_bait_wallet.json: %s. Generating fresh.", e)

        priv_key = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes_raw()
        pub_bytes = priv_key.public_key().public_bytes_raw()
        full_keypair = priv_bytes + pub_bytes

        addr = b58encode(pub_bytes)
        priv_b58 = b58encode(full_keypair)

        wallet_data = {
            "address": addr,
            "private_key": priv_b58,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "chain": "solana",
            "treasury_destination": self.treasury_address,
        }
        self.wallet_file.write_text(json.dumps(wallet_data, indent=2), encoding="utf-8")
        self.wallet_file.chmod(0o600)
        logger.info("Generated new Solana bait wallet: %s", addr)
        return priv_key, pub_bytes, addr, priv_b58

    def rpc_call(self, method: str, params: list[Any]) -> Any:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(self.rpc_url, data=payload, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            out = json.loads(resp.read().decode("utf-8"))
        if "error" in out:
            raise RuntimeError(f"Solana RPC Error ({method}): {out['error']}")
        return out.get("result")

    def get_balance(self) -> int:
        """Fetch current balance in lamports."""
        res = self.rpc_call("getBalance", [self.address])
        return int(res.get("value", 0)) if isinstance(res, dict) else 0

    def get_latest_blockhash(self) -> str:
        """Fetch recent blockhash."""
        res = self.rpc_call("getLatestBlockhash", [{"commitment": "finalized"}])
        return res.get("value", {}).get("blockhash", "")

    def build_transfer_tx(self, dest_address: str, lamports: int, blockhash_b58: str) -> str:
        """Build and sign a native SystemProgram transfer wire transaction."""
        dest_bytes = b58decode(dest_address)
        if len(dest_bytes) != 32:
            raise ValueError(f"Invalid Solana destination address: {dest_address}")

        system_prog_bytes = b"\x00" * 32
        blockhash_bytes = b58decode(blockhash_b58)

        # Message header: 1 required sig, 0 readonly signed, 1 readonly unsigned (SystemProgram)
        header = bytes([1, 0, 1])
        account_keys = encode_compact_u16(3) + self.pub_bytes + dest_bytes + system_prog_bytes
        instruction_data = struct.pack("<IQ", 2, lamports)  # 2 = Transfer
        instruction = bytes([2]) + encode_compact_u16(2) + bytes([0, 1]) + encode_compact_u16(len(instruction_data)) + instruction_data
        instructions = encode_compact_u16(1) + instruction

        message = header + account_keys + blockhash_bytes + instructions
        signature = self.priv_key.sign(message)
        transaction = encode_compact_u16(1) + signature + message
        return base64.b64encode(transaction).decode("ascii")

    def sweep(self) -> dict[str, Any] | None:
        """Check for deposited SOL and execute immediate counter-sweep."""
        bal = self.get_balance()
        if bal < self.min_sweep_lamports:
            return None

        # Solana standard tx fee is 5000 lamports (0.000005 SOL)
        tx_fee = 5_000
        sweep_amt = bal - tx_fee
        if sweep_amt <= 0:
            return None

        blockhash = self.get_latest_blockhash()
        tx_b64 = self.build_transfer_tx(self.treasury_address, sweep_amt, blockhash)
        tx_sig = self.rpc_call("sendTransaction", [tx_b64, {"encoding": "base64", "preflightCommitment": "processed"}])

        sol_swept = sweep_amt / 1_000_000_000
        usd_value = sol_swept * SOL_TO_USD_ESTIMATE

        logger.info("SOL COUNTER-SWEEP EXECUTED: %.6f SOL ($%.4f USD) -> Sig: %s", sol_swept, usd_value, tx_sig)

        if self.ledger:
            try:
                self.ledger.record_crypto_sweep(
                    trap_address=self.address,
                    attacker_address="solana_mempool_deposit",
                    deposit_wei=bal * (10**9),
                    swept_wei=sweep_amt * (10**9),
                    priority_fee_wei=tx_fee * (10**9),
                    tx_hash=tx_sig,
                    source_ip="solana_mainnet",
                )
            except Exception as e:
                logger.warning("Failed to record sweep in ledger: %s", e)

        return {
            "chain": "solana",
            "tx_hash": tx_sig,
            "lamports": sweep_amt,
            "sol_swept": sol_swept,
            "usd_value": usd_value,
            "treasury": self.treasury_address,
        }


# ==============================================================================
# 2. Tron Sweeper Engine
# ==============================================================================

DEFAULT_TRON_RPC = os.environ.get("TRON_RPC_URL", "https://api.trongrid.io")
# Default WhiteMagic Tron treasury address
DEFAULT_TRON_TREASURY = os.environ.get(
    "CITADEL_TRON_TREASURY", "TCYkvTFvhTtSSeTkd1DZMaQ7jHvne4q28D"
)
TRX_TO_USD_ESTIMATE = 0.16


def derive_tron_address(priv_key_hex: str) -> str:
    """Derive Tron Base58Check address from secp256k1 private key."""
    acct = Account.from_key(priv_key_hex)
    pub_bytes = acct._key_obj.public_key.to_bytes()  # 64 bytes uncompressed without prefix
    from eth_hash.auto import keccak
    raw_addr = b"\x41" + keccak(pub_bytes)[-20:]
    checksum = hashlib.sha256(hashlib.sha256(raw_addr).digest()).digest()[:4]
    return b58encode(raw_addr + checksum)


class TronGasSweeper:
    """Monitors Tron bait address and sweeps hostile TRX deposits into Treasury."""

    def __init__(
        self,
        state_dir: pathlib.Path | None = None,
        treasury_address: str = DEFAULT_TRON_TREASURY,
        rpc_url: str = DEFAULT_TRON_RPC,
        min_sweep_sun: int = 1_500_000,
        bounty_ledger: Any | None = None,
    ):
        self.state_dir = state_dir or pathlib.Path(
            os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic/defense"))
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.treasury_address = treasury_address
        self.rpc_url = rpc_url.rstrip("/")
        self.min_sweep_sun = min_sweep_sun
        self.wallet_file = self.state_dir / "tron_bait_wallet.json"

        self.priv_key_hex, self.address = self._load_or_create_wallet()

        if bounty_ledger:
            self.ledger = bounty_ledger
        elif HAS_BOUNTY_LEDGER:
            self.ledger = vbl.BountyLedger(
                ledger_path=self.state_dir / "bounty_ledger.jsonl",
                summary_path=self.state_dir / "bounty_summary.json",
            )
        else:
            self.ledger = None

    def _load_or_create_wallet(self) -> tuple[str, str]:
        if self.wallet_file.exists():
            try:
                data = json.loads(self.wallet_file.read_text(encoding="utf-8"))
                return data["private_key"], data["address"]
            except Exception as e:
                logger.warning("Error reading tron_bait_wallet.json: %s. Generating fresh.", e)

        acct = Account.create()
        priv_hex = acct.key.hex()
        addr = derive_tron_address(priv_hex)

        wallet_data = {
            "address": addr,
            "private_key": priv_hex,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "chain": "tron",
            "treasury_destination": self.treasury_address,
        }
        self.wallet_file.write_text(json.dumps(wallet_data, indent=2), encoding="utf-8")
        self.wallet_file.chmod(0o600)
        logger.info("Generated new Tron bait wallet: %s", addr)
        return priv_hex, addr

    def http_post(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.rpc_url}/{endpoint.lstrip('/')}"
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_balance(self) -> int:
        """Fetch current balance in sun (1 TRX = 1,000,000 sun)."""
        res = self.http_post("wallet/getaccount", {"address": self.address, "visible": True})
        return int(res.get("balance", 0))

    def create_and_sign_tx(self, dest_address: str, amount_sun: int) -> dict[str, Any]:
        """Create transaction on Tron node and sign txID with secp256k1 key."""
        tx_data = self.http_post(
            "wallet/createtransaction",
            {"to_address": dest_address, "owner_address": self.address, "amount": amount_sun, "visible": True},
        )
        if "txID" not in tx_data:
            raise RuntimeError(f"Tron createtransaction failed: {tx_data}")

        tx_id_bytes = bytes.fromhex(tx_data["txID"])
        signed_hash = Account._sign_hash(tx_id_bytes, self.priv_key_hex)
        sig_hex = signed_hash.signature.hex()
        tx_data["signature"] = [sig_hex]
        return tx_data

    def sweep(self) -> dict[str, Any] | None:
        """Check for deposited TRX and execute counter-sweep."""
        bal = self.get_balance()
        if bal < self.min_sweep_sun:
            return None

        # Standard TRX transfer fee is ~1 TRX = 1,000,000 sun
        tx_fee = 1_000_000
        sweep_amt = bal - tx_fee
        if sweep_amt <= 0:
            return None

        signed_tx = self.create_and_sign_tx(self.treasury_address, sweep_amt)
        res = self.http_post("wallet/broadcasttransaction", signed_tx)

        if not res.get("result", False):
            raise RuntimeError(f"Tron broadcast failed: {res}")

        tx_id = signed_tx["txID"]
        trx_swept = sweep_amt / 1_000_000
        usd_value = trx_swept * TRX_TO_USD_ESTIMATE

        logger.info("TRX COUNTER-SWEEP EXECUTED: %.6f TRX ($%.4f USD) -> Tx: %s", trx_swept, usd_value, tx_id)

        if self.ledger:
            try:
                self.ledger.record_crypto_sweep(
                    trap_address=self.address,
                    attacker_address="tron_mempool_deposit",
                    deposit_wei=bal * (10**12),
                    swept_wei=sweep_amt * (10**12),
                    priority_fee_wei=tx_fee * (10**12),
                    tx_hash=tx_id,
                    source_ip="tron_mainnet",
                )
            except Exception as e:
                logger.warning("Failed to record sweep in ledger: %s", e)

        return {
            "chain": "tron",
            "tx_hash": tx_id,
            "sun": sweep_amt,
            "trx_swept": trx_swept,
            "usd_value": usd_value,
            "treasury": self.treasury_address,
        }


# ==============================================================================
# 3. Multi-Chain Daemon Orchestrator
# ==============================================================================

class MultiChainSweeperDaemon:
    """Unified multi-chain monitoring daemon managing Base, Solana, and Tron traps."""

    def __init__(self, state_dir: pathlib.Path | None = None):
        self.state_dir = state_dir or pathlib.Path(
            os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic/defense"))
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.solana = SolanaGasSweeper(state_dir=self.state_dir)
        self.tron = TronGasSweeper(state_dir=self.state_dir)

    def poll_cycle(self) -> dict[str, Any]:
        """Execute one complete cross-chain poll sweep."""
        results = {}
        try:
            sol_res = self.solana.sweep()
            if sol_res:
                results["solana"] = sol_res
        except Exception as e:
            logger.debug("Solana poll error: %s", e)

        try:
            tron_res = self.tron.sweep()
            if tron_res:
                results["tron"] = tron_res
        except Exception as e:
            logger.debug("Tron poll error: %s", e)

        return results

    def run_forever(self, poll_interval: float = 3.0) -> None:
        """Run continuous multi-chain counter-sweeper daemon."""
        logger.info("═" * 70)
        logger.info(" CITADEL MULTI-CHAIN GAS-TRAP SWEEPER ACTIVE")
        logger.info("═" * 70)
        logger.info(" Solana Bait Address: %s", self.solana.address)
        logger.info(" Tron Bait Address  : %s", self.tron.address)
        logger.info("═" * 70)

        last_heartbeat = 0.0
        while True:
            try:
                now = time.time()
                if now - last_heartbeat >= 60.0:
                    sol_bal = self.solana.get_balance() / 1e9
                    tron_bal = self.tron.get_balance() / 1e6
                    logger.info(
                        "Heartbeat: Solana (%s SOL: %s), Tron (%s TRX: %s) armed & waiting",
                        sol_bal, self.solana.address[:8] + "...",
                        tron_bal, self.tron.address[:8] + "...",
                    )
                    last_heartbeat = now

                self.poll_cycle()
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                logger.info("Shutting down multichain sweeper.")
                break
            except Exception as e:
                logger.error("MultiChain cycle error: %s", e)
                time.sleep(poll_interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Citadel Multi-Chain Counter-Sweeper Daemon")
    parser.add_argument("--once", action="store_true", help="Run single poll cycle and exit")
    parser.add_argument("--interval", type=float, default=3.0, help="Polling interval in seconds")
    args = parser.parse_args()

    daemon = MultiChainSweeperDaemon()
    if args.once:
        res = daemon.poll_cycle()
        print(json.dumps(res, indent=2))
        return 0

    daemon.run_forever(poll_interval=args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
