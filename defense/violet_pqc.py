#!/usr/bin/env python3
"""Experimental Ed25519 plus custom hash-chain signatures and dual hashes.

This is not a complete SLH-DSA implementation or validated FIPS 203/204/205
cryptography. The hash-chain construction reuses its seed across calls; its
security under multiple signatures has not been established. No quantum work
factor or transport security follows from the benchmark. Historical class,
wire-format, and CLI labels remain for compatibility, not as conformance claims.
See docs/AUDIT_SCOPE.md before interpreting this prototype's output.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

STATE_DIR = Path(os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic")))
KEY_PATH = Path(os.environ.get("VIOLET_KEY_PATH", os.path.expanduser("~/.config/whitemagic/violet/redops.key")))
PQC_KEY_PATH = Path(os.environ.get("VIOLET_PQC_KEY_PATH", os.path.expanduser("~/.config/whitemagic/violet/redops_pqc.key")))

WOTS_W = 16
WOTS_MAX_STEP = WOTS_W - 1  # 15
WOTS_MSG_NIBBLES = 96       # SHA-384 = 48 bytes = 96 base-16 nibbles
WOTS_CSUM_NIBBLES = 3       # Max checksum = 96 * 15 = 1440 < 16^3 (4096)
WOTS_TOTAL_CHAINS = WOTS_MSG_NIBBLES + WOTS_CSUM_NIBBLES  # 99 chains


def _message_to_wots_nibbles(message: bytes) -> list[int]:
    """Convert message to 96 SHA-384 nibbles + 3 base-16 Winternitz checksum nibbles."""
    digest = hashlib.sha384(message).digest()
    msg_nibbles: list[int] = []
    for byte_val in digest:
        msg_nibbles.append((byte_val >> 4) & 0x0F)
        msg_nibbles.append(byte_val & 0x0F)

    csum = sum(WOTS_MAX_STEP - d for d in msg_nibbles)
    csum_nibbles = [
        (csum >> 8) & 0x0F,
        (csum >> 4) & 0x0F,
        csum & 0x0F,
    ]
    return msg_nibbles + csum_nibbles


def _wots_chain_step(val: bytes, pk_seed: bytes, chain_idx: int, start_step: int, steps: int) -> bytes:
    """Custom tweakable hash-chain step; this is not a FIPS conformance claim."""
    curr = val
    for s in range(start_step, start_step + steps):
        curr = hashlib.sha256(pk_seed + bytes([chain_idx, s]) + curr).digest()
    return curr


class StatelessHashSignature:
    """Custom Winternitz-style hash-chain experiment, not standard SLH-DSA.

    Checksums and tweakable chains alone do not implement a stateless signature
    scheme or establish security when one key is reused for multiple messages.
    """

    def __init__(self, seed: bytes | None = None):
        self.seed = seed or secrets.token_bytes(64)
        self.sk_seed = hashlib.blake2b(self.seed + b":sk", digest_size=32).digest()
        self.pk_seed = hashlib.blake2b(self.seed + b":pk", digest_size=32).digest()
        self.pubkey_root = self._compute_pubkey_root()

    def _secret_leaf(self, chain_idx: int) -> bytes:
        return hashlib.blake2b(self.sk_seed + bytes([chain_idx]), digest_size=32).digest()

    def _compute_pubkey_root(self) -> str:
        h = hashlib.sha384()
        h.update(self.pk_seed)
        for i in range(WOTS_TOTAL_CHAINS):
            leaf = self._secret_leaf(i)
            endpoint = _wots_chain_step(leaf, self.pk_seed, i, 0, WOTS_MAX_STEP)
            h.update(endpoint)
        return h.hexdigest()

    def sign(self, message: bytes) -> dict:
        """Sign a message by stepping each of the 99 chains forward `d_i` times."""
        nibbles = _message_to_wots_nibbles(message)
        sig_elements: list[str] = []
        for i, d_i in enumerate(nibbles):
            leaf = self._secret_leaf(i)
            sigma_i = _wots_chain_step(leaf, self.pk_seed, i, 0, d_i)
            sig_elements.append(sigma_i.hex())

        return {
            "scheme": "SLH-WOTS-SHA384-99",
            "pubkey_root": self.pubkey_root,
            "pk_seed": self.pk_seed.hex(),
            "elements": sig_elements,
        }

    @staticmethod
    def verify(message: bytes, sig_dict: dict, expected_pubkey_root: str | None = None) -> bool:
        """Verify the hash-based signature by completing the remaining (15 - d_i) steps of all 99 chains."""
        try:
            if not isinstance(sig_dict, dict):
                return False
            pubkey_root = sig_dict.get("pubkey_root", "")
            pk_seed_hex = sig_dict.get("pk_seed", "")
            elements = sig_dict.get("elements", [])

            if (
                not isinstance(pubkey_root, str)
                or len(pubkey_root) != 96
                or not isinstance(pk_seed_hex, str)
                or len(pk_seed_hex) != 64
                or not isinstance(elements, list)
                or len(elements) != WOTS_TOTAL_CHAINS
            ):
                return False

            if expected_pubkey_root is not None and not hmac.compare_digest(pubkey_root, expected_pubkey_root):
                return False

            pk_seed = bytes.fromhex(pk_seed_hex)
            nibbles = _message_to_wots_nibbles(message)

            h = hashlib.sha384()
            h.update(pk_seed)
            for i, d_i in enumerate(nibbles):
                elem_hex = elements[i]
                if not isinstance(elem_hex, str) or len(elem_hex) != 64:
                    return False
                sigma_i = bytes.fromhex(elem_hex)
                remaining_steps = WOTS_MAX_STEP - d_i
                endpoint = _wots_chain_step(sigma_i, pk_seed, i, d_i, remaining_steps)
                h.update(endpoint)

            reconstructed_root = h.hexdigest()
            return hmac.compare_digest(reconstructed_root, pubkey_root)
        except Exception:
            return False


class HybridCompositeSigner:
    """Ed25519 plus an experimental reusable-key hash-chain construction."""

    def __init__(self, key_path: Path = KEY_PATH, pqc_key_path: Path = PQC_KEY_PATH):
        self.key_path = key_path
        self.pqc_key_path = pqc_key_path
        self.ed25519_sk = self._load_or_create_ed25519()
        self.slh_signer = self._load_or_create_slh()

    def _load_or_create_ed25519(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            raw = self.key_path.read_text().strip()
            seed = base64.urlsafe_b64decode(raw + "==")
            return Ed25519PrivateKey.from_private_bytes(seed)
        sk = Ed25519PrivateKey.generate()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        raw = base64.urlsafe_b64encode(sk.private_bytes_raw()).decode().rstrip("=")
        self.key_path.write_text(raw)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return sk

    def _load_or_create_slh(self) -> StatelessHashSignature:
        if self.pqc_key_path.exists():
            raw_seed = bytes.fromhex(self.pqc_key_path.read_text().strip())
            return StatelessHashSignature(raw_seed)
        signer = StatelessHashSignature()
        self.pqc_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.pqc_key_path.write_text(signer.seed.hex())
        try:
            os.chmod(self.pqc_key_path, 0o600)
        except OSError:
            pass
        return signer

    def sign_hybrid(self, message: bytes) -> dict:
        """Produce the historical composite format; no FIPS conformance is claimed."""
        t0 = time.time()
        # 1. Classical Ed25519 signature (64 bytes)
        ed_sig = self.ed25519_sk.sign(message)
        ed_sig_b64 = base64.urlsafe_b64encode(ed_sig).decode("ascii")
        ed_pub_hex = self.ed25519_sk.public_key().public_bytes_raw().hex()

        # 2. Experimental hash-chain signature; legacy wire labels are retained.
        slh_sig = self.slh_signer.sign(message)

        elapsed_ms = (time.time() - t0) * 1000
        return {
            "hybrid_version": "v2-fips205-wots99",
            "security_status": "experimental_not_fips_validated",
            "ts": datetime.now(timezone.utc).isoformat(),
            "classical": {
                "algorithm": "Ed25519",
                "pubkey": ed_pub_hex,
                "signature": ed_sig_b64,
            },
            "post_quantum": {
                "algorithm": "SLH-WOTS-SHA384-99",
                "pubkey_root": self.slh_signer.pubkey_root,
                "signature": slh_sig,
            },
            "signing_elapsed_ms": round(elapsed_ms, 3),
        }

    @staticmethod
    def verify_hybrid(
        message: bytes,
        hybrid_envelope: dict,
        expected_ed25519_pub: str | None = None,
        expected_pqc_root: str | None = None,
    ) -> bool:
        """Check Ed25519 and the custom hash-chain format; no standard conformance follows."""
        try:
            # 1. Verify Classical Ed25519
            cl = hybrid_envelope.get("classical", {})
            pub_hex = cl.get("pubkey", "")
            sig_b64 = cl.get("signature", "")
            if not pub_hex or not sig_b64:
                return False
            if expected_ed25519_pub is not None and not hmac.compare_digest(pub_hex, expected_ed25519_pub):
                return False
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            sig = base64.urlsafe_b64decode(sig_b64 + "==")
            pub.verify(sig, message)

            # 2. Check the custom hash-chain format under its historical wire key.
            pq = hybrid_envelope.get("post_quantum", {})
            slh_sig = pq.get("signature", {})
            outer_root = pq.get("pubkey_root") or expected_pqc_root
            if not StatelessHashSignature.verify(message, slh_sig, expected_pubkey_root=outer_root):
                return False

            return True
        except Exception:
            return False


class GroverProofDualLedger:
    """Historical name for combined digests; no quantum work factor is established.

    The combined output is SHA-256 over two digest encodings. Combining hashes
    does not establish the old advertised quantum-security margin.
    """

    @staticmethod
    def compute_dual_hash(prev_hash: str, payload_str: str) -> dict:
        """Compute the existing digest format without asserting a security margin."""
        combined = (prev_hash + payload_str).encode("utf-8")
        h_sha384 = hashlib.sha384(combined).hexdigest()
        h_blake2b = hashlib.blake2b(combined, digest_size=64).hexdigest()
        composite = hashlib.sha256((h_sha384 + h_blake2b).encode()).hexdigest()

        return {
            "composite_hash": composite,
            "sha384": h_sha384,
            "blake2b_512": h_blake2b,
            "quantum_security_margin_bits": None,
            "security_evaluation": "not_established",
        }


def get_x25519_mlkem768_caddy_snippet() -> str:
    """Example TLS curve preferences; this does not prove deployed negotiation."""
    return """
# Candidate TLS preferences, including classical fallbacks.
# Check the actual Caddy build and negotiated connection separately.
tls {
    curves x25519mlkem768 x25519 secp256r1
    protocols tls1.3
}
"""


def run_pqc_benchmark() -> tuple[float, dict, bool]:
    """Benchmark hybrid composite signing, dual-hash ledger, verification speed, and tamper rejection."""
    signer = HybridCompositeSigner()
    sample_payload = b"VIOLET_PQC_AUTHENTICATED_COMMAND|scope:crates/engine|time:2026-10-18T20:00:00Z"

    t0 = time.time()
    hybrid_sig = signer.sign_hybrid(sample_payload)
    valid_authentic = HybridCompositeSigner.verify_hybrid(sample_payload, hybrid_sig)
    elapsed = time.time() - t0

    # Adversarial Tamper Tests (MUST all fail closed -> False)
    # 1. Tamper message by 1 bit
    tampered_msg = sample_payload[:-1] + bytes([sample_payload[-1] ^ 0x01])
    rejects_tampered_msg = not StatelessHashSignature.verify(
        tampered_msg, hybrid_sig["post_quantum"]["signature"]
    )
    # 2. Tamper one W-OTS+ hash chain element
    corrupted_slh = json.loads(json.dumps(hybrid_sig["post_quantum"]["signature"]))
    first_elem = bytes.fromhex(corrupted_slh["elements"][0])
    corrupted_slh["elements"][0] = (first_elem[:-1] + bytes([first_elem[-1] ^ 0x01])).hex()
    rejects_tampered_pqc_elem = not StatelessHashSignature.verify(sample_payload, corrupted_slh)

    # 3. Tamper pubkey_root
    corrupted_root = json.loads(json.dumps(hybrid_sig["post_quantum"]["signature"]))
    corrupted_root["pubkey_root"] = "0" * 96
    rejects_tampered_root = not StatelessHashSignature.verify(sample_payload, corrupted_root)

    dual_hashes = GroverProofDualLedger.compute_dual_hash(
        prev_hash="0" * 64,
        payload_str=sample_payload.decode(),
    )
    hybrid_sig["tamper_tests"] = {
        "authentic_composite_verifies": valid_authentic,
        "rejects_tampered_message": rejects_tampered_msg,
        "rejects_tampered_pqc_element": rejects_tampered_pqc_elem,
        "rejects_tampered_pubkey_root": rejects_tampered_root,
        "dual_ledger_composite": dual_hashes["composite_hash"],
    }

    is_valid = (
        valid_authentic
        and rejects_tampered_msg
        and rejects_tampered_pqc_elem
        and rejects_tampered_root
    )
    return elapsed, hybrid_sig, is_valid


def main() -> int:
    elapsed, sig, valid = run_pqc_benchmark()
    t_tests = sig.get("tamper_tests", {})
    print("═" * 68)
    print("  VIOLET experimental signature and digest fixtures")
    print("═" * 68)
    print(f"  Hybrid Sign & Verify Latency : {elapsed*1000:.2f} ms")
    print(f"  Authentic Composite Verifies: {t_tests.get('authentic_composite_verifies')}")
    print(f"  Selected Fixture Checks     : {valid}")
    print(f"  Tamper Test (1-bit Message)  : {'REJECTED (PASS)' if t_tests.get('rejects_tampered_message') else 'FAILED'}")
    print(f"  Tamper Test (1-bit Element)  : {'REJECTED (PASS)' if t_tests.get('rejects_tampered_pqc_element') else 'FAILED'}")
    print(f"  Tamper Test (Root Mismatch)  : {'REJECTED (PASS)' if t_tests.get('rejects_tampered_pubkey_root') else 'FAILED'}")
    print("  Quantum Security Margin      : NOT ESTABLISHED")
    print("  FIPS Conformance             : NOT ESTABLISHED")
    print("  Deployed TLS Negotiation     : NOT EVALUATED")
    print("═" * 68)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
