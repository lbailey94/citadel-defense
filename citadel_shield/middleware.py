"""citadel_shield.middleware — Drop-in ASGI / FastAPI Middleware for Citadel Active Defense.

Provides optional decoys and client puzzle admission for Python ASGI applications:
  * Intercepts hostile probe paths (/.env, /wp-admin, /latest/meta-data, /api/v1/namespaces)
  * Serves realistic procedural digital twin decoys with watermarked canaries
  * Requires verified, single-use PoW solutions on /api/heavy routes when enabled

Usage:
    from fastapi import FastAPI
    from citadel_shield.middleware import CitadelShieldMiddleware

    app = FastAPI()
    app.add_middleware(CitadelShieldMiddleware, enable_pow_gate=True, pow_difficulty=4)
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import sys
from typing import Callable

# Ensure local imports resolve
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "defense"))

try:
    import violet_digital_twin as vdt
except ImportError:
    vdt = None

from defense import violet_pow_gate as vpg

logger = logging.getLogger("citadel_shield")

DEFAULT_DECOY_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/latest/meta-data",
    "/computeMetadata/v1", "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/api/v1/namespaces", "/v1.24/containers/json", "/aws/credentials"
}
MAX_POW_HEADER_BYTES = 4096


class CitadelShieldMiddleware:
    """Drop-in ASGI middleware providing automated deception and client puzzles."""

    def __init__(
        self,
        app: Callable,
        enable_deception: bool = True,
        enable_pow_gate: bool = False,
        pow_difficulty: int = 4,
        decoy_paths: set[str] | None = None,
        state_dir: pathlib.Path | None = None,
        protected_prefixes: tuple[str, ...] = ("/api/heavy",),
        pow_gate: vpg.PoWGate | None = None,
    ):
        self.app = app
        self.enable_deception = enable_deception
        self.enable_pow_gate = enable_pow_gate
        self.pow_difficulty = pow_difficulty
        if (not isinstance(protected_prefixes, tuple) or not protected_prefixes or
                any(not isinstance(prefix, str) or not prefix.startswith("/") or
                    "?" in prefix or "#" in prefix for prefix in protected_prefixes)):
            raise ValueError("protected_prefixes must be a nonempty tuple of absolute path prefixes")
        self.protected_prefixes = tuple(prefix.rstrip("/") or "/" for prefix in protected_prefixes)
        self.admission_counts: dict[str, int] = {}
        self.decoy_paths = decoy_paths or DEFAULT_DECOY_PATHS
        self.state_dir = state_dir or pathlib.Path(os.environ.get("VIOLET_STATE_DIR", "/tmp/citadel"))

        self.twin = None
        self.pow_gate = None
        if self.enable_deception:
            try:
                self.twin = vdt.ProceduralDigitalTwin()
            except Exception as e:
                logger.warning("Could not initialize ProceduralDigitalTwin: %s", e)

        if self.enable_pow_gate:
            if (type(pow_difficulty) is not int or
                    not vpg.MIN_POW_DIFFICULTY <= pow_difficulty <= vpg.MAX_POW_DIFFICULTY):
                raise ValueError("pow_difficulty must be an integer between 1 and 8")
            # An explicitly enabled protection must not silently become passthrough.
            self.pow_gate = pow_gate if pow_gate is not None else vpg.PoWGate()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # 1. Inspect for decoy paths
        if self.enable_deception and self.twin and (path in self.decoy_paths or path.startswith("/.env")):
            # Resolve client IP
            client_ip = scope.get("client", ("127.0.0.1", 0))[0]

            if path.startswith("/.env"):
                body = self.twin.get_env_file(src_ip=client_ip).encode("utf-8")
                await self._send_response(send, 200, b"text/plain; charset=utf-8", body)
                return

            if "meta-data" in path or "computeMetadata" in path:
                meta = self.twin.get_aws_metadata(path, src_ip=client_ip)
                body = (json.dumps(meta) if isinstance(meta, dict) else str(meta)).encode("utf-8")
                await self._send_response(send, 200, b"application/json", body)
                return

        # 2. Explicitly enabled PoW admission on the protected route prefix.
        if self.enable_pow_gate and any(prefix == "/" or path == prefix or path.startswith(prefix + "/")
                                        for prefix in self.protected_prefixes):
            client = scope.get("client")
            if not client or not isinstance(client[0], str) or self.pow_gate is None:
                await self._send_response(send, 503, b"application/json", b'{"error":"PoW gate unavailable"}')
                return
            # Use the ASGI transport peer. Forwarded headers require a trusted proxy
            # configuration outside this middleware; client-controlled XFF is not identity.
            client_ip = client[0]
            submitted = [value for name, value in scope.get("headers", [])
                         if name.lower() == b"x-citadel-pow-solution"]
            verified, reason = False, "missing_solution"
            if len(submitted) == 1:
                if len(submitted[0]) > MAX_POW_HEADER_BYTES:
                    reason = "solution_too_large"
                else:
                    try:
                        solution = json.loads(submitted[0].decode("utf-8"))
                        if not isinstance(solution, dict) or set(solution) != {"challenge", "nonce"}:
                            raise ValueError("expected challenge and nonce")
                        challenge, nonce = solution["challenge"], solution["nonce"]
                        if not isinstance(challenge, dict) or type(challenge.get("difficulty")) is not int:
                            raise ValueError("invalid challenge")
                        if challenge["difficulty"] < self.pow_difficulty:
                            reason = "difficulty_below_policy"
                        else:
                            verified, reason = self.pow_gate.verify_solution(
                                challenge, nonce, client_ip, check_replay=True,
                            )
                    except (ValueError, TypeError, UnicodeError, RecursionError):
                        reason = "malformed_solution"
            elif submitted:
                reason = "duplicate_solution_header"
            self.admission_counts[reason] = self.admission_counts.get(reason, 0) + 1
            if not verified:
                challenge = self.pow_gate.generate_challenge(client_ip=client_ip, difficulty=self.pow_difficulty)
                body = json.dumps({
                    "error": "PoW challenge required",
                    "reason": reason,
                    "challenge": challenge,
                    "header_required": "X-Citadel-PoW-Solution",
                    "solution_format": {"challenge": "the issued challenge object", "nonce": "solver nonce"},
                }).encode("utf-8")
                await self._send_response(send, 428, b"application/json", body)
                return

        # 3. Allow legitimate request to proceed
        await self.app(scope, receive, send)

    async def _send_response(self, send: Callable, status: int, content_type: bytes, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"server", b"Citadel-Shield/3.0"),
                (b"x-citadel-defense", b"ACTIVE"),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
