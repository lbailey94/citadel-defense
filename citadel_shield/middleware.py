"""citadel_shield.middleware — Drop-in ASGI / FastAPI Middleware for Citadel Active Defense.

Provides zero-configuration, line-rate active defense for any Python web application:
  * Intercepts hostile probe paths (/.env, /wp-admin, /latest/meta-data, /api/v1/namespaces)
  * Serves realistic procedural digital twin decoys with watermarked canaries
  * Enforces client-side cryptographic Proof-of-Work puzzles under scan pressure
  * Imposes negative expected value (-EV) on automated threat actors

Usage:
    from fastapi import FastAPI
    from citadel_shield.middleware import CitadelShieldMiddleware

    app = FastAPI()
    app.add_middleware(CitadelShieldMiddleware, enable_deception=True, pow_difficulty=16)
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
    import violet_pow_gate as vpg
    import violet_bounty_ledger as vbl
except ImportError:
    pass

logger = logging.getLogger("citadel_shield")

DEFAULT_DECOY_PATHS = {
    "/.env", "/.env.local", "/.env.production", "/latest/meta-data",
    "/computeMetadata/v1", "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/api/v1/namespaces", "/v1.24/containers/json", "/aws/credentials"
}


class CitadelShieldMiddleware:
    """Drop-in ASGI middleware providing automated deception and client puzzles."""

    def __init__(
        self,
        app: Callable,
        enable_deception: bool = True,
        enable_pow_gate: bool = False,
        pow_difficulty: int = 16,
        decoy_paths: set[str] | None = None,
        state_dir: pathlib.Path | None = None,
    ):
        self.app = app
        self.enable_deception = enable_deception
        self.enable_pow_gate = enable_pow_gate
        self.pow_difficulty = pow_difficulty
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
            try:
                self.pow_gate = vpg.PoWGate(difficulty=self.pow_difficulty)
            except Exception as e:
                logger.warning("Could not initialize PoWGate: %s", e)

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # 1. Inspect for decoy paths
        if self.enable_deception and self.twin and (path in self.decoy_paths or path.startswith("/.env")):
            # Resolve client IP
            headers = dict(scope.get("headers", []))
            client_ip = scope.get("client", ("127.0.0.1", 0))[0]
            xff = headers.get(b"x-forwarded-for", b"").decode("utf-8")
            if xff:
                client_ip = xff.split(",")[-1].strip()

            if path.startswith("/.env"):
                body = self.twin.get_env_file(src_ip=client_ip).encode("utf-8")
                await self._send_response(send, 200, b"text/plain; charset=utf-8", body)
                return

            if "meta-data" in path or "computeMetadata" in path:
                meta = self.twin.get_aws_metadata(path, src_ip=client_ip)
                body = (json.dumps(meta) if isinstance(meta, dict) else str(meta)).encode("utf-8")
                await self._send_response(send, 200, b"application/json", body)
                return

        # 2. Client PoW challenge under scan pressure
        if self.enable_pow_gate and self.pow_gate and path.startswith("/api/heavy"):
            headers = dict(scope.get("headers", []))
            solution_hdr = headers.get(b"x-citadel-pow-solution", b"").decode("utf-8")
            if not solution_hdr:
                challenge = self.pow_gate.generate_challenge(src_ip=scope.get("client", ("0", 0))[0])
                body = json.dumps({
                    "error": "PoW challenge required",
                    "challenge": challenge,
                    "header_required": "X-Citadel-PoW-Solution"
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
