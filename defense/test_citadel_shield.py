"""test_citadel_shield.py — Unit tests for Citadel Shield ASGI middleware."""
from __future__ import annotations

import json
import pytest
from citadel_shield.middleware import CitadelShieldMiddleware


class MockASGIApp:
    def __init__(self, response_body: bytes = b"OK", status: int = 200):
        self.response_body = response_body
        self.status = status
        self.called = False

    async def __call__(self, scope: dict, receive: callable, send: callable) -> None:
        self.called = True
        await send({
            "type": "http.response.start",
            "status": self.status,
            "headers": [(b"content-type", b"text/plain")],
        })
        await send({
            "type": "http.response.body",
            "body": self.response_body,
        })


@pytest.mark.asyncio
async def test_passthrough_normal_request():
    """Verify normal application routes pass through untouched."""
    inner_app = MockASGIApp(b"Hello World", 200)
    middleware = CitadelShieldMiddleware(inner_app, enable_deception=True)

    sent_events = []
    async def mock_send(event):
        sent_events.append(event)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/users",
        "headers": [],
        "client": ("192.168.1.100", 54321),
    }

    await middleware(scope, None, mock_send)

    assert inner_app.called is True
    assert sent_events[0]["status"] == 200
    assert sent_events[1]["body"] == b"Hello World"


@pytest.mark.asyncio
async def test_non_http_scope_passthrough():
    """Verify websocket/lifespan scopes pass through directly."""
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(inner_app)

    sent_events = []
    async def mock_send(event):
        sent_events.append(event)

    scope = {"type": "websocket"}
    await middleware(scope, None, mock_send)
    assert inner_app.called is True


@pytest.mark.asyncio
async def test_env_lure_interception():
    """Verify /.env probes are intercepted and return realistic procedural lures."""
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(inner_app, enable_deception=True)

    sent_events = []
    async def mock_send(event):
        sent_events.append(event)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/.env",
        "headers": [(b"x-forwarded-for", b"203.0.113.42")],
        "client": ("127.0.0.1", 12345),
    }

    await middleware(scope, None, mock_send)

    # Inner app should NOT be called
    assert inner_app.called is False
    assert sent_events[0]["status"] == 200
    headers_dict = dict(sent_events[0]["headers"])
    assert headers_dict[b"server"] == b"Citadel-Shield/3.0"
    assert headers_dict[b"x-citadel-defense"] == b"ACTIVE"

    body = sent_events[1]["body"].decode("utf-8")
    assert "BASE_PRIVATE_KEY" in body or "TREASURY_ROUTER_ADDRESS" in body


@pytest.mark.asyncio
async def test_metadata_probe_interception():
    """Verify cloud metadata probing returns spoofed AWS metadata."""
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(inner_app, enable_deception=True)

    sent_events = []
    async def mock_send(event):
        sent_events.append(event)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/latest/meta-data",
        "headers": [],
        "client": ("198.51.100.99", 54321),
    }

    await middleware(scope, None, mock_send)

    assert inner_app.called is False
    assert sent_events[0]["status"] == 200
    body = sent_events[1]["body"].decode("utf-8")
    assert "ami-id" in body or "instance-id" in body


@pytest.mark.asyncio
async def test_pow_gate_challenge_issuance():
    """Verify rate-pressured routes return HTTP 428 PoW challenges when enabled."""
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(
        inner_app, enable_deception=True, enable_pow_gate=True, pow_difficulty=4
    )

    sent_events = []
    async def mock_send(event):
        sent_events.append(event)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/heavy/compute",
        "headers": [],
        "client": ("198.51.100.99", 54321),
    }

    await middleware(scope, None, mock_send)

    assert inner_app.called is False
    assert sent_events[0]["status"] == 428
    body = json.loads(sent_events[1]["body"].decode("utf-8"))
    assert "challenge" in body
    assert body["challenge"]["difficulty"] == 4
