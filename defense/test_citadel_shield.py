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


async def _pow_request(middleware, headers=(), client_ip="198.51.100.99"):
    events = []

    async def send(event):
        events.append(event)

    await middleware({
        "type": "http", "method": "GET", "path": "/api/heavy/compute",
        "headers": list(headers), "client": (client_ip, 54321),
    }, None, send)
    return events


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [b"bypass", b"{}", b"\xff", b"x" * 4097])
async def test_pow_header_is_not_authorization(value):
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(
        inner_app, enable_deception=False, enable_pow_gate=True, pow_difficulty=1,
    )
    events = await _pow_request(middleware, [(b"x-citadel-pow-solution", value)])
    assert not inner_app.called
    assert events[0]["status"] == 428


@pytest.mark.asyncio
async def test_pow_default_configuration_issues_a_valid_challenge():
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(inner_app, enable_deception=False, enable_pow_gate=True)
    events = await _pow_request(middleware)
    assert not inner_app.called
    assert events[0]["status"] == 428
    assert json.loads(events[1]["body"])["challenge"]["difficulty"] == 4


@pytest.mark.asyncio
async def test_pow_solution_is_verified_and_single_use():
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(
        inner_app, enable_deception=False, enable_pow_gate=True, pow_difficulty=1,
    )
    issued = await _pow_request(middleware)
    challenge = json.loads(issued[1]["body"])["challenge"]
    nonce, _, _ = middleware.pow_gate.solve(challenge)
    header = (b"x-citadel-pow-solution", json.dumps({"challenge": challenge, "nonce": nonce}).encode())
    accepted = await _pow_request(middleware, [header])
    assert inner_app.called
    assert accepted[0]["status"] == 200
    inner_app.called = False
    replay = await _pow_request(middleware, [header])
    assert not inner_app.called
    assert replay[0]["status"] == 428
    assert json.loads(replay[1]["body"])["reason"] == "challenge_already_consumed"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["ip", "signature", "expired", "difficulty", "work", "duplicate_header"])
async def test_pow_invalid_solution_never_calls_application(mutation):
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(
        inner_app, enable_deception=False, enable_pow_gate=True, pow_difficulty=2,
    )
    challenge = middleware.pow_gate.generate_challenge("198.51.100.99", difficulty=1 if mutation == "difficulty" else 2)
    if mutation == "expired":
        challenge = middleware.pow_gate.generate_challenge("198.51.100.99", difficulty=2, now=1)
    nonce, _, _ = middleware.pow_gate.solve(challenge)
    if mutation == "signature":
        challenge["sig"] = "0" * 64
    if mutation == "work":
        import hashlib
        nonce = "invalid"
        while hashlib.sha256(f"{challenge['salt']}:{nonce}".encode()).hexdigest().startswith(challenge["prefix"]):
            nonce += "x"
    header = (b"x-citadel-pow-solution", json.dumps({"challenge": challenge, "nonce": nonce}).encode())
    headers = [header, header] if mutation == "duplicate_header" else [header]
    events = await _pow_request(middleware, headers, client_ip="203.0.113.1" if mutation == "ip" else "198.51.100.99")
    assert not inner_app.called
    assert events[0]["status"] == 428


@pytest.mark.asyncio
async def test_pow_missing_transport_peer_is_unavailable():
    inner_app = MockASGIApp()
    middleware = CitadelShieldMiddleware(inner_app, enable_deception=False, enable_pow_gate=True)
    events = []

    async def send(event):
        events.append(event)

    await middleware({"type": "http", "path": "/api/heavy", "client": None}, None, send)
    assert not inner_app.called
    assert events[0]["status"] == 503


def test_pow_invalid_difficulty_fails_at_startup():
    with pytest.raises(ValueError, match="pow_difficulty"):
        CitadelShieldMiddleware(MockASGIApp(), enable_deception=False, enable_pow_gate=True, pow_difficulty=16)


def test_pow_initialization_failure_is_not_silently_disabled(monkeypatch):
    from citadel_shield import middleware as module

    def fail():
        raise RuntimeError("configured secret unavailable")

    monkeypatch.setattr(module.vpg, "PoWGate", fail)
    with pytest.raises(RuntimeError, match="configured secret unavailable"):
        CitadelShieldMiddleware(MockASGIApp(), enable_deception=False, enable_pow_gate=True)
