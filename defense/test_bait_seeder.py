"""test_bait_seeder.py — Tests for Passive Bait Seeding & Scraper Attraction Engine."""
from __future__ import annotations

import pathlib
from citadel_bait_seeder import (
    generate_staging_env,
    generate_docker_compose,
    export_seeding_kit,
    get_live_bait_info,
)


def test_generate_staging_env():
    addr = "0xb7902d7F63E3B9D25Cd631cB1be27b8904c84EE0"
    key = "f8c94d1136c714e7725fe6c8aeeeafb70cc835681e7f26f1574b81071e955fd9"

    env_content = generate_staging_env(addr, key)
    assert f"BASE_OPERATOR_ADDRESS={addr}" in env_content
    assert f"BASE_PRIVATE_KEY={key}" in env_content
    assert "OPENAI_API_KEY=wm1_sk_live_staging_" in env_content
    assert "BASE_CHAIN_ID=8453" in env_content
    assert "https://mcp.whitemagic.dev" in env_content


def test_generate_docker_compose():
    compose = generate_docker_compose()
    assert "services:" in compose
    assert "app-worker:" in compose
    assert "./staging.env" in compose


def test_export_seeding_kit(tmp_path: pathlib.Path):
    res = export_seeding_kit(tmp_path)
    assert res["staging_env"].exists()
    assert res["docker_compose"].exists()
    assert res["paste_snippet"].exists()

    env_data = res["staging_env"].read_text(encoding="utf-8")
    assert "BASE_OPERATOR_ADDRESS" in env_data

    paste_data = res["paste_snippet"].read_text(encoding="utf-8")
    assert "export const CONFIG" in paste_data
    assert "8453" in paste_data
