"""test_citadel_briefing.py — Unit tests for Citadel Morning Briefing Daemon."""
from __future__ import annotations

import json
import pathlib
from citadel_briefing import generate_briefing


def test_generate_briefing_outputs(tmp_path: pathlib.Path):
    md_file = tmp_path / "morning_briefing.md"
    json_file = tmp_path / "morning_briefing.json"

    res = generate_briefing(output_md=md_file, output_json=json_file)

    assert md_file.exists()
    assert json_file.exists()

    data = res["json"]

    # Verify JSON structure
    assert data["executive_status"] == "DEFENSES_NOMINAL"
    assert "counter_economics" in data
    assert "perimeter" in data
    assert data["perimeter"]["cowrie_honeypot_active"] is True

    # Verify Markdown contents
    md_content = md_file.read_text(encoding="utf-8")
    assert "# Citadel Defense Morning Briefing" in md_content
    assert "Counter-Economic Reversal Breakdown" in md_content
    assert "Executive Summary" in md_content
    assert "Basescan Bait Explorer" in md_content
