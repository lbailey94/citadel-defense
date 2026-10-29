"""citadel_shield — Negative Expected Value (-EV) Active Cyberdefense Framework."""
from __future__ import annotations

import sys
from pathlib import Path

# Add defense directory to sys.path
DEFENSE_DIR = Path(__file__).resolve().parent.parent / "defense"
if str(DEFENSE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENSE_DIR))

try:
    from canary_manager import CanaryManager
    from violet_bounty_ledger import BountyLedger
    from violet_digital_twin import ProceduralDigitalTwin
    from violet_gas_trap import GasTrapHoneypot
    from violet_live_sweeper import LiveGasSweeper
    from violet_pow_gate import PoWGate
except ImportError:
    pass

from citadel_shield.middleware import CitadelShieldMiddleware

__version__ = "3.0.0"
__all__ = [
    "CitadelShieldMiddleware",
    "PoWGate",
    "ProceduralDigitalTwin",
    "CanaryManager",
    "BountyLedger",
    "GasTrapHoneypot",
    "LiveGasSweeper",
]
