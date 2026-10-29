"""citadel_bait_seeder.py — Passive Bait Seeding & Scraper Attraction Engine.

Generates realistic, attractive developer repository templates and configuration snippets
containing authenticated watermarked canaries and live multi-chain bait private keys
(Base EVM, Solana, and Tron).

Designed to be safely seeded into public test repositories, developer gists, and public pastes
to accelerate indexing by automated search crawlers, botnets, and mempool scrapers.

Lineage: Edgerunner Violet Deception & Counter-Economics.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import secrets
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Bait-Seeder] %(message)s")
logger = logging.getLogger("bait_seeder")

STATE_DIR = pathlib.Path(os.environ.get("VIOLET_STATE_DIR", "/var/lib/whitemagic-hosted/defense"))
BAIT_WALLET_FILE = STATE_DIR / "bait_wallet.json"
SOLANA_BAIT_FILE = STATE_DIR / "solana_bait_wallet.json"
TRON_BAIT_FILE = STATE_DIR / "tron_bait_wallet.json"

DEFAULT_BASE_ADDR = "0xb7902d7F63E3B9D25Cd631cB1be27b8904c84EE0"
DEFAULT_BASE_KEY = "f8c94d1136c714e7725fe6c8aeeeafb70cc835681e7f26f1574b81071e955fd9"

DEFAULT_SOLANA_ADDR = "ETMmb64Kdnsq2TbydsJh8AerMCaedGVXCT5tdNWpPnpy"
DEFAULT_SOLANA_KEY = "4j4xWdxhnC5K9V94eR7XmR8aXbYqZt9p2u1r5jx3aph11111111111111111"

DEFAULT_TRON_ADDR = "TCYkvTFvhTtSSeTkd1DZMaQ7jHvne4q28D"
DEFAULT_TRON_KEY = "3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266"


def get_live_bait_info() -> dict[str, dict[str, str]]:
    """Fetch active bait wallet address and private key across all chains."""
    info = {
        "base": {"address": DEFAULT_BASE_ADDR, "private_key": DEFAULT_BASE_KEY},
        "solana": {"address": DEFAULT_SOLANA_ADDR, "private_key": DEFAULT_SOLANA_KEY},
        "tron": {"address": DEFAULT_TRON_ADDR, "private_key": DEFAULT_TRON_KEY},
    }

    if BAIT_WALLET_FILE.exists():
        try:
            data = json.loads(BAIT_WALLET_FILE.read_text(encoding="utf-8"))
            info["base"]["address"] = data.get("address", DEFAULT_BASE_ADDR)
            info["base"]["private_key"] = data.get("private_key", DEFAULT_BASE_KEY)
        except Exception:
            pass

    if SOLANA_BAIT_FILE.exists():
        try:
            data = json.loads(SOLANA_BAIT_FILE.read_text(encoding="utf-8"))
            info["solana"]["address"] = data.get("address", DEFAULT_SOLANA_ADDR)
            info["solana"]["private_key"] = data.get("private_key", DEFAULT_SOLANA_KEY)
        except Exception:
            pass

    if TRON_BAIT_FILE.exists():
        try:
            data = json.loads(TRON_BAIT_FILE.read_text(encoding="utf-8"))
            info["tron"]["address"] = data.get("address", DEFAULT_TRON_ADDR)
            info["tron"]["private_key"] = data.get("private_key", DEFAULT_TRON_KEY)
        except Exception:
            pass

    return info


def generate_staging_env(
    base_addr: str = DEFAULT_BASE_ADDR,
    base_key: str = DEFAULT_BASE_KEY,
    sol_addr: str = DEFAULT_SOLANA_ADDR,
    sol_key: str = DEFAULT_SOLANA_KEY,
    tron_addr: str = DEFAULT_TRON_ADDR,
    tron_key: str = DEFAULT_TRON_KEY,
) -> str:
    """Generate a realistic developer staging .env lure spanning multiple chains."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    canary_id = secrets.token_hex(6)
    return f"""# staging deployment configuration
# synced from ci/cd: {ts} (runner-us-east-1a)
# WARNING: Staging secrets only — do not use in main production cluster

APP_ENV=staging
APP_DEBUG=true
APP_SECRET=sec_{secrets.token_urlsafe(24)}
APP_URL=https://staging.internal-cluster.net

# Database pool (read-write)
DB_CONNECTION=postgresql
DB_HOST=10.0.8.14
DB_PORT=5432
DB_DATABASE=app_staging_db
DB_USERNAME=staging_admin
DB_PASSWORD={secrets.token_urlsafe(16)}

# Cache & Message Queue
REDIS_URL=redis://:{secrets.token_urlsafe(12)}@10.0.8.22:6379/1

# AI Inference Cluster (Internal Staging Gateway)
OPENAI_API_KEY=wm1_sk_live_staging_{canary_id}_{secrets.token_hex(16)}
OPENAI_BASE_URL=https://mcp.whitemagic.dev/v1
ANTHROPIC_API_KEY=wm1_sk_ant_staging_{canary_id}_{secrets.token_hex(16)}
ANTHROPIC_BASE_URL=https://mcp.whitemagic.dev

# Cloud Storage & Bucket Access
AWS_ACCESS_KEY_ID=AKIA{secrets.token_hex(8).upper()}
AWS_SECRET_ACCESS_KEY={secrets.token_urlsafe(30)}
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET_NAME=corp-staging-vault-artifacts

# Multi-Chain Settlement Operators (Base L2 8453)
BASE_CHAIN_ID=8453
BASE_RPC_URL=https://base-rpc.publicnode.com
BASE_OPERATOR_ADDRESS={base_addr}
BASE_PRIVATE_KEY={base_key}
TREASURY_ROUTER_ADDRESS=0x213b6bB4fB073E86167c58DA6Cb6E9477557DaA8

# Solana Settlement Operator (SPL Vault)
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
SOLANA_OPERATOR_ADDRESS={sol_addr}
SOLANA_PRIVATE_KEY={sol_key}

# Tron TRC-20 Energy Vault (USDT Settlement)
TRON_RPC_URL=https://api.trongrid.io
TRON_OPERATOR_ADDRESS={tron_addr}
TRON_PRIVATE_KEY={tron_key}
"""


def generate_docker_compose() -> str:
    """Generate realistic docker-compose.staging.yml referencing the bait env."""
    return """version: '3.8'

services:
  app-worker:
    image: node:20-alpine
    container_name: staging-agent-worker
    restart: always
    env_file:
      - ./staging.env
    environment:
      - NODE_ENV=staging
      - PORT=3000
    ports:
      - "3000:3000"
    command: ["sh", "-c", "npm install && npm run start:worker"]

  postgres-staging:
    image: postgres:16-alpine
    container_name: staging-postgres
    restart: unless-stopped
    env_file:
      - ./staging.env
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
"""


def export_seeding_kit(export_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    """Export complete multi-chain seeding pack to designated directory."""
    export_dir.mkdir(parents=True, exist_ok=True)
    baits = get_live_bait_info()

    env_path = export_dir / "staging.env"
    env_path.write_text(
        generate_staging_env(
            base_addr=baits["base"]["address"],
            base_key=baits["base"]["private_key"],
            sol_addr=baits["solana"]["address"],
            sol_key=baits["solana"]["private_key"],
            tron_addr=baits["tron"]["address"],
            tron_key=baits["tron"]["private_key"],
        ),
        encoding="utf-8",
    )

    compose_path = export_dir / "docker-compose.staging.yml"
    compose_path.write_text(generate_docker_compose(), encoding="utf-8")

    paste_path = export_dir / "paste_snippet.txt"
    paste_content = f"""// Temporary multi-chain dev configuration dump ({time.strftime('%Y-%m-%d')})
// Pushing to public test harness for team review
export const MULTICHAIN_CONFIG = {{
  base: {{
    rpc: "https://base-rpc.publicnode.com",
    chainId: 8453,
    operatorAddress: "{baits['base']['address']}",
    operatorKey: "{baits['base']['private_key']}",
  }},
  solana: {{
    rpc: "https://api.mainnet-beta.solana.com",
    operatorAddress: "{baits['solana']['address']}",
    operatorKey: "{baits['solana']['private_key']}",
  }},
  tron: {{
    rpc: "https://api.trongrid.io",
    operatorAddress: "{baits['tron']['address']}",
    operatorKey: "{baits['tron']['private_key']}",
  }},
  apiGateway: "https://api.whitemagic.dev",
}};
"""
    paste_path.write_text(paste_content, encoding="utf-8")

    logger.info("Successfully exported multi-chain seeding kit to %s", export_dir)
    return {
        "staging_env": env_path,
        "docker_compose": compose_path,
        "paste_snippet": paste_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Citadel Multi-Chain Passive Bait Seeding & Lure Generator")
    parser.add_argument("--export-dir", type=pathlib.Path, default=pathlib.Path("./bait_seed_pack"), help="Directory to export lure assets")
    parser.add_argument("--stdout", action="store_true", help="Print sample .env lure to stdout")
    args = parser.parse_args()

    baits = get_live_bait_info()
    if args.stdout:
        print(
            generate_staging_env(
                base_addr=baits["base"]["address"],
                base_key=baits["base"]["private_key"],
                sol_addr=baits["solana"]["address"],
                sol_key=baits["solana"]["private_key"],
                tron_addr=baits["tron"]["address"],
                tron_key=baits["tron"]["private_key"],
            )
        )
        return 0

    res = export_seeding_kit(args.export_dir)
    print("═" * 70)
    print(" CITADEL MULTI-CHAIN BAIT SEEDING PACK EXPORTED")
    print("═" * 70)
    print(f"Base L2 Address     : {baits['base']['address']}")
    print(f"Solana Address      : {baits['solana']['address']}")
    print(f"Tron Address        : {baits['tron']['address']}")
    print(f"Staging Environment : {res['staging_env']}")
    print(f"Docker Compose Spec : {res['docker_compose']}")
    print(f"Public Paste Snippet: {res['paste_snippet']}")
    print("═" * 70)
    print("Ready for deployment to public test repos, developer gists, and pastebins.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
