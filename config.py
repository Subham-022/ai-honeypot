"""
config.py
---------
Centralized configuration for the AI Honeypot MVP.
Reads settings from environment variables (loaded via python-dotenv in main.py).

No secrets are hard-coded here. If OPENAI_API_KEY is not set, the generative
engine automatically falls back to a local Faker-based template generator so
the whole system still runs end-to-end for a live demo without any API key.
"""

import os
from pathlib import Path

# --- Paths -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DECOYS_DIR = BASE_DIR / "decoys"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "honeypot.db"

DECOYS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# --- LLM / Generative engine -------------------------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# --- Server -------------------------------------------------------------------
HOST = os.getenv("HONEYPOT_HOST", "0.0.0.0")
PORT = int(os.getenv("HONEYPOT_PORT", "8000"))

# Public base URL the honeypot server is reachable at. This is embedded inside
# generated decoys as the "callback"/webhook URL for canary tokens, so that if
# an attacker exfiltrates a fake credential and later reuses/tests it, the
# request lands back on our /canary/{token} tripwire endpoint.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", f"http://localhost:{PORT}")

# Simple shared-secret to protect admin/regeneration endpoints in the demo.
ADMIN_TOKEN = os.getenv("HONEYPOT_ADMIN_TOKEN", "demo-admin-token-change-me")

# How many decoy variants to keep cached per template type.
DECOY_CACHE_TTL_SECONDS = int(os.getenv("DECOY_CACHE_TTL_SECONDS", "300"))
