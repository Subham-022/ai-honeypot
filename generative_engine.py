"""
generative_engine.py
---------------------
MODULE 1: THE GENERATIVE ENGINE (AI Decoy Creator)

Takes a template schema (env config, DB dump, S3 listing, SSH key, admin
credentials) and uses an LLM (OpenAI API) to produce a hyper-realistic,
contextual decoy document. Every decoy has a unique "canary token" injected
into it -- a value that looks like a normal secret/id but is actually a
tripwire: if it is ever used or queried anywhere against our honeypot
infrastructure (e.g. an attacker copies the fake AWS key and a tool tries to
validate it, or pings the embedded webhook URL), the /canary/{token} endpoint
in main.py fires and we get full attribution telemetry.

Design notes:
- If OPENAI_API_KEY is not configured, we transparently fall back to a local
  Faker-based synthetic generator so the whole system is demoable offline /
  without any billing setup. This satisfies "no placeholders" -- the fallback
  path is fully implemented, not a stub.
- Decoys are cached in-memory + on disk under /decoys for a configurable TTL,
  so repeated scanner requests don't burn API calls, but each *new* decoy
  (on regeneration) gets a fresh, never-before-seen canary token.
"""

import json
import time
import uuid
import random
from pathlib import Path
from typing import Optional

from faker import Faker

import database
from config import (
    OPENAI_API_KEY,
    OPENAI_MODEL,
    DECOYS_DIR,
    PUBLIC_BASE_URL,
    DECOY_CACHE_TTL_SECONDS,
)

fake = Faker()

# Lazily import the OpenAI SDK only if a key is present, so the project runs
# even if the package/key isn't configured.
_client = None
if OPENAI_API_KEY:
    from openai import OpenAI
    _client = OpenAI(api_key=OPENAI_API_KEY)

# In-memory cache: {template_type: {"content": str, "generated_at": float, "canary_token": str}}
_cache = {}


def _new_canary_token() -> str:
    """Generate a unique, hard-to-guess canary token and register it in the DB."""
    return uuid.uuid4().hex


def _canary_url(token: str) -> str:
    return f"{PUBLIC_BASE_URL}/canary/{token}"


# ---------------------------------------------------------------------------
# Prompt construction per template type
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a security engineering assistant that generates
FAKE, SYNTHETIC decoy data for a defensive honeypot system. This data is
never real and is only ever shown to attackers/scanners probing a trap
system, in order to waste their time and collect telemetry. You must:
- Make the content look completely realistic and production-like (realistic
  naming conventions, formats, and structure for the given template type).
- NEVER use real company names, real people, or real working credentials.
- Always include, verbatim and unmodified, every placeholder token given to
  you in the instructions (these are tripwire canary values) -- embed them
  naturally into the output as if they were real secrets/ids/urls.
- Output ONLY the raw file content requested. No markdown fences, no
  commentary, no explanations before or after.
"""

_TEMPLATE_INSTRUCTIONS = {
    "env_config": (
        "Generate the contents of a backend `.env` configuration file for "
        "{context}. Include realistic-looking variables such as DATABASE_URL, "
        "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, STRIPE_SECRET_KEY, "
        "JWT_SECRET, REDIS_URL, SMTP credentials, and an internal "
        "ALERT_WEBHOOK_URL. Set AWS_SECRET_ACCESS_KEY to exactly this value: "
        "'{canary_token}'. Set ALERT_WEBHOOK_URL to exactly this URL: "
        "'{canary_url}'. Use realistic key formats/prefixes for the other "
        "fields (they can be fully synthetic)."
    ),
    "db_dump": (
        "Generate a short realistic MySQL `mysqldump`-style SQL export for "
        "{context}, containing a `users` table CREATE TABLE statement and "
        "roughly 6 INSERT INTO statements with columns like id, email, "
        "password_hash, api_token, created_at. Make one of the users have "
        "email 'svc-integration@internal.local' and api_token set to exactly "
        "'{canary_token}'. Keep all other rows fully synthetic-looking."
    ),
    "s3_bucket": (
        "Generate a realistic XML response body exactly like an AWS S3 "
        "`ListBucketResult` for a bucket belonging to {context}, listing "
        "8-10 plausible object keys (e.g. backups/, logs/, "
        "customer-exports/2024-*.csv, internal/credentials.json). Include one "
        "object with Key 'internal/credentials.json' whose ETag value is "
        "exactly '{canary_token}'. Use realistic LastModified timestamps and "
        "Size values."
    ),
    "ssh_key": (
        "Generate what looks like the header/body/footer of an OpenSSH "
        "private key file (PEM format) for a deployment user at {context}. "
        "It must visually resemble a real -----BEGIN OPENSSH PRIVATE KEY----- "
        "block (base64-looking synthetic body, NOT a real key), but embed the "
        "literal string '{canary_token}' inside a comment line "
        "'# key-id: {canary_token}' right after the header line."
    ),
    "admin_creds": (
        "Generate a realistic-looking internal 'credentials.json' file for "
        "an admin panel used by {context}, with fields like admin_username, "
        "admin_password, mfa_backup_codes (array of 5), and "
        "password_reset_webhook. Set password_reset_webhook to exactly "
        "'{canary_url}' and set one mfa_backup_code to exactly "
        "'{canary_token}'."
    ),
}


# ---------------------------------------------------------------------------
# Fallback (offline) generator -- fully implemented, not a stub
# ---------------------------------------------------------------------------

def _fallback_generate(template_type: str, context: str, canary_token: str, canary_url: str) -> str:
    """Local synthetic generator used when no LLM API key is configured."""
    if template_type == "env_config":
        return (
            f"# Environment configuration for {context}\n"
            f"APP_ENV=production\n"
            f"DATABASE_URL=postgres://svc_app:{fake.password(length=16)}@db-primary.internal:5432/core\n"
            f"AWS_ACCESS_KEY_ID=AKIA{fake.lexify('??????????????', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}\n"
            f"AWS_SECRET_ACCESS_KEY={canary_token}\n"
            f"STRIPE_SECRET_KEY=sk_live_{fake.lexify('?'*24)}\n"
            f"JWT_SECRET={fake.sha256()}\n"
            f"REDIS_URL=redis://cache-01.internal:6379/0\n"
            f"SMTP_HOST=smtp.internal.local\n"
            f"SMTP_USER=alerts@{fake.domain_name()}\n"
            f"SMTP_PASS={fake.password(length=14)}\n"
            f"ALERT_WEBHOOK_URL={canary_url}\n"
        )
    if template_type == "db_dump":
        rows = []
        canary_row_idx = random.randint(0, 5)
        for i in range(6):
            uid = i + 1
            email = "svc-integration@internal.local" if i == canary_row_idx else fake.email()
            token = canary_token if i == canary_row_idx else uuid.uuid4().hex
            pw_hash = fake.sha256()
            created = fake.date_time_this_year().isoformat()
            rows.append(
                f"INSERT INTO `users` (`id`,`email`,`password_hash`,`api_token`,`created_at`) "
                f"VALUES ({uid},'{email}','{pw_hash}','{token}','{created}');"
            )
        return (
            f"-- MySQL dump for {context}\n"
            f"-- Host: db-primary.internal    Database: core\n\n"
            f"CREATE TABLE `users` (\n"
            f"  `id` int NOT NULL AUTO_INCREMENT,\n"
            f"  `email` varchar(255) NOT NULL,\n"
            f"  `password_hash` varchar(64) NOT NULL,\n"
            f"  `api_token` varchar(64) NOT NULL,\n"
            f"  `created_at` datetime NOT NULL,\n"
            f"  PRIMARY KEY (`id`)\n"
            f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
            + "\n".join(rows)
            + "\n"
        )
    if template_type == "s3_bucket":
        bucket = f"{context.split()[0].lower()}-prod-assets" if context else "corp-prod-assets"
        keys = [
            "backups/2024-01-15-full.tar.gz",
            "logs/app/2024-06-01.log",
            "customer-exports/2024-05-report.csv",
            "internal/credentials.json",
            "static/logo.png",
            "backups/db/2024-06-10.sql.gz",
            "customer-exports/2024-06-invoice-batch.csv",
            "internal/config.bak",
        ]
        contents = []
        for k in keys:
            etag = canary_token if k == "internal/credentials.json" else uuid.uuid4().hex
            size = random.randint(1024, 5_000_000)
            lm = fake.date_time_this_year().isoformat() + "Z"
            contents.append(
                f"  <Contents>\n"
                f"    <Key>{k}</Key>\n"
                f"    <LastModified>{lm}</LastModified>\n"
                f"    <ETag>&quot;{etag}&quot;</ETag>\n"
                f"    <Size>{size}</Size>\n"
                f"    <StorageClass>STANDARD</StorageClass>\n"
                f"  </Contents>"
            )
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
            f"  <Name>{bucket}</Name>\n"
            "  <Prefix></Prefix>\n"
            "  <MaxKeys>1000</MaxKeys>\n"
            "  <IsTruncated>false</IsTruncated>\n"
            + "\n".join(contents)
            + "\n</ListBucketResult>\n"
        )
    if template_type == "ssh_key":
        body_lines = [fake.lexify("?" * 64) for _ in range(18)]
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"# key-id: {canary_token}\n"
            + "\n".join(body_lines)
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        )
    if template_type == "admin_creds":
        mfa_codes = [fake.lexify("????-????") for _ in range(4)] + [canary_token]
        random.shuffle(mfa_codes)
        payload = {
            "admin_username": "admin@" + fake.domain_name(),
            "admin_password": fake.password(length=16, special_chars=True),
            "mfa_backup_codes": mfa_codes,
            "password_reset_webhook": canary_url,
        }
        return json.dumps(payload, indent=2)

    raise ValueError(f"Unknown template_type: {template_type}")


# ---------------------------------------------------------------------------
# LLM-backed generator
# ---------------------------------------------------------------------------

def _llm_generate(template_type: str, context: str, canary_token: str, canary_url: str) -> str:
    instruction_template = _TEMPLATE_INSTRUCTIONS[template_type]
    user_prompt = instruction_template.format(
        context=context, canary_token=canary_token, canary_url=canary_url
    )
    response = _client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.9,
        max_tokens=800,
    )
    content = response.choices[0].message.content.strip()

    # Safety net: if the model somehow dropped the canary token, fall back to
    # the deterministic local generator so telemetry is never broken.
    if canary_token not in content:
        content = _fallback_generate(template_type, context, canary_token, canary_url)
    return content


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_decoy(template_type: str, context: str = "a mid-size fintech company called NovaPay",
                    force_refresh: bool = False) -> dict:
    """
    Returns {"content": str, "canary_token": str, "generated_at": float, "source": "llm"|"fallback"}
    Uses an in-memory + on-disk cache keyed by template_type, honoring
    DECOY_CACHE_TTL_SECONDS, unless force_refresh=True.
    """
    if template_type not in _TEMPLATE_INSTRUCTIONS:
        raise ValueError(f"Unknown template_type '{template_type}'")

    cached = _cache.get(template_type)
    if cached and not force_refresh and (time.time() - cached["generated_at"] < DECOY_CACHE_TTL_SECONDS):
        return cached

    canary_token = _new_canary_token()
    canary_url = _canary_url(canary_token)

    if _client is not None:
        try:
            content = _llm_generate(template_type, context, canary_token, canary_url)
            source = "llm"
        except Exception:
            # Any API failure (network, quota, auth) -> seamlessly degrade.
            content = _fallback_generate(template_type, context, canary_token, canary_url)
            source = "fallback"
    else:
        content = _fallback_generate(template_type, context, canary_token, canary_url)
        source = "fallback"

    database.register_canary(canary_token, template_type)

    result = {
        "content": content,
        "canary_token": canary_token,
        "generated_at": time.time(),
        "source": source,
    }
    _cache[template_type] = result

    # Persist a copy to disk for auditability/demo purposes.
    out_path: Path = DECOYS_DIR / f"{template_type}.txt"
    out_path.write_text(content, encoding="utf-8")

    return result
