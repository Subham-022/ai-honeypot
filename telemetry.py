"""
telemetry.py
------------
MODULE 3: THE TRIPWIRE & TELEMETRY LOGGER

Provides a reusable `log_decoy_hit()` function called from every honeypot
route in main.py, plus a starlette Middleware class that logs metadata for
*every* request (useful to also catch generic scanner noise even on paths
that aren't explicit decoys, e.g. `/wp-admin`, `/.git/config`, etc.).

Captured fields: attacker IP, User-Agent, timestamp (via DB insert), the
requested decoy path, query params, full headers, and the request payload
(body for POST/PUT, or query string for GET), plus which decoy_type was hit
and the canary_token if one was present in the request.
"""

import json
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

import database

# Paths that are considered "noise" scanner probes we still want to log,
# but with lower severity than a direct decoy hit.
KNOWN_SCANNER_PROBES = {
    "/.env", "/.git/config", "/wp-admin", "/wp-login.php",
    "/.aws/credentials", "/phpmyadmin", "/.ssh/id_rsa",
    "/actuator/env", "/config.json",
}


def _client_ip(request: Request) -> str:
    """Best-effort real client IP, honoring X-Forwarded-For if behind a proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def log_decoy_hit(
    request: Request,
    decoy_type: str,
    canary_token: str = None,
    severity: str = "high",
    extra_payload: str = None,
) -> int:
    """
    Call this from within a honeypot route handler right when a decoy is
    accessed. Captures full request context into the alerts table.
    Returns the inserted alert row id.
    """
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    method = request.method
    path = request.url.path
    query = str(request.query_params)
    headers = json.dumps(dict(request.headers))

    if extra_payload is not None:
        payload = extra_payload
    else:
        try:
            body_bytes = await request.body()
            payload = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        except Exception:
            payload = ""

    alert_id = database.insert_alert(
        source_ip=ip,
        user_agent=ua,
        method=method,
        path=path,
        query_params=query,
        headers=headers,
        payload=payload,
        decoy_type=decoy_type,
        canary_token=canary_token,
        severity=severity,
    )
    return alert_id


class ScannerNoiseMiddleware(BaseHTTPMiddleware):
    """
    Passive middleware that logs low-severity "noise" whenever a request hits
    a well-known scanner probe path that isn't one of our explicit decoy
    routes (e.g. automated bots requesting /.env or /wp-login.php). This adds
    breadth to telemetry beyond the curated honeypot endpoints.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        response: Response = await call_next(request)

        if path in KNOWN_SCANNER_PROBES and response.status_code == 404:
            ip = _client_ip(request)
            ua = request.headers.get("user-agent", "")
            database.insert_alert(
                source_ip=ip,
                user_agent=ua,
                method=request.method,
                path=path,
                query_params=str(request.query_params),
                headers=json.dumps(dict(request.headers)),
                payload="",
                decoy_type="scanner_probe",
                canary_token=None,
                severity="low",
            )
        return response
