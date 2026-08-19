"""
main.py
-------
MODULE 2: THE BAIT / TRAP SERVER (Honeypot Endpoints)

FastAPI application that:
  - Serves AI-generated decoy assets at realistic-looking sensitive paths
    (/api/v1/config, /admin/backup.sql, mock S3 bucket listing, etc).
  - Wires up the tripwire telemetry logger (MODULE 3) on every decoy route.
  - Exposes the /canary/{token} tripwire that fires when a leaked/exfiltrated
    fake credential is later reused/tested against us.
  - Exposes a small JSON API consumed by the Streamlit SOC dashboard
    (MODULE 4) to pull live alerts/stats.
  - Exposes admin endpoints to force-regenerate decoys (protected by a
    simple bearer token for the demo).

Run with:  uvicorn main:app --reload --port 8000   (from the backend/ folder)
"""

from dotenv import load_dotenv
load_dotenv()  # must run before importing config so os.getenv sees .env values

import json
from fastapi import FastAPI, Request, Header, HTTPException, Response
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

import database
import generative_engine
import telemetry
from config import ADMIN_TOKEN
from models import AlertOut, StatsOut

app = FastAPI(
    title="AI Honeypot MVP",
    description="Generative-AI powered decoy assets & honeypot telemetry system",
    version="1.0.0",
)

# Allow the Streamlit dashboard (different port) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(telemetry.ScannerNoiseMiddleware)


@app.on_event("startup")
async def startup_event():
    # Pre-generate one of each decoy type so the honeypot has live bait
    # immediately on boot, without waiting for the first attacker request.
    for template_type in ["env_config", "db_dump", "s3_bucket", "ssh_key", "admin_creds"]:
        generative_engine.generate_decoy(template_type)


# ============================================================================
# HONEYPOT / BAIT ROUTES
# Each of these looks like a real, juicy misconfigured endpoint. Any request
# here is -- by definition -- suspicious, since no legitimate user/service
# should ever be calling these on a real system, so we log with high severity.
# ============================================================================

@app.get("/api/v1/config", response_class=PlainTextResponse)
async def bait_api_config(request: Request):
    """Mimics an accidentally-exposed backend .env / config endpoint."""
    decoy = generative_engine.generate_decoy("env_config")
    await telemetry.log_decoy_hit(
        request, decoy_type="env_config",
        canary_token=decoy["canary_token"], severity="high",
        extra_payload="",
    )
    return PlainTextResponse(content=decoy["content"], media_type="text/plain")


@app.get("/admin/backup.sql", response_class=PlainTextResponse)
async def bait_db_dump(request: Request):
    """Mimics a forgotten database backup left in a public web directory."""
    decoy = generative_engine.generate_decoy("db_dump")
    await telemetry.log_decoy_hit(
        request, decoy_type="db_dump",
        canary_token=decoy["canary_token"], severity="critical",
        extra_payload="",
    )
    return PlainTextResponse(content=decoy["content"], media_type="application/sql")


@app.get("/s3/{bucket_name}", response_class=Response)
async def bait_s3_bucket(request: Request, bucket_name: str):
    """Mimics a misconfigured public S3 bucket returning an object listing."""
    decoy = generative_engine.generate_decoy("s3_bucket", context=bucket_name)
    await telemetry.log_decoy_hit(
        request, decoy_type="s3_bucket",
        canary_token=decoy["canary_token"], severity="high",
        extra_payload="",
    )
    return Response(content=decoy["content"], media_type="application/xml")


@app.get("/s3/{bucket_name}/internal/credentials.json")
async def bait_s3_object(request: Request, bucket_name: str):
    """A specific 'sensitive object' inside the fake bucket -- pure bait."""
    decoy = generative_engine.generate_decoy("admin_creds", context=bucket_name)
    await telemetry.log_decoy_hit(
        request, decoy_type="admin_creds",
        canary_token=decoy["canary_token"], severity="critical",
        extra_payload="",
    )
    return JSONResponse(content=json.loads(decoy["content"]))


@app.get("/.well-known/deploy_key", response_class=PlainTextResponse)
async def bait_ssh_key(request: Request):
    """Mimics an accidentally committed/exposed SSH deploy key."""
    decoy = generative_engine.generate_decoy("ssh_key")
    await telemetry.log_decoy_hit(
        request, decoy_type="ssh_key",
        canary_token=decoy["canary_token"], severity="critical",
        extra_payload="",
    )
    return PlainTextResponse(content=decoy["content"])


@app.get("/admin/login", response_class=HTMLResponse)
async def bait_admin_login_page(request: Request):
    """A fake admin login page. GET just serves the form (low severity, could
    be a human misclick); the real signal is the POST below."""
    await telemetry.log_decoy_hit(
        request, decoy_type="admin_login_page", severity="low", extra_payload=""
    )
    html = """
    <html><head><title>NovaPay Internal Admin</title></head>
    <body style="font-family:sans-serif;max-width:340px;margin:80px auto;">
      <h2>Internal Admin Login</h2>
      <form method="POST" action="/admin/login">
        <input name="username" placeholder="Username" style="width:100%;padding:8px;margin-bottom:8px;"/><br/>
        <input name="password" type="password" placeholder="Password" style="width:100%;padding:8px;margin-bottom:8px;"/><br/>
        <button type="submit" style="width:100%;padding:8px;">Sign in</button>
      </form>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.post("/admin/login")
async def bait_admin_login_submit(request: Request):
    """
    Capturing a POST here is a very strong signal -- someone actively tried
    to authenticate (brute-force / credential-stuffing) against a page that
    doesn't exist on the real system. We log the submitted username/password
    as the payload (this is fake-system-only bait data, never a real account).
    """
    form = await request.form()
    payload = json.dumps(dict(form))
    await telemetry.log_decoy_hit(
        request, decoy_type="admin_login_attempt", severity="critical",
        extra_payload=payload,
    )
    # Always "fail" the login so the attacker keeps trying (more telemetry).
    return HTMLResponse(
        content="<html><body><p>Invalid credentials.</p></body></html>",
        status_code=401,
    )


# ============================================================================
# CANARY TRIPWIRE
# Fired when an exfiltrated fake credential/webhook is later used/tested
# anywhere against our infrastructure -- the strongest possible signal that
# a specific decoy was taken and acted upon by an attacker.
# ============================================================================

@app.api_route("/canary/{token}", methods=["GET", "POST", "PUT"])
async def canary_trigger(request: Request, token: str):
    known = database.trigger_canary(token)
    try:
        body_bytes = await request.body()
        payload = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    except Exception:
        payload = ""

    await telemetry.log_decoy_hit(
        request,
        decoy_type="canary_token_used",
        canary_token=token,
        severity="critical",
        extra_payload=payload,
    )
    # Respond generically -- never reveal to the attacker that this was a trap.
    return JSONResponse(content={"status": "ok"}, status_code=200)


# ============================================================================
# ADMIN / OPS API (used by the dashboard + manual demo control)
# ============================================================================

def _check_admin(authorization: str):
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/admin/regenerate/{template_type}")
async def regenerate_decoy(template_type: str, authorization: str = Header(default="")):
    """Force-regenerate a decoy (new canary token) - protected admin action."""
    _check_admin(authorization)
    decoy = generative_engine.generate_decoy(template_type, force_refresh=True)
    return {"template_type": template_type, "canary_token": decoy["canary_token"], "source": decoy["source"]}


@app.get("/api/alerts", response_model=list[AlertOut])
async def api_alerts(limit: int = 200):
    return database.get_recent_alerts(limit=limit)


@app.get("/api/stats", response_model=StatsOut)
async def api_stats():
    return database.get_alert_stats()


@app.get("/health")
async def health():
    return {"status": "up"}
