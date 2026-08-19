# 🛡️ AI-Powered Deception & Honeypot System (MVP)

A working prototype for: *"Design a generative AI system that dynamically
creates realistic decoy assets, fake credentials, and honeypot environments
to lure and analyze attacker behavior."*

Generative AI (OpenAI API, with an automatic offline fallback) creates
realistic fake secrets/config files/DB dumps/S3 listings, each embedding a
unique **canary token**. A FastAPI server hosts them at classic
"juicy misconfiguration" URLs. Every touch is logged with full attacker
telemetry, and a live Streamlit dashboard visualizes it all in real time.

---

## 1. Directory Structure

```
ai-honeypot-mvp/
├── backend/
│   ├── main.py                # MODULE 2: FastAPI bait/trap server + canary routes + admin/dashboard API
│   ├── generative_engine.py   # MODULE 1: AI decoy generator (LLM + offline fallback), canary token injection
│   ├── telemetry.py           # MODULE 3: Tripwire logger + scanner-noise middleware
│   ├── database.py            # SQLite persistence layer (alerts + canaries tables)
│   ├── config.py              # Centralized env-based configuration
│   └── models.py              # Pydantic request/response schemas
├── dashboard/
│   └── app.py                 # MODULE 4: Streamlit SOC dashboard (live alerts, charts, IP/decoy breakdown)
├── decoys/                    # Auto-populated: latest generated decoy content per template (for auditing)
├── data/
│   └── honeypot.db            # Auto-created SQLite database (alerts + canaries)
├── requirements.txt
├── .env.example
└── README.md
```

---

## 2. Install Dependencies

Requires Python 3.10+.

```bash
cd ai-honeypot-mvp
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## 3. Configure API Keys

```bash
cp .env.example .env
```

Edit `.env`:

```ini
OPENAI_API_KEY=sk-...your-key...   # optional — leave blank to run fully offline
OPENAI_MODEL=gpt-4o-mini
PUBLIC_BASE_URL=http://localhost:8000
HONEYPOT_ADMIN_TOKEN=demo-admin-token-change-me
```

> **No API key? No problem.** If `OPENAI_API_KEY` is blank, `generative_engine.py`
> automatically uses its built-in Faker-based synthetic generator, so the
> entire system — decoys, canary tokens, telemetry, dashboard — still works
> end-to-end for your demo. Adding a real key just makes the decoy *content*
> more linguistically realistic (LLM-written), the tripwire mechanics are
> identical either way.

## 4. Run the Application Locally

**Terminal 1 — start the honeypot backend:**

```bash
cd ai-honeypot-mvp/backend
uvicorn main:app --reload --port 8000
```

On startup it pre-generates one decoy of each type. Visit
`http://localhost:8000/docs` for interactive Swagger docs of every route.

**Terminal 2 — start the SOC dashboard:**

```bash
cd ai-honeypot-mvp/dashboard
streamlit run app.py
```

Open the URL Streamlit prints (default `http://localhost:8501`). It auto-refreshes every 5 seconds.

---

## 5. Test It — Simulate an Attack

With the backend running, open a third terminal and run these to simulate
an attacker/scanner probing your fake infrastructure:

```bash
# 1. Attacker discovers what looks like an exposed backend config file
curl -s http://localhost:8000/api/v1/config

# 2. Attacker grabs what looks like a forgotten DB backup
curl -s http://localhost:8000/admin/backup.sql

# 3. Attacker enumerates a "misconfigured" public S3 bucket
curl -s http://localhost:8000/s3/novapay-prod-assets

# 4. ...and pulls the "sensitive" object inside it
curl -s http://localhost:8000/s3/novapay-prod-assets/internal/credentials.json

# 5. Attacker finds an exposed SSH deploy key
curl -s http://localhost:8000/.well-known/deploy_key

# 6. Attacker brute-forces the fake admin login (captured as payload)
curl -s -X POST http://localhost:8000/admin/login \
     -d "username=admin&password=P@ssw0rd123"

# 7. THE PAYOFF: simulate the attacker later trying to *reuse* a canary
#    token they scraped out of step 1's AWS_SECRET_ACCESS_KEY value.
#    Copy the AWS_SECRET_ACCESS_KEY value printed by step 1, then:
curl -s http://localhost:8000/canary/<paste-the-canary-token-here>
```

After running these, switch to the **Streamlit dashboard** — you'll see:
- Total alert count and unique IP count jump
- A bar chart of which decoy types were hit
- The critical-severity counter light up (DB dump, admin creds, SSH key, canary reuse are all `critical`)
- A live, sortable alert feed table with full request metadata
- The row for step 6 shows the attacker's submitted `username`/`password` in the `payload` column
- The row for step 7 (`decoy_type = canary_token_used`) is the strongest signal: proof a specific leaked secret was actually reused

You can also inspect raw JSON directly:

```bash
curl -s http://localhost:8000/api/stats | python3 -m json.tool
curl -s http://localhost:8000/api/alerts | python3 -m json.tool
```

To force-generate a brand-new decoy (new canary token) on demand:

```bash
curl -s -X POST http://localhost:8000/admin/regenerate/env_config \
     -H "Authorization: Bearer demo-admin-token-change-me"
```

---

## 6. How the Canary Token Mechanism Works (Module 1 → Module 3 loop)

1. `generative_engine.py` mints a random UUID (`canary_token`) and a matching
   `canary_url` (`{PUBLIC_BASE_URL}/canary/{token}`) *before* calling the LLM.
2. The LLM (or the offline fallback) is instructed to embed that **exact**
   token/URL naturally inside the generated secret (e.g. as an AWS secret
   key, a DB `api_token` column, an S3 `ETag`, an MFA backup code, or a
   webhook URL).
3. The token is registered in the `canaries` SQLite table.
4. If an attacker copies that fake secret and later tries to *use* it
   anywhere that resolves back to us (directly hitting the embedded webhook
   URL, or a validation tool pinging it), it hits `/canary/{token}`, which
   flips `triggered_count` in the DB and logs a `critical` severity alert —
   giving you attribution even for **offline/asynchronous** credential misuse,
   not just the initial scrape.

## 7. Extending This MVP

- Swap SQLite → Postgres by changing only `database.py`'s `get_connection()`.
- Add more decoy templates by adding an entry to `_TEMPLATE_INSTRUCTIONS` and
  `_fallback_generate()` in `generative_engine.py`.
- Add IP geolocation/enrichment in `telemetry.py` before insert.
- Add Slack/email alerting by calling out from `log_decoy_hit()` when
  `severity == "critical"`.
- Put the backend behind a real public URL (or `ngrok http 8000` for a demo)
  and set `PUBLIC_BASE_URL` accordingly so canary webhook URLs are actually
  reachable from the outside internet.
