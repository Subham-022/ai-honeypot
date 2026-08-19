"""
dashboard/app.py
-----------------
MODULE 4: THE SOC DASHBOARD (Real-Time Analytics)

A Streamlit app that visualizes live security alerts coming from the
honeypot backend (main.py). Polls the backend's /api/alerts and /api/stats
JSON endpoints and auto-refreshes.

Run with:  streamlit run app.py   (from the dashboard/ folder, backend must
already be running on BACKEND_URL below)
"""

import os
import time
import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="AI Honeypot SOC Dashboard", layout="wide", page_icon="🛡️")

# Auto-refresh every 5 seconds to feel "real-time" without manual reload.
st_autorefresh(interval=5000, key="refresh")

st.title("🛡️ AI Honeypot — SOC Dashboard")
st.caption(f"Live telemetry from generative-AI honeypot decoys · backend: {BACKEND_URL}")


def fetch_json(path, default):
    try:
        resp = requests.get(f"{BACKEND_URL}{path}", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.warning(f"Could not reach backend at {BACKEND_URL}{path} ({e})")
        return default


stats = fetch_json("/api/stats", {
    "total_alerts": 0, "unique_ips": 0, "top_decoys": [], "top_ips": [], "canaries_triggered": 0,
})
alerts = fetch_json("/api/alerts?limit=300", [])

# --- Top metrics row ---------------------------------------------------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("🚨 Total Alerts", stats["total_alerts"])
col2.metric("🌐 Unique Attacker IPs", stats["unique_ips"])
col3.metric("🪤 Canary Tokens Triggered", stats["canaries_triggered"])
critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
col4.metric("🔥 Critical Severity Events", critical_count)

st.divider()

# --- Charts row --------------------------------------------------------------
c1, c2 = st.columns(2)

with c1:
    st.subheader("Most-Triggered Decoy Types")
    if stats["top_decoys"]:
        df_decoys = pd.DataFrame(stats["top_decoys"]).set_index("decoy_type")
        st.bar_chart(df_decoys["hits"])
    else:
        st.info("No decoy hits yet. Try the curl commands from the README to simulate an attack.")

with c2:
    st.subheader("Top Attacker IPs")
    if stats["top_ips"]:
        df_ips = pd.DataFrame(stats["top_ips"]).set_index("source_ip")
        st.bar_chart(df_ips["hits"])
    else:
        st.info("No attacker IPs recorded yet.")

st.divider()

# --- Alerts timeline over time ------------------------------------------------
st.subheader("Alert Volume Over Time")
if alerts:
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["minute"] = df["timestamp"].dt.floor("min")
    volume = df.groupby("minute").size()
    st.line_chart(volume)
else:
    df = pd.DataFrame()
    st.info("No alerts yet.")

st.divider()

# --- Live alert feed table ----------------------------------------------------
st.subheader("🔴 Live Alert Feed")

severity_color = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
}

if not df.empty:
    display_df = df.copy()
    display_df["severity"] = display_df["severity"].apply(
        lambda s: f"{severity_color.get(s, '⚪')} {s.upper()}"
    )
    display_df = display_df[[
        "timestamp", "source_ip", "severity", "decoy_type", "method",
        "path", "user_agent", "canary_token", "payload",
    ]]
    st.dataframe(display_df, use_container_width=True, height=450)

    st.subheader("🕵️ Inspect a Single Alert")
    idx = st.number_input(
        "Alert row id to inspect", min_value=int(df["id"].min()),
        max_value=int(df["id"].max()), value=int(df["id"].max()),
    )
    match = df[df["id"] == idx]
    if not match.empty:
        row = match.iloc[0]
        st.json({
            "id": int(row["id"]),
            "timestamp": str(row["timestamp"]),
            "source_ip": row["source_ip"],
            "user_agent": row["user_agent"],
            "method": row["method"],
            "path": row["path"],
            "query_params": row["query_params"],
            "decoy_type": row["decoy_type"],
            "canary_token": row["canary_token"],
            "severity": row["severity"],
            "payload": row["payload"],
            "headers": row["headers"],
        })
else:
    st.info("Waiting for the first intrusion attempt... try hitting a decoy endpoint!")

st.caption(f"Last refreshed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
