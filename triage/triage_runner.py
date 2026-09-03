#!/usr/bin/env python3
"""
BXB Autonomous Triage — Phase 2: Runner + Sinks
Pulls INDIVIDUAL Suricata findings (not signature-aggregated) since a watermark,
classifies each via triage_engine, and routes to sinks:
  T0 -> audit (DB row, never pings)
  T1 -> review queue (DB row, tier=1, never pings)
  T2 -> elevate (DB row + Discord)  [Discord DISABLED until explicitly enabled]
  T3 -> needs-LLM (DB row, tier=3, for the Phase 3 LLM layer)

Reuses the existing alert_intel infrastructure: ES connection pattern, .env loading,
the SQLite DB, and notify.py's Discord sender. Adds a finding-level triage_verdicts table
ALONGSIDE the existing signature-centric tables (complementary, not overlapping).

SAFETY: Discord elevation is behind ENABLE_DISCORD (default False). Build+test the audit/review
sinks first; flip ENABLE_DISCORD=True only after verifying classifications on live data.
"""
import os, sys, sqlite3, datetime, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# triage_engine lives in ../backend/ ; add it to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from triage_engine import classify
try:
    import triage_enrich
    _ENRICH = True
except Exception as _e:
    _ENRICH = False
    print(f"[triage] enrichment unavailable: {_e}", file=sys.stderr)
try:
    import triage_dashboard
    _DASH = True
except Exception as _e:
    _DASH = False
    print(f"[triage] dashboard ingest unavailable: {_e}", file=sys.stderr)

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "alert_intel.db")
TRIAGE_WATERMARK = os.path.join(HERE, ".triage_watermark")

# ---- SAFETY GATE: Discord elevation off by default ----
ENABLE_DISCORD = True   # ENABLED 2026-09-01 after plumbing test

# ---- ES creds from the shared .env (same pattern as ingest.py) ----
def _load_env():
    envp = os.path.join(HERE, "..", ".env")
    if os.path.exists(envp):
        for line in open(envp):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
_load_env()
ELASTIC_URL  = os.getenv("ELASTIC_URL",  "https://YOUR-ELASTIC-HOST:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS = os.getenv("ELASTIC_PASS", "")


def _db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS triage_verdicts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, alert_ts TEXT,
        src_ip TEXT, dst_ip TEXT, src_seg TEXT, dst_seg TEXT,
        src_port INTEGER, dst_port INTEGER,
        signature TEXT, category TEXT, severity INTEGER,
        direction TEXT, sig_class TEXT,
        tier INTEGER, reason TEXT, crown_jewel TEXT,
        reviewed INTEGER DEFAULT 0,     -- 0=unreviewed, 1=owner looked
        owner_verdict TEXT,             -- null | 'confirmed' | 'false_positive'
        elevated_sent INTEGER DEFAULT 0 -- 1 if a Discord ping was sent
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tv_tier ON triage_verdicts(tier)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_tv_reviewed ON triage_verdicts(reviewed)")
    c.commit()
    return c


def _read_watermark():
    try:
        return open(TRIAGE_WATERMARK).read().strip()
    except Exception:
        return None


def _write_watermark(ts):
    open(TRIAGE_WATERMARK, "w").write(ts)


def fetch_findings(since_iso, size=1000):
    """Pull INDIVIDUAL findings (with IPs) since the watermark. Excludes the pure
    decoder-noise signatures at query time so we don't store 100k Ethertype rows —
    those are known-Tier-0 and counted separately by the signature pipeline."""
    import requests, urllib3
    urllib3.disable_warnings()
    gte = since_iso if since_iso else "now-1h"
    q = {"size": size,
         "query": {"bool": {
             "must": [
                 {"term": {"event.module": "suricata"}},
                 {"term": {"suricata.eve.event_type": "alert"}},
                 {"range": {"@timestamp": {"gt": gte}}}],
             "must_not": [
                 {"terms": {"suricata.eve.alert.signature": [
                     "SURICATA Ethertype unknown",
                     "SURICATA STREAM CLOSEWAIT FIN out of window",
                     "SURICATA STREAM Packet with invalid timestamp",
                     "SURICATA STREAM excessive retransmissions",
                     "SURICATA STREAM ESTABLISHED packet out of window"]}}]}},
         "sort": [{"@timestamp": "asc"}]}   # asc so the watermark advances correctly
    r = requests.post(f"{ELASTIC_URL}/.ds-filebeat-*/_search", json=q,
                      auth=(ELASTIC_USER, ELASTIC_PASS), verify=False, timeout=30)
    return r.json().get("hits", {}).get("hits", [])


def _to_finding(src):
    a = src.get("suricata", {}).get("eve", {}).get("alert", {})
    s = src.get("source") or {}
    d = src.get("destination") or {}
    return {
        "alert_ts": src.get("@timestamp"),
        "src_ip": s.get("ip"), "dst_ip": d.get("ip"),
        "src_port": s.get("port"), "dst_port": d.get("port"),
        "signature": a.get("signature"), "category": a.get("category"),
        "severity": a.get("severity"),
    }


def elevate_discord(v):
    """T2 sink — enrich with LLM, then send to Discord. GATED by ENABLE_DISCORD.
    If the LLM suppresses a low-stakes non-crown-jewel/non-threat finding, no ping is sent
    (but it's still stored). Crown-jewel/threat ALWAYS ping. LLM failure -> alert with raw reason."""
    if not ENABLE_DISCORD:
        return False
    # --- enrich (fail-safe: if enrichment module or LLM is down, we still alert) ---
    enrich = {"enrich_ok": False, "suppressed": False}
    if _ENRICH:
        try:
            enrich = triage_enrich.enrich_verdict(v)
        except Exception as e:
            print(f"[elevate] enrich error (alerting anyway): {e}", file=sys.stderr)
    # --- guardrail: only suppress if enrichment explicitly says so (crown/threat never suppressed) ---
    if enrich.get("suppressed"):
        print(f"[elevate] LLM-suppressed low-stakes ping: {v.get('src')}->{v.get('dst')} ({v.get('reason')})")
        return False
    try:
        import requests
        wf = os.path.join(HERE, ".webhook_digest")
        url = open(wf).read().strip()
        if _ENRICH and enrich.get("enrich_ok"):
            msg = triage_enrich.format_alert(v, enrich)
        else:
            msg = (f"🚨 **[BXB TRIAGE] {v['reason']}**\n"
                   f"`{v['src']}` → `{v['dst']}` ({v.get('dst_seg','?')}) · {v['direction']}\n"
                   f"Signature: {v['signature']}\n"
                   f"Tier {v['tier']} · {v.get('crown_jewel') or ''}"
                   f"\n_(AI enrichment unavailable — alerting on rule verdict alone)_")
        requests.post(url, json={"content": msg}, timeout=15)
        return True
    except Exception as e:
        print(f"[elevate] discord send failed: {e}", file=sys.stderr)
        return False


def run(dry_run=False):
    since = _read_watermark()
    hits = fetch_findings(since)
    if not hits:
        try:
            open(os.path.join(HERE, ".triage_heartbeat"), "w").write(datetime.datetime.utcnow().isoformat())
        except Exception:
            pass
        print(f"[triage] no new findings since {since or 'start'}")
        return {"processed": 0}

    c = _db()
    from collections import Counter
    tiers = Counter()
    last_ts = since
    sent = 0
    for h in hits:
        src = h["_source"]
        f = _to_finding(src)
        v = classify(f)
        tiers[v["tier"]] += 1
        last_ts = f["alert_ts"] or last_ts

        elevated_sent = 0
        if v["tier"] == 2 and not dry_run:
            if elevate_discord(v):
                elevated_sent = 1
                sent += 1
        # push T1/T2 to the BXB Analyst dashboard (respects FP suppression)
        if v["tier"] in (1, 2) and not dry_run and _DASH:
            try:
                triage_dashboard.ingest_verdict_to_dashboard(v)
            except Exception as e:
                print(f"[triage] dashboard ingest error: {e}", file=sys.stderr)

        if not dry_run:
            c.execute("""INSERT INTO triage_verdicts
                (ts, alert_ts, src_ip, dst_ip, src_seg, dst_seg, src_port, dst_port,
                 signature, category, severity, direction, sig_class, tier, reason,
                 crown_jewel, elevated_sent)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (datetime.datetime.utcnow().isoformat(), f["alert_ts"],
                 f["src_ip"], f["dst_ip"], v["src_seg"], v["dst_seg"],
                 f["src_port"], f["dst_port"], f["signature"], f["category"],
                 f["severity"], v["direction"], v["sig_class"], v["tier"],
                 v["reason"], v.get("crown_jewel"), elevated_sent))

    if not dry_run:
        c.commit()
        if last_ts:
            _write_watermark(last_ts)
    c.close()

    # heartbeat: prove the runner RAN, even if it found nothing (watchdog checks this)
    try:
        open(os.path.join(HERE, ".triage_heartbeat"), "w").write(datetime.datetime.utcnow().isoformat())
    except Exception:
        pass
    result = {"processed": len(hits), "tiers": dict(tiers),
              "elevated_sent": sent, "discord_enabled": ENABLE_DISCORD,
              "watermark_advanced_to": last_ts if not dry_run else "(dry-run, not advanced)"}
    print(f"[triage] {json.dumps(result)}")
    return result


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    if dry:
        print("=== DRY RUN (classifies + reports, writes NOTHING, sends NOTHING) ===")
    run(dry_run=dry)
