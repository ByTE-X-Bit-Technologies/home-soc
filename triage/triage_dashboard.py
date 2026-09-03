#!/usr/bin/env python3
"""
BXB Autonomous Triage — Dashboard Ingest
Writes T1/T2 triage verdicts into the BXB Analyst dashboard's findings table (soc.db),
using the SAME schema, fp_hash logic, UPSERT dedup, and false-positive check the dashboard
uses. So triage findings appear as normal dashboard cards (source="triage"), and clicking
FALSE POSITIVE in the dashboard suppresses that pattern going forward — the feedback loop,
reusing the machinery already in main.py.

fp_hash = sha256("{source}:{title}:{host}")[:16]  — identical to main.py's make_fp_hash,
so hashes match and the dashboard's existing FP list applies to triage findings too.
"""
import os, sqlite3, hashlib, json, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
# soc.db is in ../data/ relative to alert_intel/ (host path)
SOC_DB = os.path.join(HERE, "..", "data", "soc.db")


def make_fp_hash(source, title, host=""):
    # MUST match main.py exactly
    return hashlib.sha256(f"{source}:{title}:{host}".encode()).hexdigest()[:16]


def _sev_for_tier(tier):
    # map triage tier -> dashboard severity string (matches existing critical/high/medium/low)
    return {2: "high", 1: "medium"}.get(tier, "low")


def _title_for(v):
    # stable, human-readable title. Include src->dst so the fp_hash is per-pattern,
    # so marking ONE pattern FP doesn't suppress unrelated triage findings.
    return f"[Triage] {v.get('reason')} — {v.get('src')} → {v.get('dst')}"


def ingest_verdict_to_dashboard(v):
    """
    Ingest one T1/T2 triage verdict into soc.db findings (source='triage').
    Respects the dashboard's false_positives list (skips suppressed patterns).
    UPSERTs on (title, host) like main.py, so recurring = one finding seen N times.
    Returns 'ingested' | 'updated' | 'suppressed' | 'skipped'.
    """
    if v.get("tier") not in (1, 2):
        return "skipped"  # only surface review/elevate items on the dashboard

    source = "triage"
    title = _title_for(v)
    host = str(v.get("dst") or "")
    sev = _sev_for_tier(v.get("tier"))
    category = v.get("direction") or "triage"
    desc = (f"{v.get('reason')}. Signature: {v.get('signature')}. "
            f"{v.get('src')}→{v.get('dst')} ({v.get('dst_seg')}). "
            f"Tier {v.get('tier')}. {('Crown-jewel: ' + v['crown_jewel']) if v.get('crown_jewel') else ''}")
    fp_hash = make_fp_hash(source, title, host)

    conn = sqlite3.connect(SOC_DB, timeout=15)
    try:
        # respect the dashboard's false-positive list (this IS the feedback loop)
        if conn.execute("SELECT 1 FROM false_positives WHERE fp_hash=?", (fp_hash,)).fetchone():
            return "suppressed"

        existing = conn.execute(
            "SELECT id FROM findings WHERE title=? AND host=? AND status='open'",
            (title, host)).fetchone()
        if existing:
            conn.execute(
                "UPDATE findings SET last_seen=datetime('now'), count=count+1, "
                "severity=?, description=? WHERE id=?",
                (sev, desc, existing[0]))
            conn.commit()
            return "updated"

        conn.execute(
            "INSERT INTO findings (timestamp, source, severity, category, title, description, "
            "network, host, raw_data, status, fp_hash, last_seen, count) "
            "VALUES (datetime('now'),?,?,?,?,?,?,?,?, 'open', ?, datetime('now'), 1)",
            (source, sev, category, title, desc, v.get("dst_seg") or "",
             host, json.dumps({k: v.get(k) for k in
                 ("src","dst","signature","direction","sig_class","tier","reason","crown_jewel")}),
             fp_hash))
        conn.commit()
        return "ingested"
    finally:
        conn.close()


if __name__ == "__main__":
    # self-test with a couple of synthetic verdicts
    tests = [
        {"tier":1,"src":"198.51.100.27","dst":"192.0.2.106","dst_seg":"IoT",
         "signature":"ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response","direction":"WAN->LAN",
         "sig_class":"other","reason":"WAN->LAN direct (potential attack stage 1)","crown_jewel":None},
        {"tier":2,"src":"203.0.113.5","dst":"192.0.2.10","dst_seg":"Main",
         "signature":"ET SCAN test","direction":"WAN->LAN","sig_class":"other",
         "reason":"traffic TO crown-jewel homesoc","crown_jewel":"homesoc (SOC/SIEM + PILA)"},
    ]
    for t in tests:
        print(t["tier"], "->", ingest_verdict_to_dashboard(t))
    # show it landed
    c = sqlite3.connect(SOC_DB)
    print("--- triage findings now in dashboard ---")
    for r in c.execute("SELECT severity, title, count FROM findings WHERE source='triage' ORDER BY id DESC LIMIT 5"):
        print("  ", r[0], "|", r[1], "| seen", r[2])
