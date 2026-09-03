#!/usr/bin/env python3
"""
BXB Autonomous Triage — Phase 4: Remediation Report
Pulls Critical + High vulnerabilities from Wazuh, cross-references CISA KEV (actively-exploited),
and produces a RANKED, ACTIONABLE report (high->low): what to patch, on which host, why it matters.

Ranking priority:
  1. In CISA KEV (actively exploited in the wild)  <- top, regardless of raw CVSS
  2. CVSS base score
  3. Number of hosts affected
Groups by (host, package) so "update this one package" clears its cluster of CVEs at once —
the high-leverage actions surface first.

Output: markdown report to a folder + (optionally) into the dashboard as an artifact.
Uses the Wazuh indexer that main.py uses. Read-only.
"""
import os, sys, json, datetime, collections

HERE = os.path.dirname(os.path.abspath(__file__))
def _load_env():
    envp = os.path.join(HERE, "..", ".env")
    if os.path.exists(envp):
        for line in open(envp):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
_load_env()
WAZUH_URL  = os.getenv("WAZUH_URL",  "https://YOUR-WAZUH-HOST:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = os.path.join(HERE, ".kev_cache.json")
REPORT_DIR = os.path.join(HERE, "..", "data", "remediation")
SOC_DB = os.path.join(HERE, "..", "data", "soc.db")


def fetch_kev():
    """Fetch CISA KEV (actively-exploited CVEs). Cache locally; fall back to cache on failure."""
    import requests, urllib3
    urllib3.disable_warnings()
    try:
        r = requests.get(KEV_URL, timeout=20)
        if r.status_code == 200:
            data = r.json()
            cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
            open(KEV_CACHE, "w").write(json.dumps(sorted(cves)))
            return cves, f"live ({len(cves)} KEV CVEs)"
    except Exception as e:
        print(f"[remediation] KEV fetch failed ({e}); using cache", file=sys.stderr)
    # fallback to cache
    if os.path.exists(KEV_CACHE):
        return set(json.load(open(KEV_CACHE))), "cached"
    return set(), "unavailable"


def fetch_vulns(severities=("Critical", "High"), size=5000):
    """Pull vuln states from Wazuh for the given severities."""
    import requests, urllib3
    urllib3.disable_warnings()
    q = {"size": size,
         "query": {"bool": {"must": [
             {"terms": {"vulnerability.severity": list(severities)}}]}},
         "_source": ["vulnerability.id", "vulnerability.severity", "vulnerability.score",
                     "vulnerability.reference", "vulnerability.published_at",
                     "agent.name", "package.name", "package.version"]}
    r = requests.post(f"{WAZUH_URL}/wazuh-states-vulnerabilities-*/_search",
                      json=q, auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=40)
    d = r.json()
    out = []
    for h in d.get("hits", {}).get("hits", []):
        s = h["_source"]; v = s.get("vulnerability", {})
        pkg = s.get("package", {}); ag = s.get("agent", {})
        score = v.get("score", {})
        out.append({
            "cve": v.get("id"), "severity": v.get("severity"),
            "cvss": (score.get("base") if isinstance(score, dict) else score) or 0,
            "host": ag.get("name"), "pkg": pkg.get("name"), "ver": pkg.get("version"),
            "ref": v.get("reference"),
        })
    return out


def build_report():
    kev, kev_status = fetch_kev()
    vulns = fetch_vulns()
    if not vulns:
        return None, "no vulnerabilities returned (check Wazuh indexer)"

    # group by (host, package) — one action clears its cluster of CVEs
    groups = collections.defaultdict(lambda: {"cves": [], "max_cvss": 0, "kev": False,
                                              "kev_cves": [], "severity": "High"})
    for v in vulns:
        key = (v["host"], v["pkg"], v["ver"])
        g = groups[key]
        g["cves"].append(v["cve"])
        g["max_cvss"] = max(g["max_cvss"], v["cvss"] or 0)
        if v["severity"] == "Critical":
            g["severity"] = "Critical"
        if v["cve"] in kev:
            g["kev"] = True
            g["kev_cves"].append(v["cve"])
        ref = v.get("ref") or ""
        g["ref"] = (ref.split(",")[0].strip() if ref else "vendor advisory")

    # rank: KEV first, then max CVSS, then #CVEs cleared
    ranked = sorted(groups.items(),
                    key=lambda kv: (kv[1]["kev"], kv[1]["max_cvss"], len(kv[1]["cves"])),
                    reverse=True)

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# BXB Remediation Report — {now}",
             f"\nCISA KEV feed: {kev_status}. Vulnerabilities: {len(vulns)} across "
             f"{len(groups)} host/package groups.\n",
             "Ranked high→low. **KEV = actively exploited in the wild — patch these FIRST**, "
             "even above higher raw-CVSS items.\n",
             "---\n"]

    kev_groups = [g for g in ranked if g[1]["kev"]]
    if kev_groups:
        lines.append("## 🚨 ACTIVELY EXPLOITED (CISA KEV) — do these first\n")
        for (host, pkg, ver), g in kev_groups:
            lines.append(f"- **{host}** — update `{pkg}` (currently {ver})")
            lines.append(f"  - Clears {len(g['cves'])} CVE(s); max CVSS {g['max_cvss']}. "
                         f"**IN KEV: {', '.join(g['kev_cves'][:5])}**")
            lines.append(f"  - Action: update the package + reboot if kernel/core. Ref: {g.get('ref') or 'vendor advisory'}\n")

    lines.append("\n## By severity (KEV-free), highest impact first\n")
    shown = 0
    for (host, pkg, ver), g in ranked:
        if g["kev"]:
            continue
        if shown >= 40:
            lines.append(f"\n_({len(ranked)-40-len(kev_groups)} more groups omitted — see dashboard)_")
            break
        tag = "🔴 CRITICAL" if g["severity"] == "Critical" else "🟠 HIGH"
        lines.append(f"- {tag} **{host}** — `{pkg}` {ver} — clears {len(g['cves'])} CVE(s), max CVSS {g['max_cvss']}")
        shown += 1

    # high-leverage summary: hosts with the most fixable CVEs
    by_host = collections.Counter()
    for v in vulns:
        by_host[v["host"]] += 1
    lines.append("\n---\n## Highest-leverage: hosts with the most open CVEs\n")
    for host, n in by_host.most_common(10):
        lines.append(f"- **{host}**: {n} open Critical/High CVEs (often one kernel/package update clears many)")

    return "\n".join(lines), "ok"


def save_to_dashboard(md):
    """Write the report into the dashboard artifacts table (shows in the ARTIFACTS tab)."""
    import sqlite3
    try:
        conn = sqlite3.connect(SOC_DB, timeout=15)
        title = f"Remediation Report {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        conn.execute(
            "INSERT INTO artifacts (timestamp,title,content,tags,finding_id,artifact_type) "
            "VALUES (datetime('now'),?,?,?,?,?)",
            (title, md, "remediation,vuln,kev", None, "remediation"))
        conn.commit(); conn.close()
        return True
    except Exception as e:
        print(f"[remediation] dashboard save failed: {e}", file=sys.stderr)
        return False


def save_report(md):
    os.makedirs(REPORT_DIR, exist_ok=True)
    fn = os.path.join(REPORT_DIR, f"remediation-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M')}.md")
    open(fn, "w").write(md)
    return fn


if __name__ == "__main__":
    md, status = build_report()
    if md:
        fn = save_report(md)
        dash = save_to_dashboard(md)
        print(f"[remediation] report saved: {fn} | dashboard artifact: {dash}\n")
        print(md[:2500])
    else:
        print(f"[remediation] {status}")
