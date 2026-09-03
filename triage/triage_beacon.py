#!/usr/bin/env python3
"""
BXB Autonomous Triage — Phase 3.5: Beacon Detection (Zeek conn logs)
Detects regular-interval "beaconing" between host pairs — the fingerprint of C2 /
compromised-device check-ins. Implements the owner-specified algorithm:
  per src->dst pair over a lookback window:
    (a) connection COUNT           — need enough to establish a pattern (>= MIN_CONNS)
    (b) interval REGULARITY        — coefficient of variation (stddev/mean) of the time-gaps
                                     between consecutive connections. LOW cv = metronomic = beacon.
    (c) size CONSISTENCY           — coefficient of variation of bytes-per-connection.
                                     LOW cv = near-identical check-ins = automated.
  beacon_score combines these; high score = strong beacon candidate.

This is the same statistical approach professional C2-hunting tools (RITA, Zeek beaconing) use.
Beacon-positive != malicious (NTP, cloud polling, update checks all beacon) — so a hit goes to
REVIEW + LLM assessment, and is UPGRADED only if the destination is external/unknown reputation.

Data: 26M zeek.connection docs in ES (.ds-filebeat-*). Read-only aggregation.
"""
import os, sys, json, statistics, ipaddress

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
ELASTIC_URL  = os.getenv("ELASTIC_URL",  "https://YOUR-ELASTIC-HOST:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS = os.getenv("ELASTIC_PASS", "")

# ---- tunables ----
MIN_CONNS      = 8      # need >= this many connections to score a pair
INTERVAL_CV_MAX = 0.25  # interval coeff-of-variation below this = "regular" (beacon-like)
SIZE_CV_MAX     = 0.30  # byte-size coeff-of-variation below this = "consistent" (beacon-like)
LOOKBACK        = "now-7d"  # window to analyze (Zeek data is historical)


def _is_lan(ip):
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return None
    for n in ("192.168.0.0/16","10.0.0.0/8","172.16.0.0/12","fe80::/10","fc00::/7"):
        if a in ipaddress.ip_network(n):
            return True
    return False

def _is_multicast_or_bcast(ip):
    """Multicast (224/4, ff00::/8), broadcast, link-local-all-nodes — protocol traffic,
    NOT host-to-host beacons. mDNS/SSDP/IGMP/DHCPv6 beacon by design; exclude them."""
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return a.is_multicast or a.is_reserved or str(ip).endswith(".255") or str(ip) == "255.255.255.255"


def _cv(values):
    """Coefficient of variation = stddev/mean. Lower = more regular. Returns None if <2 values."""
    if len(values) < 2:
        return None
    m = statistics.mean(values)
    if m == 0:
        return 0.0
    return statistics.pstdev(values) / m


def fetch_pair_conns(min_conns=MIN_CONNS, lookback=LOOKBACK, top_pairs=200, per_pair=500):
    """
    Aggregate zeek.connection by src->dst pair, return per-pair connection lists
    (timestamps + bytes) for pairs with >= min_conns connections.
    Uses a composite-ish approach: top talkers by pair, then pull their conns.
    """
    import requests, urllib3
    urllib3.disable_warnings()
    sess = requests.Session(); sess.auth = (ELASTIC_USER, ELASTIC_PASS); sess.verify = False

    # Step 1: find the busiest src->dst pairs (candidates worth scoring)
    agg = {"size": 0,
           "query": {"bool": {"must": [
               {"term": {"event.dataset": "zeek.connection"}},
               {"range": {"@timestamp": {"gte": lookback}}}]}},
           "aggs": {"pairs": {"multi_terms": {
               "terms": [{"field": "source.ip"}, {"field": "destination.ip"}],
               "size": top_pairs, "min_doc_count": min_conns,
               "order": {"_count": "desc"}}}}}
    r = sess.post(f"{ELASTIC_URL}/.ds-filebeat-*/_search", json=agg, timeout=30)
    d = r.json()
    if "aggregations" not in d:
        print("ES agg error:", json.dumps(d)[:300], file=sys.stderr)
        return {}
    candidate_pairs = []
    for b in d["aggregations"]["pairs"]["buckets"]:
        src, dst = b["key"]
        # skip multicast/broadcast destinations — protocol infra, not host beacons
        if _is_multicast_or_bcast(dst):
            continue
        candidate_pairs.append((src, dst, b["doc_count"]))

    # Step 2: for each candidate pair, pull its connections (ts + bytes) to compute variance
    pairs = {}
    for src, dst, cnt in candidate_pairs:
        q = {"size": per_pair,
             "_source": ["@timestamp", "network.bytes", "destination.port", "network.protocol"],
             "query": {"bool": {"must": [
                 {"term": {"event.dataset": "zeek.connection"}},
                 {"term": {"source.ip": src}},
                 {"term": {"destination.ip": dst}},
                 {"range": {"@timestamp": {"gte": lookback}}}]}},
             "sort": [{"@timestamp": "asc"}]}
        rr = sess.post(f"{ELASTIC_URL}/.ds-filebeat-*/_search", json=q, timeout=30)
        hits = rr.json().get("hits", {}).get("hits", [])
        conns = []
        for h in hits:
            s = h["_source"]
            conns.append({"ts": s.get("@timestamp"),
                          "bytes": (s.get("network") or {}).get("bytes", 0),
                          "dport": (s.get("destination") or {}).get("port"),
                          "proto": (s.get("network") or {}).get("protocol")})
        if len(conns) >= min_conns:
            pairs[(src, dst)] = conns
    return pairs


def _parse_ts(ts):
    import datetime
    # ES timestamps like 2026-08-21T19:08:30.434Z
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def score_pair(src, dst, conns):
    """Compute the beacon score for one src->dst pair."""
    times = sorted(_parse_ts(c["ts"]) for c in conns if c.get("ts"))
    intervals = [t2 - t1 for t1, t2 in zip(times, times[1:]) if (t2 - t1) > 0]
    sizes = [c["bytes"] for c in conns if c.get("bytes") is not None]

    interval_cv = _cv(intervals)
    size_cv = _cv(sizes)
    n = len(conns)

    # beacon-like if BOTH interval and size are regular (low CV)
    regular_interval = interval_cv is not None and interval_cv <= INTERVAL_CV_MAX
    consistent_size  = size_cv is not None and size_cv <= SIZE_CV_MAX
    is_beacon = n >= MIN_CONNS and regular_interval and consistent_size

    # a simple 0-100 score: more connections + lower CVs = higher
    score = 0
    if interval_cv is not None:
        score += max(0, (1 - min(interval_cv / INTERVAL_CV_MAX, 2)) * 40)
    if size_cv is not None:
        score += max(0, (1 - min(size_cv / SIZE_CV_MAX, 2)) * 30)
    score += min(n / 50, 1) * 30
    score = round(score)

    median_interval = statistics.median(intervals) if intervals else None
    return {
        "src": src, "dst": dst, "conns": n,
        "interval_cv": round(interval_cv, 3) if interval_cv is not None else None,
        "size_cv": round(size_cv, 3) if size_cv is not None else None,
        "median_interval_s": round(median_interval, 1) if median_interval else None,
        "dport": conns[0].get("dport"), "proto": conns[0].get("proto"),
        "dst_is_lan": _is_lan(dst),
        "is_beacon": is_beacon, "score": score,
    }


def find_beacons(min_score=50):
    """Main entry: return scored beacon candidates, sorted by score."""
    pairs = fetch_pair_conns()
    results = [score_pair(s, d, c) for (s, d), c in pairs.items()]
    beacons = [r for r in results if r["is_beacon"] or r["score"] >= min_score]
    beacons.sort(key=lambda r: r["score"], reverse=True)
    return beacons, len(results)


if __name__ == "__main__":
    print("Analyzing Zeek conn logs for beacon patterns (this queries a lot of data)...")
    beacons, total = find_beacons()
    print(f"Scored {total} host pairs (>= {MIN_CONNS} conns). Beacon candidates: {len(beacons)}\n")
    print(f"{'SCORE':>5} {'BEACON':>6} {'CONNS':>6} {'INT_CV':>7} {'SIZE_CV':>7} {'~INTERVAL':>10}  PAIR")
    for b in beacons[:25]:
        ext = "" if b["dst_is_lan"] else " [EXTERNAL DST]"
        iv = f"{b['median_interval_s']}s" if b['median_interval_s'] else "?"
        print(f"{b['score']:>5} {str(b['is_beacon']):>6} {b['conns']:>6} "
              f"{str(b['interval_cv']):>7} {str(b['size_cv']):>7} {iv:>10}  "
              f"{b['src']} -> {b['dst']}:{b['dport']} ({b['proto']}){ext}")
