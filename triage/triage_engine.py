#!/usr/bin/env python3
"""
home-soc — Deterministic Triage Core
Classifies IDS/network findings into tiers by TOPOLOGY + SIGNATURE (no LLM).

Tiers:
  0 = AUTO-DISMISS (logged, never shown)   — LAN->LAN, benign sig, non-crown-jewel, no anomaly
  1 = FILE FOR REVIEW (queue, not pinged)  — WAN->LAN edge, ambiguous
  2 = ELEVATE (alert)                      — WAN->crown-jewel, real-threat sig, high-sev
  3 = LLM (needs investigation)            — survives rules but not clearly 0/1/2

CONFIGURATION
-------------
Network-specific values (your segments, crown-jewel assets, benign management sources) are read
from `config.yaml` at import time — nothing about any real network is hardcoded here. Copy
`config.example.yaml` to `config.yaml` and fill in your own values. See the README.

Generic security knowledge (RFC1918 ranges, common noise / threat / info signature markers) ships
with sensible defaults below; your config can EXTEND them via the `signatures:` section.

This module is side-effect-free: it classifies and returns verdicts. Wiring to alerting / a review
queue / an audit log lives in the runner.
"""
import os
import ipaddress

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------
def _load_config():
    """Load config.yaml from (in order): $HOMESOC_CONFIG, ./config.yaml next to this file, cwd.
    Returns a dict. Missing config is fine — we fall back to safe empty/default values so the
    engine still runs (it just won't have crown-jewels/segments until you configure them)."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("HOMESOC_CONFIG"),
        os.path.join(here, "config.yaml"),
        os.path.join(os.getcwd(), "config.yaml"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            try:
                import yaml
                with open(path) as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                print(f"[triage_engine] WARNING: could not load config {path}: {e}")
                return {}
    return {}

_CFG = _load_config()

# ---------------------------------------------------------------------------
# Network model — RFC1918 is universal; kept in code. Config may add ranges.
# ---------------------------------------------------------------------------
_DEFAULT_LAN_NETS = [
    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",   # IPv4 RFC1918
    "fe80::/10", "fc00::/7", "::1/128", "127.0.0.0/8",  # IPv6 link-local/ULA/loopback + IPv4 loopback
]
LAN_NETS = [ipaddress.ip_network(n) for n in
            (_DEFAULT_LAN_NETS + list(_CFG.get("extra_lan_nets", [])))]

# ---- Segments: VLAN labels for reporting. FROM CONFIG (your network). ----
SEGMENTS = dict(_CFG.get("segments", {}))            # e.g. {"192.168.10.0/24": "Main", ...}

# ---- Crown-jewel assets: traffic TOWARD these ELEVATES. FROM CONFIG (your network). ----
CROWN_JEWELS = dict(_CFG.get("crown_jewels", {}))    # e.g. {"192.168.10.10": "SIEM", ...}

# ---- Benign management sources: infra that legitimately generates heavy internal traffic
#      (a controller polling gateways, a monitoring host, etc). We dismiss what these DO
#      (their outbound management chatter) — never what's done TO them. FROM CONFIG. ----
BENIGN_MGMT_SOURCES = dict(_CFG.get("benign_mgmt_sources", {}))   # {ip: description}
# gateways the benign sources legitimately manage (their polling targets). FROM CONFIG.
BENIGN_MGMT_GATEWAYS = set(_CFG.get("benign_mgmt_gateways", []))  # {"192.168.10.1", ...}

# ---------------------------------------------------------------------------
# Signature classification — generic ET/Suricata knowledge. Sensible defaults;
# config `signatures:` may extend each list for your environment's noise.
# ---------------------------------------------------------------------------
_sig = _CFG.get("signatures", {}) if isinstance(_CFG.get("signatures"), dict) else {}

KNOWN_NOISE_SIGS = set([
    "SURICATA Ethertype unknown",
    "SURICATA STREAM CLOSEWAIT FIN out of window",
    "SURICATA STREAM Packet with invalid timestamp",
    "SURICATA STREAM excessive retransmissions",
    "SURICATA HTTP Request line incomplete",
    "SURICATA STREAM 3way handshake wrong seq wrong ack",
    "SURICATA STREAM ESTABLISHED packet out of window",
    "SURICATA STREAM FIN out of window",
    "SURICATA STREAM TIMEWAIT ACK with wrong seq",
    "SURICATA STREAM ESTABLISHED SYNACK resend",
    "SURICATA STREAM ESTABLISHED SYN resend",
    "SURICATA STREAM bad window update",
    "SURICATA STREAM 3way handshake SYNACK resend with different ACK",
    "SURICATA UDPv4 invalid checksum",
    "SURICATA HTTP Response excessive header",
    "SURICATA Applayer Protocol detection skipped",
] + list(_sig.get("extra_noise", [])))

# any signature starting with one of these prefixes is treated as decoder/protocol noise
NOISE_PREFIXES = tuple([
    "SURICATA STREAM ", "SURICATA TCPv", "SURICATA UDPv", "SURICATA IPv",
    "SURICATA zero length padN option", "SURICATA Applayer",
] + list(_sig.get("extra_noise_prefixes", [])))

# substrings indicating a REAL threat — elevate regardless of topology
REAL_THREAT_MARKERS = tuple([
    "ET MALWARE", "ET EXPLOIT", "ET TROJAN", "ET CNC",
    "ET ATTACK_RESPONSE", "ET WORM", "ExploitKit", "Cobalt Strike",
] + list(_sig.get("extra_threat_markers", [])))

# block-listed-source scanners hitting the edge — real but firewall already drops them
EDGE_SCANNER_MARKERS = tuple([
    "ET CINS", "ET DROP", "ET DSHIELD", "Dshield", "Spamhaus DROP",
    "Poor Reputation", "Block Listed Source",
] + list(_sig.get("extra_edge_markers", [])))

# informational / benign-context signatures (STUN, DNS lookups, connectivity checks, app UAs)
INFO_MARKERS = tuple([
    "ET INFO", "ET DNS", "ET USER_AGENTS", "ET POLICY",
    "Microsoft Connection Test", "Connection Test", "STUN",
    "External IP Lookup", "Observed UA", "Session Traversal",
] + list(_sig.get("extra_info_markers", [])))


# ---------------------------------------------------------------------------
# Core logic (unchanged — pure functions over the config above)
# ---------------------------------------------------------------------------
def is_lan(ip_str):
    """True if the IP is internal (RFC1918 / link-local / loopback)."""
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    return any(ip in net for net in LAN_NETS)


def segment_of(ip_str):
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for cidr, name in SEGMENTS.items():
        if ip in ipaddress.ip_network(cidr):
            return name
    return "LAN-other" if is_lan(ip_str) else "WAN"


def direction(src_ip, dst_ip):
    """Classify traffic direction from src/dst LAN/WAN status."""
    s, d = is_lan(src_ip), is_lan(dst_ip)
    if s is None or d is None:
        return "UNKNOWN"          # missing IP (e.g. Ethertype-unknown decode noise)
    if s and d:     return "LAN->LAN"
    if not s and d: return "WAN->LAN"
    if s and not d: return "LAN->WAN"
    return "WAN->WAN"


def sig_class(signature):
    """Bucket a signature: 'noise' | 'threat' | 'edge_scan' | 'info' | 'other'."""
    if not signature:
        return "other"
    if signature in KNOWN_NOISE_SIGS:
        return "noise"
    if any(signature.startswith(pfx) for pfx in NOISE_PREFIXES):
        return "noise"
    if any(m in signature for m in REAL_THREAT_MARKERS):
        return "threat"
    if any(m in signature for m in EDGE_SCANNER_MARKERS):
        return "edge_scan"
    if any(m in signature for m in INFO_MARKERS):
        return "info"
    return "other"


def classify(finding):
    """
    finding: dict with keys src_ip, dst_ip, src_port, dst_port, signature, severity, category.
    Returns: dict {tier, reason, direction, sig_class, needs_llm, ...}
    Tier 3 (needs_llm) = deterministic rules couldn't confidently decide.
    """
    src, dst = finding.get("src_ip"), finding.get("dst_ip")
    sig = finding.get("signature") or ""
    sev = finding.get("severity")
    dr = direction(src, dst)
    sc = sig_class(sig)

    v = lambda tier, reason, **kw: {
        "tier": tier, "reason": reason, "direction": dr, "sig_class": sc,
        "src": src, "dst": dst, "signature": sig, "severity": sev,
        "src_seg": segment_of(src), "dst_seg": segment_of(dst),
        "crown_jewel": CROWN_JEWELS.get(dst), "needs_llm": tier == 3, **kw}

    # Gate 1 — real-threat signatures ELEVATE regardless of topology.
    if sc == "threat":
        return v(2, f"real-threat signature ({sig})")

    # Gate 2 — known decoder-noise signatures AUTO-DISMISS (even with null IPs).
    if sc == "noise":
        return v(0, f"known-noise signature ({sig})")

    # Gate 2b — informational signatures (ET INFO/DNS/STUN/etc) AUTO-DISMISS.
    if sc == "info":
        return v(0, f"informational signature ({sig}) — normal network behavior")

    # Gate 3 — benign management source (e.g. a controller polling its gateways / phoning cloud).
    # Dismiss THAT chatter — scoped so it can't blind us: only when the dest is a managed gateway
    # or external. A benign source hitting a NON-gateway crown-jewel still falls through and elevates.
    if src in BENIGN_MGMT_SOURCES:
        if dst in BENIGN_MGMT_GATEWAYS or dr == "LAN->WAN":
            return v(0, f"benign mgmt source ({BENIGN_MGMT_SOURCES[src]})")

    # Gate 4 — traffic TO a crown-jewel asset ELEVATES (possible lateral movement / targeted attack).
    if dst in CROWN_JEWELS:
        return v(2, f"traffic to crown-jewel: {CROWN_JEWELS[dst]}")

    # Gate 5 — topology-based.
    if dr == "LAN->LAN":
        return v(0, "LAN->LAN, benign category, non-sensitive target")
    if dr == "WAN->LAN":
        if sc == "edge_scan":
            return v(0, f"WAN->LAN edge scanner ({sig}) — firewall-dropped, low value")
        return v(1, "WAN->LAN direct (potential attack stage 1) — watch")
    if dr == "LAN->WAN":
        return v(1, "LAN->WAN outbound, unclassified signature — reputation check / review")
    if dr == "WAN->WAN":
        return v(1, "WAN->WAN transit — unusual, review")
    if dr == "UNKNOWN":
        return v(3, "missing src/dst IP, non-noise signature — investigate")

    return v(3, "unclassified by rules — investigate")


if __name__ == "__main__":
    # Self-test — works with or without a config.yaml present.
    print(f"config: {len(CROWN_JEWELS)} crown-jewels, {len(SEGMENTS)} segments, "
          f"{len(BENIGN_MGMT_SOURCES)} benign sources loaded")
    tests = [
        {"src_ip": "192.168.40.99", "dst_ip": "192.168.40.50",
         "signature": "SURICATA STREAM FIN out of window"},                    # -> T0 noise
        {"src_ip": None, "dst_ip": None, "signature": "SURICATA Ethertype unknown"},  # -> T0
        {"src_ip": "192.168.40.99", "dst_ip": "8.8.8.8", "signature": "ET INFO DNS"}, # -> T0 info
        {"src_ip": "192.168.40.99", "dst_ip": "192.168.40.50",
         "signature": "ET MALWARE Cobalt Strike Beacon"},                      # -> T2 threat
    ]
    for t in tests:
        r = classify(t)
        print(f"[T{r['tier']}] {r['direction']:10} {str(r['src']):16}->{str(r['dst']):16} | {r['reason'][:50]}")
