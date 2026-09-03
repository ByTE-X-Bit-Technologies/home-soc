#!/usr/bin/env python3
"""
BXB Autonomous Triage — Phase 3: LLM Enrichment (T2 alerts)
When a T2 elevation fires, the LLM investigates it and writes a human-readable
assessment (what it means + recommended action) that gets folded into the Discord alert.

SAFETY GUARDRAILS (from the design):
- The LLM ENRICHES every T2 and may RAISE urgency / add "this looks actively bad".
- The LLM may only DOWNGRADE-to-not-ping for LOW-STAKES verdicts with HIGH confidence,
  and NEVER for crown-jewel or real-threat findings — those ALWAYS ping regardless of what
  the LLM says. The LLM's job on those is to EXPLAIN, not to decide whether to alert.
- If the LLM is unavailable/errors, the alert still fires with the raw deterministic reason
  (fail-safe toward alerting — never toward silence).

Uses a local Ollama endpoint (set OLLAMA_URL / OLLAMA_MODEL). Runs on-prem — data never leaves the network.
"""
import os, sys, json, re

HERE = os.path.dirname(os.path.abspath(__file__))

# Local Ollama endpoint (set via OLLAMA_URL)
def _load_env():
    envp = os.path.join(HERE, "..", ".env")
    if os.path.exists(envp):
        for line in open(envp):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
_load_env()
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://YOUR-LLM-HOST:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")

# Verdicts the LLM is NEVER allowed to suppress (always ping; LLM only explains):
NEVER_SUPPRESS = ("threat", )  # sig_class; crown_jewel handled by field check


SYSTEM_PROMPT = (
    "You are a SOC analyst assistant for a home/small-network SOC. You receive ONE security finding "
    "that deterministic rules already flagged as worth alerting on. Your job is NOT to decide whether "
    "to alert — the rules decided that. Your job is to EXPLAIN it clearly and recommend an action.\n"
    "The network is segmented by role (e.g. trusted, guest, IoT), plus a SOC/SIEM host, and "
    "consumer/IoT devices (so lots of benign external chatter is normal).\n"
    "Respond ONLY with a compact JSON object, no markdown, with keys:\n"
    '  "assessment": one or two plain-English sentences on what this likely is and how worried to be,\n'
    '  "action": one short recommended next step for the owner,\n'
    '  "confidence": "low"|"medium"|"high" — your confidence in the assessment,\n'
    '  "likely_benign": true|false — is this probably normal/benign despite the rule flag?\n'
    "Be concise and specific. Do not invent facts not in the finding."
)


def _ask_llm(finding_desc, timeout=60):
    """Call the local Ollama endpoint. Returns parsed dict or None on failure."""
    try:
        import requests
        payload = {"model": OLLAMA_MODEL, "stream": False,
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": finding_desc}]}
        r = requests.post(OLLAMA_URL + "/api/chat", json=payload, timeout=timeout)
        r.raise_for_status()
        content = r.json().get("message", {}).get("content", "")
        # strip any code fences / prose, extract the JSON object
        content = re.sub(r"```(json)?", "", content).strip()
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception as e:
        print(f"[enrich] LLM call failed: {e}", file=sys.stderr)
    return None


def enrich_verdict(v):
    """
    Given a T2 verdict dict from triage_engine.classify(), return an enrichment dict:
      {llm_assessment, llm_action, llm_confidence, suppressed(bool), enrich_ok(bool)}
    NEVER suppresses crown-jewel or real-threat findings. On LLM failure, returns
    enrich_ok=False and the caller still alerts (fail-safe).
    """
    out = {"llm_assessment": None, "llm_action": None, "llm_confidence": None,
           "suppressed": False, "enrich_ok": False}

    desc = (f"Finding: {v.get('direction')} traffic  {v.get('src')} -> {v.get('dst')}\n"
            f"Destination segment: {v.get('dst_seg')}\n"
            f"Signature: {v.get('signature')}\n"
            f"Severity: {v.get('severity')}\n"
            f"Rule reason: {v.get('reason')}\n"
            f"Crown-jewel target: {v.get('crown_jewel') or 'no'}\n"
            f"Signature class: {v.get('sig_class')}")

    r = _ask_llm(desc)
    if not r:
        return out  # enrich_ok stays False -> caller alerts with raw reason (fail-safe)

    out["enrich_ok"] = True
    out["llm_assessment"] = str(r.get("assessment", ""))[:400]
    out["llm_action"] = str(r.get("action", ""))[:200]
    out["llm_confidence"] = r.get("confidence", "unknown")

    # --- GUARDRAIL: decide whether the LLM is ALLOWED to suppress this ping ---
    is_crown = bool(v.get("crown_jewel"))
    is_threat = v.get("sig_class") in NEVER_SUPPRESS
    llm_says_benign = bool(r.get("likely_benign")) and r.get("confidence") == "high"

    if llm_says_benign and not is_crown and not is_threat:
        # low-stakes + LLM highly confident it's benign -> allowed to suppress the PING
        # (still stored in DB; just no Discord). This is the "reduce false pings" path.
        out["suppressed"] = True
    else:
        # crown-jewel / threat / not-high-confidence-benign -> ALWAYS ping, LLM just explains
        out["suppressed"] = False

    return out


def format_alert(v, enrich):
    """Build the Discord message for a T2, with LLM enrichment folded in."""
    head = f"🚨 **[BXB TRIAGE] {v.get('reason')}**"
    body = (f"`{v.get('src')}` → `{v.get('dst')}` ({v.get('dst_seg','?')}) · {v.get('direction')}\n"
            f"Signature: {v.get('signature')}\n"
            f"Tier {v.get('tier')} · {v.get('crown_jewel') or ''}")
    if enrich.get("enrich_ok"):
        body += (f"\n\n**AI assessment** ({enrich.get('llm_confidence')} confidence): "
                 f"{enrich.get('llm_assessment')}"
                 f"\n**Recommended:** {enrich.get('llm_action')}")
    else:
        body += "\n\n_(AI enrichment unavailable — alerting on rule verdict alone)_"
    return head + "\n" + body


if __name__ == "__main__":
    # self-test with a synthetic crown-jewel T2 (requires CT116 reachable)
    test_v = {"direction":"WAN->LAN","src":"203.0.113.66","dst":"192.0.2.10",
              "dst_seg":"Main","signature":"ET SCAN Suspicious SSH probe","severity":2,
              "reason":"traffic TO crown-jewel homesoc (SOC/SIEM + PILA)",
              "crown_jewel":"homesoc (SOC/SIEM + PILA)","sig_class":"other","tier":2}
    print("Testing LLM enrichment against CT116...")
    e = enrich_verdict(test_v)
    print(json.dumps(e, indent=2))
    print("\n--- formatted alert ---")
    print(format_alert(test_v, e))
