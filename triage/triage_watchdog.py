#!/usr/bin/env python3
"""
BXB Triage Watchdog — dead-man's-switch.
Runs INDEPENDENTLY of the triage runner (separate cron). Checks that the triage
runner has executed recently (via the watermark file's mtime + a heartbeat file).
If it's gone silent (no run in STALE_MINUTES), sends a Discord alert — because
silence must NEVER look like "all clear" (the SOC-docs lesson).

Also self-heartbeats so we can tell "watchdog alive" from "watchdog also dead".
"""
import os, sys, time, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
WATERMARK = os.path.join(HERE, ".triage_heartbeat")  # runner heartbeat (updated every run)
HEARTBEAT = os.path.join(HERE, ".watchdog_heartbeat")
WEBHOOK_FILE = os.path.join(HERE, ".webhook_digest")
ALERT_STATE = os.path.join(HERE, ".watchdog_alerted")  # so we don't spam every 15 min while down

STALE_MINUTES = 50   # triage runs every 15m; 50m = ~3 missed cycles = genuinely stuck


def _send(msg):
    try:
        import requests
        url = open(WEBHOOK_FILE).read().strip()
        requests.post(url, json={"content": msg}, timeout=15)
        return True
    except Exception as e:
        print(f"[watchdog] discord send failed: {e}", file=sys.stderr)
        return False


def main():
    now = time.time()
    # write our own heartbeat (proves the watchdog itself is running)
    open(HEARTBEAT, "w").write(datetime.datetime.utcnow().isoformat())

    if not os.path.exists(WATERMARK):
        # runner has never run — that's a problem if the system's supposed to be live
        if not os.path.exists(ALERT_STATE):
            _send("⚠️ **[BXB WATCHDOG] Triage runner has NEVER run** — no watermark file. "
                  "Monitoring may be OFFLINE. Check the triage cron on your SOC host.")
            open(ALERT_STATE, "w").write(str(now))
        return

    age_min = (now - os.path.getmtime(WATERMARK)) / 60.0

    if age_min > STALE_MINUTES:
        # runner is stuck/dead — alert ONCE (state file prevents spam), re-alert cleared on recovery
        if not os.path.exists(ALERT_STATE):
            _send(f"🚨 **[BXB WATCHDOG] Triage runner is DOWN** — last run {age_min:.0f} min ago "
                  f"(expected every 15m). **Security monitoring is OFFLINE.** "
                  f"Check `triage.log` + the runner cron on your SOC host.")
            open(ALERT_STATE, "w").write(str(now))
            print(f"[watchdog] ALERT sent — runner stale {age_min:.0f}m")
        else:
            print(f"[watchdog] runner still stale {age_min:.0f}m (already alerted)")
    else:
        # healthy — clear any prior alert state and send a recovery note if we HAD alerted
        if os.path.exists(ALERT_STATE):
            _send(f"✅ **[BXB WATCHDOG] Triage runner RECOVERED** — running again "
                  f"(last run {age_min:.0f} min ago). Monitoring back online.")
            os.remove(ALERT_STATE)
            print(f"[watchdog] recovery — runner healthy again ({age_min:.0f}m)")
        else:
            print(f"[watchdog] OK — runner ran {age_min:.0f}m ago")


if __name__ == "__main__":
    main()
