# triage — the custom SOC brain

The custom layer that makes the open-source stack *operational*: it cuts the noise, alerts you only
when it matters, hunts beacons, and prioritizes remediation. Seven small Python modules, deterministic
core + optional local-AI enrichment.

Read the [architecture series](#) for the *why* behind every design decision here.

## The modules

| Module | Job |
|---|---|
| `triage_engine.py` | deterministic classifier — turns a finding into a tier (dismiss / review / elevate) using topology + signature + crown-jewel logic. No AI; auditable rules. |
| `triage_runner.py` | pulls new findings on a schedule, classifies each, routes to sinks (audit / review queue / alert / dashboard). |
| `triage_enrich.py` | local-LLM enrichment — writes a plain-language "what/how-worried/what-to-do" briefing for elevated alerts. Guardrailed: can raise concern, never silences a crown-jewel/threat alert. |
| `triage_beacon.py` | statistical beacon/C2 detection over Zeek connection logs (coefficient-of-variation on timing + size). |
| `triage_watchdog.py` | dead-man's-switch — alerts if the runner itself stops (silence ≠ safe). |
| `triage_dashboard.py` | pushes tier-1/2 findings into your review dashboard. |
| `triage_remediation.py` | CISA-KEV-ranked remediation reports from Wazuh vuln data. |

## How the system runs (the full picture)

The seven modules form one pipeline. Data flows in from your open-source sensors and out to you only
when something earns your attention:

```
  Sensors (Suricata / Zeek / Wazuh)  →  Elasticsearch
                                              │
                                    triage_runner (every 15m)
                                              │  pulls new findings
                                     triage_engine.classify()
                                     (topology + signature → tier)
                    ┌─────────────────────────┼───────────────────────────┐
                  Tier 0                     Tier 1                       Tier 2
                auto-dismiss            review queue                   ELEVATE
               (audit row,            (dashboard card,          triage_enrich (local LLM)
                never shown)           never pings)              writes assessment + action
                                            │                          │  guardrailed
                                     triage_dashboard  ←───────────────┤  (never silences a
                                     (feedback loop:                    │   crown-jewel/threat)
                                      mark FALSE POSITIVE                │
                                      → suppressed next time)       real-time alert (chat)

  triage_beacon (scheduled)  →  scans Zeek conn logs for C2-style regularity → feeds findings in
  triage_remediation (weekly) →  Wazuh vulns × CISA KEV → ranked "patch this first" report
  triage_watchdog (every 15m, offset) →  watches the runner's heartbeat; alerts if it goes silent
```

**The principle:** you are hands-off unless something is genuinely wrong. Tier 0 (the overwhelming
majority) is handled silently. Only Tier 2 is allowed to interrupt you — and when it does, the LLM has
already written you a plain-English briefing. If the whole thing goes quiet, the watchdog tells you —
because silence must never be mistaken for "all clear."

## Scheduling (cron)

The system is designed to run unattended on a schedule. An example crontab (adjust paths to your
install):

```cron
# Triage runner — pull, classify, route. Every 15 minutes.
*/15 * * * * cd /path/to/triage && /usr/bin/python3 triage_runner.py >> triage.log 2>&1

# Watchdog — dead-man's-switch. Every 15 min, OFFSET from the runner so it checks between runs.
7,22,37,52 * * * * cd /path/to/triage && /usr/bin/python3 triage_watchdog.py >> watchdog.log 2>&1

# Remediation report — Wazuh vulns × CISA KEV, ranked. Weekly (Monday 6am).
0 6 * * 1 cd /path/to/triage && /usr/bin/python3 triage_remediation.py >> remediation.log 2>&1

# Beacon scan — statistical C2 detection over Zeek conn logs. Daily is plenty.
30 5 * * * cd /path/to/triage && /usr/bin/python3 triage_beacon.py >> beacon.log 2>&1
```

The watchdog runs **independently** of the runner (its own cron line) on purpose: if they shared a
process and it died, they'd both go silent together. Separate schedules mean the watchdog survives the
runner's failure and can report it.

## First-run sequence (do this in order)

1. **Configure** — `cp config.example.yaml config.yaml`, fill in your segments, crown-jewels, data
   sources. Set secrets as env vars / the webhook file (see Setup above).
2. **Dry-run** — `python3 triage_runner.py --dry-run`. It classifies and reports but writes and sends
   nothing. Look at the tier distribution: on a normal network it should be overwhelmingly Tier 0, a
   little Tier 1, and few/zero Tier 2. If it's wildly off, tune the noise list and thresholds first.
3. **Real run, alerting still off** — run it for real so it populates the review queue/dashboard, but
   keep `ENABLE_DISCORD`/alerting off until you've watched the classifications look right on *your*
   network for a bit.
4. **Enable alerting** — only once you trust the Tier-2 calls. Now its first real ping is a real
   finding, not a miscalibration.
5. **Schedule everything** — add the cron lines above. Confirm the watchdog fires (you can simulate a
   stale runner to test it).

## Each module ↔ the architecture series

If you want the *why* behind any piece, the flagship series covers it:

| Module | Post |
|---|---|
| `triage_engine.py` | Building an AI SOC Analyst From Scratch (deterministic-first design) |
| `triage_runner.py` + `triage_dashboard.py` | Making Alerts Actionable (tiering, the feedback loop) |
| `triage_beacon.py` | Hunting C2 — Beacon Detection with Statistics and Zeek |
| `triage_enrich.py` | Making Alerts Actionable (LLM enrichment + guardrails) |
| `triage_remediation.py` | Remediation That Prioritizes What's Actually Being Exploited |
| `triage_watchdog.py` | Who Watches the Watcher? Self-Monitoring |

## Setup

1. **Configure it for your network.** Copy the example config and edit it:
   ```bash
   cp config.example.yaml config.yaml
   # edit config.yaml: your segments, crown-jewels, data sources, LLM endpoint, webhook
   ```
   Everything network-specific lives in `config.yaml`. Nothing real is hardcoded in the modules.

2. **Set your secrets as environment variables** (never commit them):
   ```bash
   export ELASTIC_PASS='...'
   export WAZUH_PASS='...'
   # put your alert webhook URL in the file named by alerting.webhook_file (e.g. .webhook)
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional, Tier 2+) Set up the local LLM** for enrichment — install Ollama on your GPU host and
   pull a model that fits your card (a 12 GB GPU comfortably runs a 14B model). Point `llm.primary_url`
   at it. Skip this at Tier 1 and the deterministic layer still runs.

## Running it

- **Test first (read-only):**
  ```bash
  python triage_runner.py --dry-run   # classifies + reports, writes/sends nothing
  ```
- **Real run:**
  ```bash
  python triage_runner.py
  ```
- **Schedule it** (cron — every 15 min for the runner, offset for the watchdog, weekly for
  remediation). Example crontab is in [../docs/07-triage-deploy.md](../docs/07-triage-deploy.md).

## Safety notes

- The runner ships with `enable_discord`/alerting gated so you can watch it classify before it can
  ping you. Turn alerting on only after you've confirmed the classifications look right on your
  network.
- The watchdog is not optional in spirit — an unattended SOC needs something watching *it*. Schedule
  it independently of the runner.
- **Tuning is the real work.** The shipped thresholds are home defaults. The noise on *your* network
  is different; expect to extend `extra_noise_signatures` and adjust as you learn what's normal. This
  is exactly the tuning that, at organizational scale, is the professional engagement.

## License

MIT. Free to use and adapt. If you want this built, tuned, and operated for an organization,
[that's what BXB does](https://byte-x-bit.com).
