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
