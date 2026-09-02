# Triage modules — coming soon

The seven triage modules (`triage_engine.py`, `triage_runner.py`, `triage_enrich.py`,
`triage_beacon.py`, `triage_watchdog.py`, `triage_dashboard.py`, `triage_remediation.py`) are being
finalized for public release — refactored to be fully config-driven (everything network-specific
reads from `config.yaml`; nothing hardcoded).

In the meantime:
- The **architecture and logic** are fully documented in the blog series
  ([Building an Enterprise-Grade SOC at Home](https://byte-x-bit.com/#resources)).
- **`config.example.yaml`** shows exactly how the engine is configured for a network.
- The **[triage/README.md](README.md)** explains each module's job, the setup, and how to run it.

Star/watch the repo to be notified when the code lands. Building your own version from the blog
series? Open an issue — genuinely interested in how it goes.
