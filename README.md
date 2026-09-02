# home-soc

**A real, enterprise-grade Security Operations Center you can build on a home network — from
open-source foundations and a custom AI triage layer.**

This repo is the hands-on companion to a two-part blog series:

- **[Building an Enterprise-Grade SOC at Home](#)** (the *architecture* — the why)
- **[Home SOC: The Build](#)** (the *step-by-step* — the how)

Everything here is free and open source (MIT). It's the home-network-tuned version of the detection,
triage, and remediation systems I build professionally at [ByTE X Bit Technologies](https://byte-x-bit.com).
If you want an enterprise-grade version designed, deployed, and tuned for your organization —
[that's what BXB does](https://byte-x-bit.com).

---

## What this is

A complete home SOC stack:

| Layer | Tool | Job |
|---|---|---|
| Network IDS | **Suricata** | signature-based alerts on known-bad traffic |
| Network flow | **Zeek** | logs every connection / DNS / TLS / HTTP as structured data |
| Endpoint + vuln | **Wazuh** | host agent, file integrity, vulnerability detection |
| Traffic view | **ntopng** | live human-readable traffic visibility |
| Data layer | **Elasticsearch + Kibana** | store, index, search, dashboard everything |
| **The brain** | **`triage/` (this repo)** | custom deterministic-plus-AI triage: cuts the noise, alerts only when it matters, prioritizes remediation |

The open-source tools do detection. The `triage/` code — the part that makes it *operational* — is
the custom layer this project adds on top.

## Start here

1. **Read [docs/00-requirements.md](docs/00-requirements.md)** — pick your hardware tier (it scales
   from a single 16 GB mini-PC to a dedicated hypervisor). Hardware is a dial, not a gate.
2. **Follow the build docs in order** (below). Each corresponds to a post in the build series.
3. **Deploy the triage engine** ([docs/07-triage-deploy.md](docs/07-triage-deploy.md)) and configure
   it for *your* network via `triage/config.example.yaml`.

## Build order

| Step | Doc | What it sets up |
|---|---|---|
| 0 | [00-requirements.md](docs/00-requirements.md) | tiered specs, platform choice, prerequisites |
| 1 | [01-platform-proxmox.md](docs/01-platform-proxmox.md) · [01-platform-virtualbox.md](docs/01-platform-virtualbox.md) | hypervisor, VLAN segments, SPAN/mirror |
| 2 | [02-elastic.md](docs/02-elastic.md) | Elasticsearch + Kibana (the data layer) |
| 3 | [03-suricata.md](docs/03-suricata.md) | Suricata IDS → ships to Elasticsearch |
| 4 | [04-zeek.md](docs/04-zeek.md) | Zeek connection/flow logging → Elasticsearch |
| 5 | [05-wazuh.md](docs/05-wazuh.md) | Wazuh manager + agents + vulnerability detection |
| 6 | [06-ntopng.md](docs/06-ntopng.md) | ntopng traffic visibility |
| 7 | [07-triage-deploy.md](docs/07-triage-deploy.md) | deploy + configure the triage engine (the AI layer) |

## The triage engine (`triage/`)

The custom part. Seven small Python modules:

- `triage_engine.py` — the deterministic classifier (topology + signature → tier)
- `triage_runner.py` — pulls findings on a schedule, classifies, routes to sinks
- `triage_enrich.py` — local-LLM enrichment of elevated alerts
- `triage_beacon.py` — statistical beacon / C2 detection over Zeek data
- `triage_watchdog.py` — dead-man's-switch (alerts if the monitoring itself dies)
- `triage_dashboard.py` — pushes findings into a review dashboard
- `triage_remediation.py` — CISA-KEV-ranked remediation reports

**You configure it for your own network** in `triage/config.example.yaml` (copy to `config.yaml`) —
your crown-jewel assets, your segments, your alert webhook, your LLM endpoint. Nothing about any real
network is hardcoded. See [triage/README.md](triage/README.md).

## A note on scope

This is the *home-tuned* version — the thresholds, the noise filters, and the crown-jewel logic are
calibrated for a home network. On a production network with different scale, assets, and threat
model, it needs real tuning. That tuning — and the detection engineering, deployment, and operational
discipline behind it — is the professional work. The code is free; doing it right for an organization
is [what BXB does](https://byte-x-bit.com).

## License

MIT — see [LICENSE](LICENSE). Use it, learn from it, build on it.

## Contributing / feedback

Built your own version? Hit a snag? Improved something? Open an issue or PR — genuinely interested in
how it goes on other people's networks.
