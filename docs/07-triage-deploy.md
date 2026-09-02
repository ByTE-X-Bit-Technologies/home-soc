# 07 — Deploy the Triage Engine

Clone/copy the triage/ code, configure config.yaml for YOUR network, set up the local LLM (optional at Tier 1), schedule the runner + watchdog + remediation report, and wire the dashboard. This is where the open-source stack becomes an operational SOC.

> **Status:** command reference — fill/verify the exact commands against a current install when you
> build it (versions and package names drift). The concept and shape below are stable; the commands
> are what to keep current in this repo.
>
> **Why it's shaped this way:** see the flagship post — Building an AI SOC Analyst / Actionable Alerts / Remediation / Self-Monitoring.

## Concept

_(This doc holds the exact, current commands for this step. The blog post explains the why; this is
the how. Sections to fill:)_

- Prerequisites (what must be done first)
- Install
- Configuration
- Point it at the data / mirror / segments as needed
- Verify it's working (the check that proves this step succeeded)
- Ship its output to Elasticsearch (where applicable)

## Verify

_(The single command/check that confirms this step works before moving on. Every step should end with
a "you'll know it worked when…" so the reader never builds on a broken foundation.)_

---
**Next:** see the build order in the [repo README](../README.md).
