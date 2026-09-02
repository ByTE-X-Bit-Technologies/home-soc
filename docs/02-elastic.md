# 02 — Elasticsearch + Kibana (the data layer)

Install the SIEM store and dashboards. Everything else ships its data here. Mind the JVM heap sizing (a too-small heap silently rejects queries — a real failure mode).

> **Status:** command reference — fill/verify the exact commands against a current install when you
> build it (versions and package names drift). The concept and shape below are stable; the commands
> are what to keep current in this repo.
>
> **Why it's shaped this way:** see the flagship post — The Foundation.

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
