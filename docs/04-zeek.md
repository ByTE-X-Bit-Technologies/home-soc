# 04 — Zeek (network flight recorder)

Install Zeek, configure capture on the mirror interface, and ship conn/dns/ssl/http logs to Elasticsearch. Harden it to survive reboots and auto-restart — a silently-dead Zeek takes a whole category of detection down with it.

> **Status:** command reference — fill/verify the exact commands against a current install when you
> build it (versions and package names drift). The concept and shape below are stable; the commands
> are what to keep current in this repo.
>
> **Why it's shaped this way:** see the flagship post — The Foundation / Beacon Detection.

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
