# 00 — Requirements: Pick Your Tier

The single biggest myth about home SOCs is that you need serious hardware. You don't. The architecture
scales down cleanly. Pick a tier and start where you are — **hardware is a dial, not a gate.**

## The three tiers

| | **Tier 1 — Start here** | **Tier 2 — Sweet spot** | **Tier 3 — Reference (overkill)** |
|---|---|---|---|
| **Goal** | Learn the concepts, real detection on a small network | The full system, running well, 24/7 | Transparency, not a target |
| **Machine** | 1 box (old desktop / mini-PC / spare laptop) | Dedicated hypervisor host | Multiple hypervisor hosts |
| **CPU** | ~4 cores | 8+ cores | many cores |
| **RAM** | 16 GB | 32–64 GB | 128 GB-class |
| **Storage** | 256 GB+ SSD | 1 TB NVMe | multiple TB |
| **GPU** | none (AI layer optional/slow) | **used RTX 3060 12 GB** — the key upgrade | dedicated GPU(s) |
| **Platform** | VirtualBox is fine | Proxmox | Proxmox |
| **Stack** | slimmed, single-node, one host | each component its own VM/container | full multi-VLAN + pentest range |
| **AI triage** | CPU-only (slow) or skip it | fast on the GPU | fast |
| **Cost** | $0 (spare) – ~$200 (used mini-PC) | ~$800–1,500 used | more than you need |

## Which tier should you pick?

- **Just exploring?** Tier 1. A single machine with 16 GB RAM runs a real, working SOC. The
  deterministic triage layer works great on CPU; the AI enrichment is the only thing that wants a GPU,
  and you can skip it at this tier and still have something genuinely useful.
- **Serious about running it 24/7?** Tier 2. This is the recommended target. The one upgrade that
  matters most is a **used RTX 3060 (12 GB)** — it turns local AI triage from "too slow to bother"
  into "answers in a couple of seconds." If you do one thing beyond Tier 1, do that.
- **Tier 3 is what the author runs** — and it's overkill, stated plainly. The same hardware does
  double duty for other work. You do not need it. Everything in this guide works at Tier 1.

## The GPU question (Tier 2+)

The AI enrichment layer runs a language model **locally** — your security data never leaves your
network. That's the right design for a SOC, but it means the model runs on your hardware:

- **No GPU:** the model runs on CPU. It works, but it's slow (many seconds to minutes per query) —
  fine for occasional use, impractical for high-volume triage. The *deterministic* layer (which does
  ~99% of the work) doesn't need a GPU at all.
- **A modest GPU (used RTX 3060 12 GB or similar):** local inference drops to a couple of seconds.
  This is the single best price/performance upgrade for the whole build. A 12 GB card comfortably runs
  a capable mid-size model.

## Network prerequisites

Regardless of tier, you'll want:

- **A VLAN-capable router or firewall** — pfSense, OPNsense, or a prosumer platform like UniFi.
  This lets you segment your network by role (covered in step 1), which the detection logic depends
  on. *(Tier 1 exception: you can start on a flat network and segment later — don't let this block
  you.)*
- **A way to mirror traffic to your sensors** — a SPAN/mirror port on a managed switch, your
  firewall's mirroring feature, or (in a virtualized setup) a promiscuous-mode interface on a bridge.
  Covered in step 1.

## Software prerequisites

- Comfort with a Linux command line — not expert-level, but you should be able to run commands and
  read output. This guide gives you the exact commands.
- Patience. You're building a real system; it won't all work on the first try, and that's part of the
  learning.

---

**Next:** [01-platform-proxmox.md](01-platform-proxmox.md) or
[01-platform-virtualbox.md](01-platform-virtualbox.md) — stand up the platform and design the network.
