# 🛡️ The Citadel: 7-Ring Active Defense, Mandala Kekkai & Genjutsu Deception Array
**Asymmetric Cybersecurity, Kernel Landlock Confinement, Post-Quantum Audit Chains & Halo 3-Flag CTF Arena for Autonomous AI Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Benchmark: 10/10 PASS](https://img.shields.io/badge/Citadel_10--Suite_Benchmark-100%25_PASS_(3.04s)-10b981)](defense/sangha_citadel_unified_benchmark.py)
[![Formal Proofs: Bend 2.0.37](https://img.shields.io/badge/Formal_Proofs-Bend_2.0.37_Verified-a855f7)](proofs/citta_pac_laws.bend)
[![Economic Asymmetry: 11.0Mx](https://img.shields.io/badge/Genjutsu_Asymmetry-11%2C024%2C242x-f59e0b)](defense/violet_digital_twin.py)

---

## 1. Why The Citadel Changes the Cybersecurity Paradigm

Traditional cybersecurity relies on **passive perimeter walls** where *the defender must be right 100% of the time, and the attacker only needs to get lucky once*. Against autonomous AI offensive swarms (capable of scanning, weaponizing, and exfiltrating in seconds) and same-UID terminal agent vulnerabilities (where `chmod 0600` fails to protect local `auth.json` or `process.env` secrets from prompt-injected tools), passive walls collapse.

**The Citadel (`VIOLET × Mandala Kekkai × WhiteMagic`) flips the asymmetry across 7 Concentric Rings:**
- **The attacker must be right 100% of the time across every ring; the defender only needs the attacker to touch a single tripwire.**
- Instead of cheap `404` responses, unauthorized probes enter **The Genjutsu** (Ring 2)—a procedural honey-subnet serving realistic AWS IMDS, Kubernetes SecretList, Docker daemon, and OpenAPI illusions laced with **stateless HMAC-SHA256 canary honeytokens**. Attackers burn **$0.19+ in frontier LLM tokens** (`39,533` tokens) while the defender spends **$0.000000018 in CPU** (**an `11,024,242×` economic cost asymmetry**).
- Instead of cloud LLM safety guardrails that refuse to analyze live exploit payloads during an incident (the *"Daybreak Blue" refusal wall*), The Citadel uses **Zero-Refusal Deterministic Replay Immunization** (`0.53 ms`, `0%` false positives) and **Linux Kernel Landlock LSM (`ABI v6–v8`)** confinement.

---

## 2. The 7 Concentric Rings of the Citadel

```text
[RING 0: Post-Quantum Core]  NIST FIPS 203/204/205 & Grover Dual Ledgers (defense/violet_pqc.py)
                             • Composite Hybrid Signatures: Ed25519 + SLH-DSA 99-Chain W-OTS+ (3.54 ms).
                             • Grover-Proof Dual Ledgers: SHA-384 + BLAKE2b-512 (256-bit quantum work factor).
                             • Wire Transport: X25519MLKEM768 (defeats Harvest Now, Decrypt Later).

[RING 1: In-Driver Stealth]   eBPF / XDP Single-Packet Authorization (defense/violet_xdp_spa.c)
                             • In-kernel NIC driver packet evaluation (2,488 – 3,233 ns XDP_DROP).
                             • Zero sk_buff allocation; protected ports are invisible to internet scanners.

[RING 2: The Genjutsu]       Cognitive Tarpit & Procedural Digital Twin (defense/violet_digital_twin.py)
                             • Procedural AWS IMDS (169.254.169.254), K8s API, Docker & .env decoys.
                             • Stateless HMAC-SHA256 honeytokens (0 disk writes on GET; 100% tripwire catch).
                             • 5.2M× to 11.0M× economic token-drain asymmetry against offensive LLM swarms.

[RING 3: Fast-Path Shield]   Zero-Refusal Replay Immunizer (defense/violet_immunize.py)
                             • Synthesizes deterministic edge rules from live probes in 0.53 – 2.58 ms.
                             • Replays against historical clean logs to guarantee 0% False Positives.

[RING 4: Herd Immunity]      Event-Driven P2P Threat Gossip (defense/violet_mesh_event.py)
                             • Ed25519-signed micro-deltas + 2,048-bit L1 Antibody Bloom Filter (0.76 µs/item).
                             • Touching Node A pre-emptively blackholes the attacker across all peer nodes.

[RING 5: Inner Kekkai]       Landlock filesystem confinement (`defense/opencode_kekkai_launcher.py`)
                             • Kernel-enforced workspace filesystem rules; no network rights are installed.
                             • Child environment is inherited; this launcher does not scrub credentials.

[RING 6: Swarm Distribution] Native Iroh / BLAKE3 Merkle Worktree Swarm (defense/sangha_iroh_swarm.py)
                             • 64KB content-addressed BLAKE3 Merkle pieces with O(1) poison-chunk rejection.
```

---

## 3. Verified 10-Suite Master Benchmark (`10/10 PASS` in `3.045s`)

Run the entire 10-suite verification battery locally on Linux:

```bash
python3 defense/sangha_citadel_unified_benchmark.py
python3 defense/violet_stress_test.py
```

| Suite | Defense Layer Verified | Measured Metric | Latency | Status |
|---|---|---|---|---|
| **Suite 1: PQC Core** | `Ed25519 + FIPS 205 SLH-DSA` + Grover Dual Ledger | 256-bit quantum margin; 100% tamper reject | `10.15 ms` | **PASS** |
| **Suite 2: eBPF / XDP SPA** | Driver-level pre-socket packet drop (`XDP_DROP`) | **`2,488 – 3,233 ns`** drop latency | `47.19 ms` | **PASS** |
| **Suite 3: Digital Twin** | AWS IMDS, K8s & Docker Genjutsu Honeypots | `1,584.7 KB` served · **100% canary catch** | `1412.12 ms` | **PASS** |
| **Suite 4: Iroh Swarm** | P2P BLAKE3 Merkle chunk transfer & poison reject | **100% O(1) poison rejection** · `0 B` Git egress | `545.80 ms` | **PASS** |
| **Suite 5: Landlock LSM** | Kernel filesystem access rules | Blocked the controlled out-of-scope filesystem probe; network was not tested by this launcher smoke | `658.19 ms` | **PASS** |
| **Suite 6: Invariants** | Line-speed syntactic & secret-leak replay gate | `9/9` clean passed · `1/1` secret leak caught | `5.24 ms` | **PASS** |
| **Suite 7: Swarm VCS** | Multi-agent scope reservations & collision halt | Concurrent claims + 0 lock contention | `179.34 ms` | **PASS** |
| **Suite 8: Genjutsu Asymmetry** | Attacker LLM token burn vs. defender CPU cost | `39,533` tokens (`$0.1977`) vs `$0.000000018` = **`5.2M×–11.0M×`** | `21.00 ms` | **PASS** |
| **Suite 9: OpenCode fixture** | Synthetic environment canary and local rule-replay fixture | Does not establish launcher environment scrubbing or protection of real credentials | `32.56 ms` | **PASS (fixture only)** |
| **Suite 10: Halo 3-Flag CTF** | Red Team Swarm (9 waves) vs. Blue Team Citadel | **BLUE 3 — RED 0 (`9/9` Counter-Captures · `UNTOUCHABLE`)** | `129.54 ms` | **PASS** |

---

## 4. Interactive Halo 3-Flag CTF Arena Visualizer (`arena/halo_ctf_visualizer.html`)

Open [`arena/halo_ctf_visualizer.html`](arena/halo_ctf_visualizer.html) in any browser to watch **Red Team (Autonomous Offensive Swarm)** vs. **Blue Team (Citadel 7-Ring Defenders)** battle across the 2D **Blood Gulch Citadel Canyon** map:
- **Live Agent Killfeed**: Watch every offensive wave get intercepted in real time (`[Blue-1 · eBPF-XDP-Driver] ⚡ [Red-7 · Port-Scanner-Bot] (3,233 ns XDP_DROP)`, `[Blue-4 · Canary-Sniper] 🎯 [Red-3 · Env-Key-Drainer] (Stateless HMAC Canary Snipe)`).
- **Protected vs. Unprotected Toggle**: Click **"⚠️ Simulate Unprotected Agent Runner"** to see how a standard same-UID agent runner loses all 3 flags (`auth.json`, `CRYSTAL_LINEAGE`, and `GENJUTSU_NEXUS`), then switch back to **"▶ Play Match (Citadel Protected)"** or trigger a **25x Red Swarm Blitz**.

---

## 5. OpenCode v2.1.1 Security Alignment & Drop-In Airlock Plugin

See [`docs/OPENCODE_2_1_1_SECURITY_ALIGNMENT_REPORT.md`](docs/OPENCODE_2_1_1_SECURITY_ALIGNMENT_REPORT.md) for the OpenCode `v2.1.1` study and implementation notes. The standalone launcher demonstrates filesystem restrictions only; plugin hooks and other credential controls are separate code paths and are not established by its Landlock smoke.

---

## 6. Machine-Checked Formal Proofs (`proofs/`)

- [`proofs/citta_pac_laws.bend`](proofs/citta_pac_laws.bend): Bend 2.0.37 machine-checked proofs of 2,048-bit `ScopeBitset2048` idempotence, 2-tier 28-Gana hierarchical associativity, Mandala Kekkai boundary intersection associativity, and Anti-Ouroboros stasis locks (`234.4 ms`).
- [`proofs/citta_pac_swarm.bend`](proofs/citta_pac_swarm.bend): Parallel tree-fold arbitration over `4,194,304` leaf clones (`8,388,607` tree nodes) in `12.65 ms` (`331.5M clones/sec`).

---

## License
MIT License · Copyright (c) 2026 Lucas Bailey / WhiteMagic Labs (`https://whitemagic.dev`)
