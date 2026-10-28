# The Citadel

Experimental security tools for agent workflows: Linux confinement, environment
filtering, signed single-packet authorization, decoy services, receipt tooling,
and small Bend algebraic examples. Code is MIT licensed.

Start with [audit scope and evidence boundaries](docs/AUDIT_SCOPE.md). The old
[practice audit report](docs/PRACTICE_AUDIT_REPORT.md) is withdrawn as an assurance
claim. No independent security audit or production qualification is established
by this repository's internal checks.

## What each part currently demonstrates

| Area | Artifact | Evidence boundary |
|---|---|---|
| Signature experiments | `defense/violet_pqc.py` | Ed25519 plus custom hash-chain code. This is not a complete SLH-DSA implementation, a FIPS conformance claim, or a measured quantum-security margin. |
| Single-packet authorization | `defense/violet_spa.py`, `defense/violet_xdp_spa.py`, `defense/violet_xdp_spa.c` | The Python benchmark exercises signed knocks, replay/tamper cases, and a Python packet-table simulation. Compiling a BPF ELF does not load it into a kernel. Its Python timings are not NIC/driver drop latency. |
| Proof-of-work puzzle gate | `defense/violet_pow_gate.py` | Stateless HMAC-SHA256 client puzzle generator and O(1) verifier. Imposes asymmetric compute barrier against automated crawlers and brute-force worms. Solvers run locally in unit tests and benchmarks. |
| Web3 sweeper gas-trap | `defense/violet_gas_trap.py` | Deceptive zero-native-gas honeypot wallet and front-running simulation. Dual-hash forensic ledger of captured attacker gas. Simulates mempool counter-drains under controlled conditions. |
| Comprehensive benchmark | `defense/citadel_comprehensive_benchmark.py` | Six-track micro-benchmark of PoW gates, LLM token sponges, canary minting/verification, Web3 traps, flytrap taxonomy, and SPA knock generation. Metrics reflect local host throughput. |
| Theory & architecture | `docs/CITADEL_THEORY_AND_ARCHITECTURE.md` | Comprehensive theoretical foundation and operational blueprint detailing biomimetic defense, counter-economics, and line-rate hardware defenses. |
| Decoys and canaries | `defense/violet_digital_twin.py` | Controlled decoy and token-detection exercises. Detection rates apply to the supplied cases. The historical economic ratio used assumed token and CPU prices; it is not evidence of adversaries' real costs or general defensive advantage. |
| Replay filters | `defense/violet_immunize.py` | Deterministic rule generation and replay against a finite corpus. No general zero-false-positive guarantee follows. |
| Peer notifications and chunks | `defense/violet_mesh_event.py`, `defense/sangha_iroh_swarm.py` | Local protocol and chunk-integrity exercises. They do not establish independent multi-host coordination or a deployed network's behavior. |
| Confinement and airlock | `defense/mandala_kekkai.py`, `defense/sangha_kekkai.py`, `plugins/opencode-citadel-airlock.js` | Experimental filesystem/network restrictions and environment filtering. Qualification requires actual kernel/support identity, readable and writable positive controls, denied negative controls, subprocess startup evidence, and precise runtime integration. |
| Algebraic examples | `proofs/citta_pac_laws.bend` | Nine Bool/Nat lemmas. These do not prove implementation-level capability attenuation, anti-rollback correctness, safe fallback, or model-weight behavior. |
| Synthetic folds | `proofs/citta_pac_swarm.bend`, `proofs/cpr_batch.bend` | Fixed-depth U32 arithmetic tree folds. Leaves are not running agents or cryptographically verified receipts. |

The seven-ring arrangement is a design organization. It does not mean an
attacker must defeat every component or that touching one decoy prevents an
attack. Source modules may retain historical names; use the boundaries above
when interpreting those names and older reports.

## Reproduce a bounded check

Requirements: Python 3.10+ and a compatible Bend compiler on `PATH` (the current
local reproduction used Bend 2.0.39). The report command does not import the
product modules, read personal keys, or mutate a personal WhiteMagic store.
Select an output directory outside this checkout to keep your working tree clean:

```bash
python3 defense/practice_audit_battery.py --checks bend --output-dir /tmp/citadel-internal-checks
python3 -m unittest discover -s defense -p test_practice_audit_reporting.py -v
```

To run the Citadel Comprehensive Benchmark across all defense and counter-economic tracks:

```bash
python3 defense/citadel_comprehensive_benchmark.py
python3 -m pytest -v defense/test_citadel_benchmark.py defense/test_pow_gate.py defense/test_gas_trap.py
```

With `cryptography` installed, `python3 -m unittest discover -s defense -p
test_pqc_claim_boundaries.py -v` also checks experimental output disclosures,
an isolated signature/tamper fixture, and failure exit status. It uses temporary
fixture keys and does not qualify the custom construction for security use.

The Bend selection runs both the front-end check and the separate `--verdict`
kernel recheck. The latter needs the kernel dependencies reported by Bend
(the local tool requests Lean 4.34.0 or a built `BENDTT` kernel). Missing kernel
infrastructure is `NOT_EVALUATED`, even if the front-end checker succeeds.

The paired JSON/Markdown reports record compiler and source hashes, command
outputs, process wall times, and synthetic leaves per second calculated from
the same measurement. Wall time includes compiler checking and startup.
`PASS` applies to the selected checks only; unsupported lanes remain
`NOT_EVALUATED` with reasons.

Exit status is `0` when all selected checks pass, `1` for an actual failed check,
and `2` when selected checks cannot be evaluated. Missing engines, matching
crashes, empty output, and malformed verifier results cannot create parity.

For a separate CPR agreement check, first build the Python/Rust/JavaScript
verifiers according to the selected CPR checkout's own instructions, then pass
its exact location explicitly:

```bash
python3 defense/practice_audit_battery.py --checks differential --cpr-dir /path/to/continuity-receipt --output-dir /tmp/citadel-cpr-agreement
```

This checks the three bundle manifests, honors their anchor options, and
compares verdicts and error codes against each other and the declared expected
outcomes. Manifests themselves are not counted as receipt fixtures.
Agreement between three implementations maintained in the same project is
useful consistency evidence; an independent oracle and source-to-binary build
provenance still need separate evidence.

## Standalone launcher smoke

`defense/opencode_kekkai_launcher.py` uses Python's standard library. The
Linux backend needs x86_64 or arm64 and a kernel exposing Landlock; unsupported
hosts fail before spawning the child. Run a harmless owned-workspace fixture
with a deliberately minimal environment:

```sh
scratch=$(mktemp -d) || exit 1
workspace="$scratch/workspace"
mkdir "$scratch/home" "$workspace"
printf '%s\n' 'owned launcher fixture' > "$workspace/probe.txt"
env -i PATH=/usr/bin:/bin HOME="$scratch/home" python3 \
  defense/opencode_kekkai_launcher.py --workspace "$workspace" -- \
  /usr/bin/cat "$workspace/probe.txt"
rm -r -- "$scratch"
```

The launcher installs filesystem restrictions only. It inherits the child
environment and leaves networking unrestricted; it does not scrub credentials
or establish an OpenCode/Devin client integration. The fixture above only
checks child startup and an allowed read. Use the separate confinement
positive/negative controls before making a containment claim. macOS has a
separate Seatbelt path; this Linux fixture does not qualify it.

## Demonstrations and integration work

[`arena/halo_ctf_visualizer.html`](arena/halo_ctf_visualizer.html) is an illustrative
animation. Its scripted scores, killfeed, and timing labels are not live
red-team telemetry. The legacy master benchmark and escape/mutation scripts
also need review before their printed success labels can serve as acceptance
criteria; see [the open review list](docs/AUDIT_SCOPE.md).

[`docs/OPENCODE_2_1_1_SECURITY_ALIGNMENT_REPORT.md`](docs/OPENCODE_2_1_1_SECURITY_ALIGNMENT_REPORT.md)
is a maintainer-authored study of a named historical version. The plugin and
launcher need qualification against the exact host/runtime being used. Installing
an environment filter alone does not establish protection of credentials,
transcripts, or every execution path.

## License

[MIT](LICENSE) · Copyright (c) 2026 Lucas Bailey / WhiteMagic Labs.
