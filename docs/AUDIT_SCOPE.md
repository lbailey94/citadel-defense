# Citadel audit scope and claims evidence

Prepared October 26 and independently reviewed October 27, 2026 against base
`d1cf9f8017d3787fd4263faa25ebd2aa8a5bd50a`. This incorporates the intent of
the intervening path/rate correction: source selection is now an explicit
`--cpr-dir`, and rates derive from each matching process time. The earlier
`e1a8f10` report and the later canonical report were preserved separately.
This candidate changes reporting, claim wording, proof comments, and
experimental output disclosures. It does not change a confinement mechanism,
install an integration, deploy a service, or establish an independent audit.

## Withdrawn conclusions

The old practice report's weighted `100/100` score and its `BATTLE-TESTED` /
`AUDIT-READY` verdict are withdrawn. The score mixed measurements, simulations,
and assigned constants; it has no calibrated relationship to security assurance.
The original report and generator were preserved with SHA-256 hashes in the
parent review's `outputs/audit-preparation-20261026/citadel-*-before.*` evidence.
Git retains the original published source at the base commit above.

| Previous claim | What source actually exercised | Required next evidence |
|---|---|---|
| Kernel XDP drop in nanoseconds | `XDPAuthorizer.simulate_xdp_eval` performs Python socket/address/table operations. `compile_bpf` builds an ELF; no load/attach path is exercised by that benchmark. | Load/attach evidence, interface/kernel identity, map updates, packet counters, allowed/denied traffic controls and a defined timing method. |
| SLH-DSA/FIPS-205 or quantum margin | Custom 99-chain hash signature and Ed25519; no complete SLH-DSA hypertree/FORS construction or conformance validation. | Replace with a reviewed standard implementation and validate standardized parameters/vectors. Review reuse of a hash-chain key before any security use. |
| CTF 9/9 stopped | Practice generator assigned both attempted and stopped waves to 9. The visualizer is scripted. | Actual attempts through the selected enforcement path, meaningful controls, and captured outcomes. |
| agmi 10/10 / rollback and resurrection rejected | Practice generator returned Boolean results from string labels for anchor location/content. No store or read-path attack ran. | Reproduce the actual external suite and product read path with pinned source/store/anchor identities, rollback and erase baselines, and attacker scope. |
| All attempted escapes blocked by the kernel | Legacy escape harness treats any nonzero child exit as blocking. A path, interpreter, permission, or network failure can cause that outcome too. | Prove child startup; readable/writable control fixture; unconfined success; confined failure with a specific errno/cause; kernel and sandbox support; no reliance on remote network availability. |
| Full three-engine parity | Old generator could treat unavailable engines or equal malformed results as agreement. | Require all three engines, valid protocol output and expected process status, and compare error codes as well as verdicts. This candidate implements those reporting gates. |
| Formal capability attenuation / anti-rollback | Boolean AND associativity and natural-number identities, without a runtime/storage model. | Formalize the real state machine and trust assumptions; prove refinement or test the implementation mapping separately. |
| Millions of agents/receipts per second | U32 tree folds without agents, signatures, receipt parsing or cryptographic hashes. Historical reports combined different time samples with copied rates. | Name arithmetic leaves and timing scope. This candidate derives rates from each matching run; a receipt throughput benchmark needs actual receipt verification. |

## What this candidate runs

The signature experiment retains its historical signature/hash identifiers,
but its output now identifies the construction as experimental. The old
`quantum_security_margin_bits: 256` assertion is `null` with an explicit
`not_established` evaluation; neither the digest combination nor a passing
tamper fixture establishes a quantum work factor. CLI fixture failures now
exit nonzero, and the printed authentic-verification result is observed rather
than a hardcoded `True`. The cryptographic operations and key-selection
mechanism are unchanged. NIST's [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
defines SLH-DSA based on SPHINCS+; a custom hash-chain demonstration is not a
complete implementation or validation of that standard.

`practice_audit_battery.py` runs only explicitly selected, scoped checks. Its
default selection is Bend: nine Bool/Nat lemmas, a separate kernel recheck,
and two synthetic arithmetic
folds. A separate `--checks differential --cpr-dir ...` mode runs the top-level
CPR bundle manifests against three already-built engines, honors anchor
options, and checks declared expected verdicts/codes as well as agreement.
It records source and
binary hashes, but does not prove those binaries were built from that source.
The Python regression suite checks the reporting failure modes; it is not a
security or containment test.

The October 27 local front-end check passed. The separate `--verdict` kernel
could not build because Lean was absent; Bend requested Lean 4.34.0 or an
existing `BENDTT` kernel. That lane is `NOT_EVALUATED`, not a mathematical
counterexample and not a completed kernel verification.

`NOT_EVALUATED` and `NOT_SELECTED` remain visible. Selected missing inputs yield
`INCOMPLETE` and exit 2. Executed check failures yield `FAIL` and exit 1 even when
other selected checks pass. There is no composite security score.

## Bound the first independent review

A useful first engagement is the receipt parser/canonicalization/signature trust
boundary in its own repository, followed by the exact launcher/confinement path
used in one runtime. Identify source and executable hashes, supported kernel
features, trust roots, input limits, process lifecycle, secret handling, and
positive/negative controls before expanding to decoys or networking. The
independent reviewer chooses findings and severity; a clean internal run does
not predetermine their conclusion.

The legacy `sangha_citadel_unified_benchmark.py`, `advanced_mutation_fuzz.py`,
`test_kernel_sandbox_escape.py`, and `violet_insurability_pack.py` retain separate
review work. Their historical labels and synthetic/assigned outcomes must not
be cited as independent audit evidence. Existing afternoon candidates for some
of those paths are separate changes; this slice does not silently integrate them.
