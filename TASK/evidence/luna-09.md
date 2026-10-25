# Luna 09 — Citadel truth contracts

## Identity and scope

- Accepted starting head: `a060dbcb22b97e90485aab4046eea9f1820fbefa` (`reject broad confinement workspaces`).
- Implementation commit: `0d30c5f61e23bf2ea95458dc2e2ebb492e25a370` (`Harden Citadel canary and evidence truth contracts`).
- Owned files: `defense/canary_manager.py`, `defense/violet_insurability_pack.py`, new `defense/evidence_validation.py`, and new `defense/evidence_truth_smoke.py`.
- No AGENTS.md was present under the Luna09 worktree. No canonical checkout, installed runtime, third-party service, or external state was changed.

## Changes

Canary hits now require either a valid HMAC under a present node secret or an exact registered token. Format-shaped strings are returned as `format_like_unverified` and do not trip or enter the registry. Missing, unreadable, or empty secrets disable minting and stateless authentication; no fallback secret is derived. CLI mint output omits the minted token.

Evidence packs now require explicit, fresh pin manifests for artifact integrity checks. Each artifact is checked for path containment, SHA-256 digest, schema, timestamp freshness, and caller-pinned counts. Missing or malformed inputs stay invalid or unavailable. The pack reports benchmark status as unavailable without validated benchmark evidence, and compliance as `NOT_ASSESSED`. Local self-signature verification checks integrity only; the report explicitly says it establishes neither an external trusted peer nor compliance. Private signing keys are written only beneath the configured state directory, outside the exported pack.

## Verification

Commands run from the Luna09 worktree:

| Command | Exit | Result |
|---|---:|---|
| `python3 defense/evidence_truth_smoke.py` | 0 | 3 test methods passed; covers valid local signed canary, wrong MAC, prefix-only token, missing secret, registered token, missing/stale/tampered/truncated evidence, absent benchmark, pack self-signature and tamper rejection. |
| `python3 -m py_compile defense/canary_manager.py defense/evidence_validation.py defense/violet_insurability_pack.py defense/evidence_truth_smoke.py` | 0 | All owned Python files compiled. |
| `git diff --check` | 0 | No whitespace errors. |

All test keys, state files, pin manifests, receipts, and packs were under temporary directories. The `violet_pqc` module environment was set before import, and the pack signer paths were explicitly bound to that temporary state root.

## Failed attempts and corrections

- First smoke run exited 1 because the test reused a stateless canary after checking it; a valid trip had correctly registered that token, so a second manager without the key correctly recognized the already-registered token. The test was corrected to check an unseen token against the missing-secret manager; subsequent run exited 0.
- The first tool response envelope failed to decode (`unknown field result_buffered_for_ns`); the command output was recovered via the yielded execution result. No mutation was retried without inspecting state.

## Limits

- No benchmark artifact was supplied; no benchmark pass count or performance result is claimed.
- Supplied pin manifests are operator inputs, not externally authenticated identities. A self-generated local signature cannot establish an external trusted peer, standards compliance, field performance, or production deployment.
- Tests use controlled local fixtures and do not establish production key custody or end-to-end operational behavior.
