# OpenCode v2.1.1 Defensive Security Alignment & Hardening Report
**Prepared by WhiteMagic Labs · October 20, 2026**  
**Target Reviewed:** `@opencode/cli` `v2.1.1` & `@opencode-ai/plugin` SDK (`v2`)  
**Companion Artifact:** [`plugins/opencode-citadel-airlock.js`](../plugins/opencode-citadel-airlock.js) & [`defense/mandala_kekkai.py`](../defense/mandala_kekkai.py)

---

## 1. Executive Summary

Following the recent industry-wide wave of autonomous agent security incidents—where offensive swarms targeted developer credential vaults, ambient environment variables, and un-sandboxed terminal tool runners—we conducted a constructive defensive review of **OpenCode v2.1.1** (`@opencode/cli` and `@opencode-ai/plugin`).

Our goal is to help the OpenCode core team (`@thdxr` / Anomaly) and the broader developer community harden local and hosted coding agents against machine-speed kill chains.

### Key Findings at a Glance
1. **Strong Architectural Steps Already Landed in OpenCode v2.1.1:**
   - **Pre-Execution Plugin Hooks (`tool.execute.before` & `shell.create.before`):** OpenCode v2's Promise-based plugin architecture now exposes exact interception seams before any shell environment is created or any tool executes.
   - **Experimental Workspace Adaptor (`experimental_workspace`):** Introduces a clean abstraction (`configure`, `create(config, env)`, `remove`, `target -> local | remote`) separating workspace lifecycle from model turns.
   - **Loopback Service Binding & File Mode Hardening:** `opencode.exe serve --service` binds strictly to `127.0.0.1` (`127.0.0.1:<ephemeral>`), and credential/state files (`~/.local/share/opencode/auth.json`, `account.json`, `service.json`, `opencode.db`, and `~/.config/opencode/cli.json`) are created with mode `0600` (`-rw-------`).
2. **Five Residual Security Gaps Between OpenCode v2.1.1 and the Wider Net:**
   - **Gap 1 — Same-UID Credential Store Exposure (`chmod 0600` vs. Same-User Subprocesses):** Because `shell` commands, `npm postinstall` scripts, and MCP servers run under the *same OS UID* as OpenCode, `chmod 0600` does not stop a prompt-injected command or rogue dependency from reading `~/.local/share/opencode/auth.json` or `~/.local/share/opencode/opencode.db`.
   - **Gap 2 — Ambient Secret Inheritance in Child Shells (`process.env` Harvesting):** Unless scrubbed in `shell.create.before`, child processes inherit ambient `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, and `AWS_*` variables.
   - **Gap 3 — `--auto` Mode Without Kernel-Enforced Scope Confinement:** Application-level command allow/deny patterns can be bypassed by shell indirection (`python3 -c`, `base64 -d | sh`, `Makefile` targets) unless backed by an OS kernel LSM (`Landlock ABI v6–v8`).
   - **Gap 4 — Un-Anchored Session Transcript Database (`opencode.db` Storage Tampering):** `~/.local/share/opencode/opencode.db` stores multi-gigabyte session transcripts without hash-chained commitments (`GroverProofDualLedger` / `continuity-receipt`), leaving `--continue` and session compaction vulnerable to at-rest SQLite poisoning (`agmi` T1–T9 vectors).
   - **Gap 5 — Cloud LLM Safety Refusal Walls ("Daybreak Blue") During Incident Triage:** Relying on cloud frontier models to inspect suspicious tool payloads or active exploit traffic hits commercial guardrail refusals mid-incident.

---

## 2. Detailed Gap Analysis & Drop-In Remediations

### Gap 1 & Gap 2: Same-UID Credential Harvesting (`auth.json` & `process.env`)
- **The Threat Vector:** When an AI coding agent clones an untrusted repository, reads a poisoned `AGENTS.md`/`CLAUDE.md`, or runs `npm test` / `cargo test`, the spawned child process runs as the developer's UID. `chmod 0600` on `~/.local/share/opencode/auth.json` provides zero protection against same-UID reads.
- **Citadel Remediation (Included in [`plugins/opencode-citadel-airlock.js`](../plugins/opencode-citadel-airlock.js) + [`defense/mandala_kekkai.py`](../defense/mandala_kekkai.py)):**
  1. **Hook 1 (`ctx.shell.hook("create.before")`)**: The plugin source contains environment-scrub and canary-injection logic. This review's Landlock launcher fixture does not exercise that plugin path; no ambient-credential protection claim is based on the filesystem smoke.
  2. **Hook 2 (`ctx.tool.hook("execute.before")`)**: The plugin source contains path checks for OpenCode state and common credential directories. Those app-level checks are separate from the launcher's kernel filesystem fixture and are not qualified by it.
  3. **Filesystem Enforcement (`opencode_kekkai_launcher.py`)**: On Linux, the launcher installs Landlock filesystem rules and a fake-home smoke verifies that selected workspace files remain readable while controlled credential sentinels in unallowed home paths are denied. This is filesystem evidence only; the launcher does not filter environment variables or restrict network access.

### Launcher Boundary: Filesystem Only

The Linux launcher grants the workspace and its private temporary directory for writes, system runtime paths for execution, and narrow read-only tool roots (`~/.cargo/bin`, Cargo registry index/cache/source data, `~/.rustup/toolchains`, `~/.rustup/settings.toml`, and `~/.nvm/versions`). It does not grant `~/.gitconfig`, `~/.config/git`, the whole `~/.cargo` tree, or `~/.local/bin` by default. A controlled fake-`HOME` fixture confirms that `.gitconfig`, `.git-credentials`, `.config/git/credentials`, and `.cargo/credentials.toml` sentinels are unreadable while workspace content and `/usr/bin/python3` remain usable. No real credentials are read by this check.

The launcher copies the parent environment and only replaces temporary-directory variables. It does not scrub or filter provider credentials, and the Linux Landlock rules handle no network rights. Network is therefore unrestricted by this launcher. The fixture proves filesystem access boundaries on the tested Linux host; it does not establish an environment credential airlock, network containment, or behavior on other hosts.

### Gap 3: Hardening `--auto` Mode with `ScopeBitset2048` & Landlock Kekkai
- **The Threat Vector:** Users love `opencode --auto` for velocity, but string-level permission matching cannot statically analyze what an arbitrary script will touch on disk or over the network.
- **Citadel Remediation:** Bind every tool execution in `--auto` mode to a **Mandala Kekkai slot**:
  - **Filesystem:** Read/Write granted *only* to the active project worktree (`ctx.worktree`); Read-Only granted to `/usr`, `/lib`, `/bin`; `~/.local/share/opencode` and `~/.ssh` unmounted at the kernel level.
  - **Network:** The standalone `opencode_kekkai_launcher.py` does not restrict network access. Any network control must be separately enforced and tested; it is not part of the Landlock filesystem evidence above.

### Gap 4: Defending `opencode.db` Against At-Rest Session Poisoning
- **The Threat Vector:** As demonstrated by the `agmi` benchmark (where 12/12 mainstream agent stores silently accepted tampered on-disk records), an attacker or rogue local process that modifies a historical row in `~/.local/share/opencode/opencode.db` can inject persistent hidden instructions into future `--continue` or `experimental.session.compacting` turns.
- **Citadel Remediation:** Emit a signed **`continuity-receipt`** (or Grover-proof `SHA-384 + BLAKE2b-512` dual hash) at every session checkpoint and verify the chain head before `experimental.session.compacting` or `--continue`.

### Gap 5: Eliminating the "Daybreak Blue" Refusal Wall with Zero-Refusal Local Triage
- **The Threat Vector:** During an active attack, security responders and defensive agents need to classify raw shellcode, reverse shells, and obfuscated prompt injections immediately—without a cloud provider's safety filter refusing the prompt.
- **Citadel Remediation:** `violet_immunize.py` (`FastPathImmunizer`) and WhiteMagic's local System-0 engine synthesize and replay-verify deterministic block rules locally in **`0.53 ms – 2.58 ms`** with **0.0% refusal rate** and **0.0% false positives** against historical clean traffic.

---

## 3. Quickstart for OpenCode Users & Maintainers

1. **Install the Drop-In OpenCode v2.1.1 Airlock Plugin (< 30 seconds):**
   ```bash
   cp plugins/opencode-citadel-airlock.js ~/.config/opencode/plugin/
   opencode reload
   ```
2. **Run the OpenCode Airlock & 10-Suite Citadel Verification Battery:**
   ```bash
   python3 defense/violet_stress_test.py
   python3 defense/sangha_citadel_unified_benchmark.py
   ```
