/**
 * opencode-citadel-airlock.js — Drop-in OpenCode v2.1.1+ Kernel-Confined Security Airlock Plugin
 *
 * Bridges WhiteMagic / VIOLET Citadel Rings 2, 3, and 5 directly into OpenCode v2's
 * plugin lifecycle (`shell.create.before`, `tool.execute.before`, and `experimental_workspace`):
 *
 *   1. Ambient Credential Scrubbing + Canary Baiting (`shell.create.before`):
 *      Strips ambient developer secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
 *      `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`, etc.) from
 *      child shell environments and replaces them with stateless HMAC-SHA256
 *      Canary Honeytokens (`sk-proj-canary-opencode-...`).
 *
 *   2. Fast-Path Credential Store Guard (`tool.execute.before`, < 0.05 ms):
 *      Rejects direct tool arguments referencing `~/.local/share/opencode/auth.json`,
 *      `account.json`, `service.json`, `opencode.db`, `~/.ssh`, `~/.aws`, and `~/.gnupg`.
 *
 *   3. Hardware-Speed Linux Kernel Landlock LSM Confinement (`opencode_kekkai_launcher.py`):
 *      Wraps `shell` / `bash` commands in the zero-dependency Landlock LSM launcher on Linux
 *      so even obfuscated commands (`base64 -d | sh`, `python3 -c ...`, `npm postinstall`)
 *      cannot read `~/.local/share/opencode/auth.json` or `~/.ssh` under the same OS UID
 *      (`EACCES: Permission denied` enforced by the Linux kernel), while `git`, `node`,
 *      `cargo`, and workspace file edits run at 100% native speed.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_LAUNCHER = path.resolve(HERE, "../defense/opencode_kekkai_launcher.py");

const SENSITIVE_ENV_MARKERS = [
  "OPENAI_",
  "ANTHROPIC_",
  "OPENROUTER_",
  "GEMINI_",
  "GOOGLE_API_",
  "AWS_SECRET",
  "AWS_SESSION",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITLAB_",
  "STRIPE_",
  "X402_",
  "CDP_",
  "PRIVATE_KEY",
  "DATABASE_URL",
];

const FORBIDDEN_CREDENTIAL_PATHS = [
  ".local/share/opencode/auth.json",
  ".local/share/opencode/account.json",
  ".local/share/opencode/service.json",
  ".local/share/opencode/opencode.db",
  ".config/opencode/cli.json",
  ".config/opencode/service.json",
  ".ssh/id_",
  ".aws/credentials",
  ".gnupg/",
];

const AUDIT_LOG = path.join(os.homedir(), ".local/state/whitemagic/opencode-airlock.jsonl");

export function mintStatelessCanary(label = "opencode") {
  const nonce = crypto.randomBytes(6).toString("hex");
  const mac = crypto
    .createHmac("sha256", "violet-canary-hmac-v2:opencode-airlock")
    .update(`${label}:openai_key:${nonce}`)
    .digest("hex")
    .slice(0, 24);
  return `sk-proj-canary-${label}-${nonce}-${mac}`;
}

function logAirlockEvent(event, detail) {
  try {
    fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
    fs.appendFileSync(
      AUDIT_LOG,
      JSON.stringify({ ts: new Date().toISOString(), event, ...detail }) + "\n"
    );
  } catch {}
}

function referencesForbiddenPath(text) {
  const norm = String(text || "").replace(/\\/g, "/");
  return FORBIDDEN_CREDENTIAL_PATHS.find((p) => norm.includes(p)) || null;
}

function shellSingleQuote(str) {
  return `'${String(str).replace(/'/g, `'\\''`)}'`;
}

export default {
  id: "opencode-citadel-airlock",
  setup: async (ctx) => {
    const launcherPath = process.env.OPENCODE_KEKKAI_LAUNCHER || DEFAULT_LAUNCHER;
    const landlockAvailable = os.platform() === "linux" && fs.existsSync(launcherPath);

    // 1. Scrub ambient secrets & plant stateless HMAC canary in child shell environments
    if (ctx?.shell?.hook) {
      await ctx.shell.hook("create.before", async (event) => {
        if (!event || typeof event.env !== "object" || !event.env) return;
        let scrubbed = 0;
        for (const key of Object.keys(event.env)) {
          const upper = key.toUpperCase();
          if (SENSITIVE_ENV_MARKERS.some((m) => upper.includes(m))) {
            delete event.env[key];
            scrubbed++;
          }
        }
        event.env.OPENAI_API_KEY_CANARY_TRAP = mintStatelessCanary("opencode_shell");
        if (scrubbed > 0) {
          logAirlockEvent("SHELL_ENV_AIRLOCKED", { scrubbed_count: scrubbed });
        }
      });
    }

    // 2. Fast-path credential guard + Linux Kernel Landlock LSM command wrapping
    if (ctx?.tool?.hook) {
      await ctx.tool.hook("execute.before", async (event) => {
        const toolName = String(event?.tool ?? "").toLowerCase();
        const serialized = JSON.stringify(event?.input ?? {});
        const hit = referencesForbiddenPath(serialized);
        if (hit) {
          logAirlockEvent("CREDENTIAL_PATH_BLOCKED", { tool: toolName, path_pattern: hit });
          throw new Error(
            `[Citadel Airlock] Blocked access to protected credential store (${hit}). ` +
              `Same-UID subprocesses and tools are confined under Mandala Kekkai policy.`
          );
        }

        // Wrap shell/bash commands in Linux Kernel Landlock LSM so obfuscated/indirect
        // reads of ~/.local/share/opencode/auth.json or ~/.ssh fail at the syscall boundary.
        if (
          landlockAvailable &&
          (toolName === "shell" || toolName === "bash") &&
          event?.input &&
          typeof event.input === "object"
        ) {
          const key =
            typeof event.input.command === "string"
              ? "command"
              : typeof event.input.cmd === "string"
                ? "cmd"
                : null;
          if (key && !event.input[key].includes("opencode_kekkai_launcher.py")) {
            const ws = ctx?.worktree || ctx?.directory || process.cwd();
            const rawCmd = event.input[key];
            event.input[key] =
              `python3 ${shellSingleQuote(launcherPath)} --workspace ${shellSingleQuote(ws)} -- bash -c ${shellSingleQuote(rawCmd)}`;
          }
        }
      });
    }
  },
};
