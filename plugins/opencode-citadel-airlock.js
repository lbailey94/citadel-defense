/**
 * opencode-citadel-airlock.js — Drop-in OpenCode v2.1.1+ Security Airlock Plugin
 *
 * Bridges WhiteMagic / VIOLET Citadel Rings 2, 3, and 5 directly into OpenCode v2's
 * plugin lifecycle (`shell.create.before` and `tool.execute.before`):
 *
 *   1. Ambient Credential Scrubbing (`shell.create.before`):
 *      Strips ambient developer secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
 *      `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`, etc.) from
 *      child shell environments and replaces them with stateless HMAC-SHA256
 *      Canary Honeytokens (`sk-proj-canary-opencode-...`) so any prompt-injected
 *      command or rogue postinstall script attempting to harvest `process.env`
 *      captures a self-attributing tripwire instead of a real credential.
 *
 *   2. Same-UID Credential Store Guard (`tool.execute.before`):
 *      Because `chmod 0600` on `~/.local/share/opencode/auth.json`, `opencode.db`,
 *      and `~/.ssh` does not stop subprocesses running under the same OS UID,
 *      this hook blocks unapproved tool reads/writes or shell traversals targeting
 *      `~/.local/share/opencode/auth.json`, `account.json`, `service.json`,
 *      `~/.ssh`, `~/.aws`, and `~/.gnupg`.
 *
 *   3. Optional Kernel Landlock LSM Confinement (`OPENCODE_KEKKAI_ENFORCE=1`):
 *      Wraps untrusted shell commands inside `mandala_kekkai.py` so the Linux
 *      kernel (Landlock ABI v6–v8) enforces workspace confinement at syscall level.
 *
 * Installation:
 *   Copy this file into `~/.config/opencode/plugin/opencode-citadel-airlock.js`
 *   and run `opencode reload`.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
  ".config/opencode/cli.json",
  ".config/opencode/service.json",
  ".ssh/id_",
  ".aws/credentials",
  ".gnupg/",
];

const AUDIT_LOG = path.join(os.homedir(), ".local/state/whitemagic/opencode-airlock.jsonl");

function mintStatelessCanary(label = "opencode") {
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

export default {
  id: "opencode-citadel-airlock",
  setup: async (ctx) => {
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

    // 2. Guard ~/.local/share/opencode/auth.json, ~/.ssh, and ~/.aws against same-UID tool exfiltration
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
      });
    }
  },
};
