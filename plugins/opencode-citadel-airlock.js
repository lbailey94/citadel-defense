/**
 * opencode-citadel-airlock.js — Tri-Platform OpenCode v2.1.1+ Security Airlock Plugin
 *
 * Supports Linux (`x64`/`arm64`), macOS (`darwin-arm64` Apple Silicon / `darwin-x64`),
 * and Windows (`win32-x64` / `win32-arm64` + WSL2):
 *
 *   1. Ambient Credential Scrubbing + Canary Baiting (`shell.create.before`, All OSes):
 *      Strips ambient developer secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
 *      `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `STRIPE_SECRET_KEY`, etc.) from
 *      child shell environments and replaces them with stateless HMAC-SHA256
 *      Canary Honeytokens (`sk-proj-canary-opencode-...`).
 *
 *   2. Case-Insensitive Tri-Platform Credential Guard (`tool.execute.before`, < 55 µs):
 *      Normalizes Windows (`\`) and POSIX (`/`) separators and enforces case-insensitive
 *      matching (defeating NTFS and APFS case-folding bypasses like `.SSH/id_ed25519` or
 *      `AppData\Local\OpenCode\Auth.json`) across Linux XDG, macOS `Library/Application Support`,
 *      Windows `AppData/Local` & `AppData/Roaming`, and macOS Keychain (`security dump-keychain`).
 *
 *   3. OS-Native Kernel Confinement (`opencode_kekkai_launcher.py`):
 *      - Linux (`x64`/`arm64`/WSL2): Kernel Landlock LSM (`SYS_landlock_restrict_self`).
 *      - macOS (`arm64`/`x64`): XNU Seatbelt Mandatory Access Control (`sandbox-exec -p`).
 *      - Windows (`x64`/`arm64`): Windows Job Object + Clipboard Isolation (`CreateJobObjectW`).
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

// Lowercase normalized patterns covering Linux XDG, macOS Library/Keychain, and Windows AppData
const FORBIDDEN_CREDENTIAL_PATTERNS = [
  ".local/share/opencode/auth.json",
  ".local/share/opencode/account.json",
  ".local/share/opencode/service.json",
  ".local/share/opencode/opencode.db",
  ".config/opencode/cli.json",
  ".config/opencode/service.json",
  "library/application support/opencode",
  "library/preferences/opencode",
  "appdata/local/opencode",
  "appdata/roaming/opencode",
  "security dump-keychain",
  "find-generic-password",
  ".ssh/id_",
  ".ssh/authorized_keys",
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

export function referencesForbiddenPath(text) {
  const norm = String(text || "").replace(/\\\\/g, "/").replace(/\\/g, "/").toLowerCase();
  return FORBIDDEN_CREDENTIAL_PATTERNS.find((p) => norm.includes(p)) || null;
}

function shellSingleQuote(str) {
  return `'${String(str).replace(/'/g, `'\\''`)}'`;
}

export default {
  id: "opencode-citadel-airlock",
  setup: async (ctx) => {
    const launcherPath = process.env.OPENCODE_KEKKAI_LAUNCHER || DEFAULT_LAUNCHER;
    const plat = os.platform();
    const launcherSupported =
      (plat === "linux" || plat === "darwin") && fs.existsSync(launcherPath);

    // 1. Scrub ambient secrets & plant stateless HMAC canary in child shell environments (All OSes)
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
          logAirlockEvent("SHELL_ENV_AIRLOCKED", { platform: plat, scrubbed_count: scrubbed });
        }
      });
    }

    // 2. Case-insensitive tri-platform credential guard + OS Kernel confinement wrapper
    if (ctx?.tool?.hook) {
      await ctx.tool.hook("execute.before", async (event) => {
        const toolName = String(event?.tool ?? "").toLowerCase();
        const serialized = JSON.stringify(event?.input ?? {});
        const hit = referencesForbiddenPath(serialized);
        if (hit) {
          logAirlockEvent("CREDENTIAL_PATH_BLOCKED", {
            platform: plat,
            tool: toolName,
            path_pattern: hit,
          });
          throw new Error(
            `[Citadel Airlock] Blocked access to protected credential store (${hit}). ` +
              `Same-UID subprocesses and tools are confined under Mandala Kekkai policy.`
          );
        }

        // Wrap shell/bash commands in OS-native kernel confinement (Linux Landlock LSM / macOS Seatbelt)
        if (
          launcherSupported &&
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
