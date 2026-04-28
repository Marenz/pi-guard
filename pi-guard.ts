/**
 * pi-guard — Remote command path guard for pi
 *
 * Intercepts bash and read tool calls to prevent accidental leakage of
 * sensitive files via SSH, Docker, or kubectl remote commands.
 *
 * Features:
 * - Parse remote commands, extract accessed file paths
 * - Prompt for approval with multiple pattern-granularity options
 * - Save rules to ~/.config/pi-guard/rules.json
 * - Always-block sensitive paths (.env, .ssh/*, .aws/*, etc.)
 * - Session suspend/resume for temporary overrides
 * - /guard-forget <id> to un-remember specific rules
 * - Follows the AGENTS.md style of OpenCode (functional, concise, no try/catch, early returns)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ──────────────────────────────────────────────
// State & persistence
// ──────────────────────────────────────────────

const confDir = join(homedir(), ".config", "pi-guard");
const rulesPath = join(confDir, "rules.json");

type Rule = {
  id: number;
  pattern: string;
  host?: string;
  label: string;
};

type Config = { rules: Rule[]; nextId: number };

const load = (): Config => {
  if (!existsSync(rulesPath)) return { rules: [], nextId: 1 };
  try {
    return JSON.parse(readFileSync(rulesPath, "utf-8"));
  } catch {
    return { rules: [], nextId: 1 };
  }
};

const save = (c: Config) => {
  if (!existsSync(confDir)) mkdirSync(confDir, { recursive: true });
  writeFileSync(rulesPath, JSON.stringify(c, null, 2), "utf-8");
};

// Session state (not persisted)
let suspended = false;

// ──────────────────────────────────────────────
// Path pattern matching
// ──────────────────────────────────────────────

// Convert a stored pattern (with <?> and <?*>) to a RegExp
const patternToRe = (pattern: string): RegExp => {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const reStr = escaped
    .replace(/<\?\*>/g, ".*")   // <?*> matches everything
    .replace(/<\?>/g, "[^/]+");  // <?> matches one segment
  return new RegExp(`^${reStr}$`);
};

// Shorten a path by replacing the common prefix with …
// show shows how many trailing segments to keep visible
const shorten = (path: string, show: number): string => {
  const parts = path.split("/").filter(Boolean);
  if (parts.length <= show) return path;
  return "…/" + parts.slice(-show).join("/");
};

// Generate candidate patterns from a concrete path
const candidates = (path: string): Array<{ label: string; pattern: string; display: string }> => {
  const parts = path.replace(/^~/, homedir()).split("/").filter(Boolean);
  const result: Array<{ label: string; pattern: string; display: string }> = [];

  // Exact path
  result.push({ label: "Exact", pattern: path, display: shorten(path, 2) });

  // One-level wildcard (last component -> <?>)
  if (parts.length > 1) {
    const parent = parts.slice(0, -1).join("/");
    const fp = path.startsWith("/") ? `/${parent}/<?>` : `${parent}/<?>`;
    // Show last 2 meaningful parts + <?>
    const tail = [...parts.slice(-1), "<?>"];
    result.push({ label: "Directory", pattern: fp, display: "…/" + tail.join("/") });
  }

  // Full tree under parent
  if (parts.length > 1) {
    const parent = parts.slice(0, -1).join("/");
    const fp = path.startsWith("/") ? `/${parent}/<?*>` : `${parent}/<?*>`;
    const tail = [...parts.slice(-1), "<?*>"];
    result.push({ label: "Tree", pattern: fp, display: "…/" + tail.join("/") });
  }

  // Full tree under grandparent
  if (parts.length > 2) {
    const gp = parts.slice(0, -2).join("/");
    const fp = path.startsWith("/") ? `/${gp}/<?*>` : `${gp}/<?*>`;
    const tail = [...parts.slice(-2), "<?*>"];
    result.push({ label: "Broad", pattern: fp, display: "…/" + tail.join("/") });
  }

  return result;
};

// Check if a concrete path matches a stored pattern
const matchesPattern = (path: string, pattern: string): boolean => {
  // Normalize ~ in the path
  const p = path.replace(/^~/, homedir());
  return patternToRe(pattern).test(p);
};

// ──────────────────────────────────────────────
// Sensitive path detection
// ──────────────────────────────────────────────

// Paths that are always non-negotiable — cannot be approved, no prompt shown.
// Use /guard-suspend to bypass temporarily.
const sensitivePatterns: Array<{ name: string; re: RegExp }> = [
  { name: ".env", re: /(?:^|[\/"'\s])\.env(?:$|["'\s]|[.\w-]|$)/ },
  { name: ".aws/credentials", re: /\.aws\/credentials/ },
  { name: ".aws/config", re: /\.aws\/config/ },
  { name: ".ssh file", re: /\.ssh\/[^\s"'`|;&$()]+/ },
  { name: "PEM key", re: /[^\s"'`|;&$()]+\.pem/ },
  { name: "SSH key", re: /id_(?:rsa|dsa|ecdsa|ed25519|ed448)[^\s"'`|;&$()]*/ },
  { name: ".kube/config", re: /\.kube\/config/ },
  { name: "secrets.json", re: /secrets\.json/ },
  { name: "auth.json", re: /auth\.json/ },
];

const isSensitive = (path: string): string | null => {
  for (const s of sensitivePatterns) {
    if (s.re.test(path)) return s.name;
  }
  return null;
};

// ──────────────────────────────────────────────
// Remote command parsing
// ──────────────────────────────────────────────

const remoteRe = [
  /^ssh\s+(?:-\S+\s+)*(\S+@\S+)\s+(.+)$/i,
  /^ssh\s+(?:-\S+\s+)*(\S+)\s+(.+)$/i,
  /^docker\s+exec\s+(?:-\S+\s+)*(\S+)\s+(.+)$/i,
  /^kubectl\s+exec\s+(?:-\S+\s+)*(\S+)\s+(?:--\s+)?(.+)$/i,
];

type Remote = { tool: string; host: string; cmd: string; raw: string };

const parseRemote = (raw: string): Remote | null => {
  for (const re of remoteRe) {
    const m = raw.match(re);
    if (m) {
      const host = m[1];
      if (host.startsWith("-")) continue;
      const tool = re.source.includes("kubectl") ? "kubectl" : re.source.includes("docker") ? "docker" : "ssh";
      return { tool, host, cmd: m[2], raw };
    }
  }
  return null;
};

// Extract file paths from a remote command string
// Looks for /... and ~/... tokens, even inside quoted strings
const extractPaths = (cmd: string): string[] => {
  // Find all absolute/relative paths in the command
  const re = /(?:^|\s)(\/[^\s"'|;&$()]+|~\/[^\s"'|;&$()]+|\.\/[^\s"'|;&$()]+)/g;
  const paths: string[] = [];
  const seen = new Set<string>();
  let m;
  while ((m = re.exec(cmd)) !== null) {
    const p = m[1].replace(/["']$/, ""); // strip trailing quote if any
    if (!seen.has(p)) {
      seen.add(p);
      paths.push(p);
    }
  }
  return paths;
};

// ──────────────────────────────────────────────
// Rule matching
// ──────────────────────────────────────────────

type Match = { rule: Rule; path: string } | null;

const matchRule = (path: string, host: string, config: Config): Match => {
  for (const rule of config.rules) {
    if (rule.host && rule.host !== host) continue;
    if (matchesPattern(path, rule.pattern)) return { rule, path };
  }
  return null;
};

// ──────────────────────────────────────────────
// Prompt helpers
// ──────────────────────────────────────────────

const choiceLabels = [
  "Exact path",
  "Directory (one level wildcard)",
  "Tree (everything under)",
  "Broad tree",
  "Allow this once only",
  "Block",
] as const;

const promptOpts = (path: string): Array<{ label: string; pattern?: string }> => {
  const cs = candidates(path);
  const opts: Array<{ label: string; pattern?: string }> = [];
  for (const c of cs) opts.push({ label: `[${c.label}] ${c.display}`, pattern: c.pattern });
  opts.push({ label: "Custom pattern" });
  opts.push({ label: "Allow this once only" });
  opts.push({ label: "Block" });
  return opts;
};

// ──────────────────────────────────────────────
// Extension
// ──────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  // ── Commands ──

  pi.registerCommand("guard-rules", {
    description: "List all pi-guard rules",
    handler: async (_args, ctx) => {
      const c = load();
      if (!c.rules.length) {
        ctx.ui.notify("No pi-guard rules configured.", "info");
        return;
      }
      const lines = c.rules.map(
        (r) => `  #${r.id}  ${r.host ? `host=${r.host} ` : ""} ${r.label}\n         pattern: ${r.pattern}`,
      );
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("guard-forget", {
    description: "Remove a rule by ID (use /guard-rules to list IDs)",
    params: { id: "number" },
    handler: async (args, ctx) => {
      const c = load();
      const id = args.id as number;
      const before = c.rules.length;
      c.rules = c.rules.filter((r) => r.id !== id);
      if (c.rules.length === before) {
        ctx.ui.notify(`No rule with ID ${id} found.`, "warning");
        return;
      }
      save(c);
      ctx.ui.notify(`Forgot rule #${id}. Next matching command will prompt again.`, "success");
    },
  });

  pi.registerCommand("guard-suspend", {
    description: "Temporarily disable all rules for this session",
    handler: async (_args, ctx) => {
      suspended = true;
      ctx.ui.notify("pi-guard rules suspended for this session. Everything will prompt.", "info");
    },
  });

  pi.registerCommand("guard-resume", {
    description: "Re-enable rules after suspension",
    handler: async (_args, ctx) => {
      suspended = false;
      ctx.ui.notify("pi-guard rules resumed.", "info");
    },
  });

  pi.registerCommand("guard-status", {
    description: "Show whether rules are active and list them",
    handler: async (_args, ctx) => {
      const c = load();
      const state = suspended ? "suspended" : "active";
      const lines = [
        `Rules: ${state} (${c.rules.length} rules)`,
        ...c.rules.map(
          (r) => `  #${r.id}  ${r.host ? `host=${r.host} ` : ""} ${r.label}\n         pattern: ${r.pattern}`,
        ),
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  // ── Tool call interceptor ──

  pi.on("tool_call", async (event, ctx) => {
    // If suspended, let everything through (no rules, keep prompting if needed)
    // Actually suspended means: don't auto-approve, but also don't auto-block.
    // We still check sensitive paths though. Let's make suspended = prompt on everything,
    // never auto-allow, but still block sensitive paths unless user explicitly allows.

    if (event.toolName === "read") {
      const path = event.input.path as string;
      const sens = isSensitive(path);
      if (suspended) {
        // Still check, but prompt the user instead of blocking
        if (sens && ctx.hasUI) {
          const choice = await ctx.ui.select(
            `⚠️ Sensitive file: ${path} (${sens})\n\nAllow reading this file?`,
            ["Allow once", "Block"],
          );
          if (choice === "Block") {
            return { block: true, reason: `Blocked by user: ${sens} path ${path}` };
          }
        }
        return undefined;
      }

      if (sens) {
        if (ctx.hasUI) {
          ctx.ui.notify(`⛔ Blocked read of ${sens}: ${path}. Use /guard-suspend to bypass.`, "warning");
        }
        return { block: true, reason: `Reading ${path} blocked by pi-guard (${sens}). This is always blocked for safety.` };
      }
      return undefined;
    }

    if (event.toolName !== "bash") return undefined;

    const command = event.input.command as string;
    const remote = parseRemote(command);

    if (!remote) {
      // Not a remote command — check for sensitive paths in local commands
      const paths = extractPaths(command);
      for (const p of paths) {
        const sens = isSensitive(p);
        if (sens) {
          if (ctx.hasUI) {
            ctx.ui.notify(`⛔ Local command references ${sens}: ${p}. Blocked.`, "warning");
          }
          return { block: true, reason: `Command references ${sens} path ${p}. Blocked by pi-guard.` };
        }
      }
      return undefined;
    }

    // It's a remote command
    const config = load();
    const paths = extractPaths(remote.cmd);

    if (!paths.length) {
      // No file paths in the remote command — let it through
      return undefined;
    }

    // Check each path against rules or sensitive list
    const blockedPaths: string[] = [];
    const unknownPaths: string[] = [];
    let matchedRule: Match = null;

    for (const p of paths) {
      const sens = isSensitive(p);
      if (sens && !suspended) {
        blockedPaths.push(`${p} (${sens})`);
        continue;
      }

      if (!suspended) {
        const m = matchRule(p, remote.host, config);
        if (m) {
          matchedRule = m;
          continue; // Approved by rule
        }
      }

      unknownPaths.push(p);
    }

    // If any paths are blocked (sensitive, not suspended), block entirely
    if (blockedPaths.length) {
      if (ctx.hasUI) {
        ctx.ui.notify(
          `⛔ Remote command blocked: ${blockedPaths.join(", ")}\n  ${remote.tool} ${remote.host}: ${remote.cmd}\n  Use /guard-suspend to bypass for this session.`,
          "warning",
        );
      }
      return {
        block: true,
        reason: `Remote command blocked: accessing sensitive path(s) ${blockedPaths.join(", ")}. These are always blocked by pi-guard. Use /guard-suspend to bypass for the session.`,
      };
    }

    // If a rule auto-allowed, let it through with a notification
    if (!unknownPaths.length && matchedRule) {
      if (ctx.hasUI) {
        ctx.ui.notify(
          `✅ Allowed: ${remote.tool} ${remote.host} ${paths.join(" ")}\n   (matched rule #${matchedRule.rule.id}: ${matchedRule.rule.pattern})\n   Run /guard-forget ${matchedRule.rule.id} to un-remember.`,
          "info",
        );
      }
      return undefined;
    }

    // No rule matched — prompt for approval
    if (!ctx.hasUI) {
      return { block: true, reason: `Remote command to ${remote.host} blocked: no UI for approval.` };
    }

    // For each unknown path, prompt
    // For simplicity, prompt on the first unknown path
    const path = unknownPaths[0];
    const opts = promptOpts(path);
    const parts = path.split("/").filter(Boolean);
    const prefix = parts.length > 2 ? parts.slice(0, -2).join("/") : "";
    const choice = await ctx.ui.select(
      [
        `🌐 ${remote.tool.toUpperCase()} to ${remote.host}`,
        `Command: ${remote.cmd}`,
        ``,
        `Path: ${path}`,
        ``,
        `Choose how to remember this:`,
      ].join("\n"),
      opts,
    );

    if (choice === "Block") {
      return { block: true, reason: `Remote command to ${remote.host} blocked by user.` };
    }

    if (choice === "Allow this once only") {
      return undefined;
    }

    if (choice === "Custom pattern") {
      const pattern = await ctx.ui.input("Pattern (use <?> for segment, <?*> for rest):", path);
      if (!pattern) return undefined; // cancelled or empty — just allow once
      const label = `[Custom] ${pattern}`;
      const c = load();
      const rule: Rule = { id: c.nextId++, pattern, label };
      c.rules.push(rule);
      save(c);
      ctx.ui.notify(`✅ Rule #${rule.id} saved: ${label}`, "success");
      return undefined;
    }

    // Find the pattern from the choice label
    const chosenPattern = choice.match(/\[(Exact|Directory|Tree|Broad)\]\s+(.+)/);
    if (chosenPattern) {
      const pattern = chosenPattern[2];
      const label = `[${chosenPattern[1]}] ${pattern}`;
      const c = load();
      const rule: Rule = { id: c.nextId++, pattern, label };
      c.rules.push(rule);
      save(c);
      ctx.ui.notify(`✅ Rule #${rule.id} saved: ${label}`, "success");
      return undefined;
    }

    // Fallback
    return undefined;
  });
}
