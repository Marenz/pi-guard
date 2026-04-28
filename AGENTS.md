# pi-guard

Guard sensitive file paths in remote commands (SSH, Docker, kubectl).

## Overview

Pi extension that intercepts `bash` and `read` tool calls. Parses remote commands to extract accessed file paths. Prompts user for approval on unknown paths with multiple pattern granularity options. Always blocks sensitive paths (.env, .ssh/*, .aws/*, .kube/config, *.pem, id_* keys, secrets.json, auth.json). Saved rules persist in `~/.config/pi-guard/rules.json`.

## Architecture

Single file extension (`pi-guard.ts`). No dependencies beyond `@mariozechner/pi-coding-agent`. No daemon. State is a JSON config file.

Key modules:
- **Pattern matching**: `<?>` matches one path segment, `<?*>` matches everything after. Converted to RegExp at match time.
- **Remote parsing**: Regex-based extraction of (tool, host, remote command) from SSH/docker/kubectl invocations.
- **Path extraction**: Tokenizes remote command, grabs tokens starting with `/`, `~/`, or `./`.
- **Rule system**: Numeric IDs, persistent. `guard-forget <id>` removes a rule.
- **Session suspend**: `guard-suspend`/`guard-resume` toggles all auto-approvals off for the session.

## Commands

| Command | What it does |
|---------|-------------|
| `/guard-rules` | List all rules with IDs |
| `/guard-forget <id>` | Remove rule by ID, next time prompts again |
| `/guard-suspend` | Disable all rules for this session |
| `/guard-resume` | Re-enable rules after suspend |
| `/guard-status` | Show active/suspended state + rule list |

## Sensitive paths (always blocked, use /guard-suspend to bypass)

- `.env`, `.env.*`
- `~/.aws/credentials`, `~/.aws/config`
- `~/.ssh/*`, `id_rsa*`, `id_ed25519*`
- `*.pem`, `*-key.pem`
- `~/.kube/config`
- `secrets.json`, `auth.json`

## Conventions

- One file. No splitting unless composable or reusable.
- No try/catch. Early returns. No else.
- Prefer const over let. Ternary over reassignment.
- Single-word vars where possible.
- TypeScript with type inference, avoid `any`.
- Prefer `Bun.file()` when possible (not applicable here, fs is fine).

## Build/Test

```bash
# No build step — pi loads .ts directly
# Install:
cp pi-guard.ts ~/.pi/agent/extensions/
# Run with:
pi -e ~/.pi/agent/extensions/pi-guard.ts
```

## Pitfalls

- `ctx.hasUI` check required before using `ctx.ui.*` — non-interactive mode has no UI.
- `StringEnum` from `@mariozechner/pi-ai` for enum parameters in commands, not `Type.Union`.
- Tool call interceptors must return `undefined` to let the call through, or `{ block: true, reason }` to block.
- `Type.Union`/`Type.Literal` doesn't work with Google's API — but pi-guard doesn't use Google models currently.
- Rules are matched against the *original* path, not a normalized one. The pattern `<?>` matches exactly one path segment.
- Sensitive path detection is regex-based and case-insensitive — false positives possible on uncommon filenames.

## GitHub

- Upstream: `https://github.com/marenz/pi-guard`
- Push to main, create release tags.
