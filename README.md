# pi-guard

A [pi](https://github.com/mariozechner/pi) extension that guards sensitive file paths in remote commands (SSH, Docker, kubectl) and blocks accidental secret leakage.

## How it works

pi-guard intercepts all `bash` and `read` tool calls in pi. It:

1. **Parses remote commands** (SSH, Docker, kubectl) to extract the remote host and the file paths being accessed.
2. **Checks against saved rules** — if a path pattern was previously approved, the command runs silently.
3. **Prompts for approval** — if no rule matches, shows the paths being read and asks what to do, with multiple granularity options for the saved rule.
4. **Always blocks sensitive paths** — `.env`, `~/.aws/*`, `~/.ssh/*`, `*.pem`, etc. are non-negotiable unless explicitly overridden per-session.

## Installation

```bash
mkdir -p ~/.pi/agent/extensions
cp pi-guard.ts ~/.pi/agent/extensions/
```

Then add to your pi config or load via `-e`:

```bash
pi -e ~/.pi/agent/extensions/pi-guard.ts
```

## Commands

- **`/guard-rules`** — list all saved approval rules with their IDs.
- **`/guard-forget <id>`** — remove a rule by ID. Next time that command will prompt again.
- **`/guard-suspend`** — temporarily disable all rules for the current session. Everything prompts fresh.
- **`/guard-resume`** — re-enable rules after suspension.
- **`/guard-status`** — show whether rules are active, plus the rule list.

## Rule matching

Rules are path-pattern-based. `<?>` matches one path segment, `<?*>` matches everything after.

| Pattern | Matches | Doesn't match |
|---------|---------|---------------|
| `/var/log/<?>/errors.log` | `/var/log/nginx/errors.log` | `/var/log/nginx/sub/errors.log` |
| `/home/<?>/project/<?*>` | `/home/user/project/src/main.rs` | `/home/user/other/thing` |
| `/etc/<?*>` | `/etc/nginx/nginx.conf` | — |

## Sensitive paths (always blocked)

These are never auto-allowed. You can override per-session with `/guard-suspend`:

- `.env`, `.env.*`
- `~/.aws/credentials`, `~/.aws/config`
- `~/.ssh/*`, `id_rsa*`, `id_ed25519*`
- `*.pem`, `*-key.pem`
- `~/.kube/config`
- `secrets.json`, `auth.json`
