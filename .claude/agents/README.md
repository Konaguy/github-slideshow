# Bug Bounty Agents

A suite of Claude Code subagents for **authorized** bug bounty hunting and responsible disclosure. Each agent is a specialist you can invoke by name (e.g. "use the recon-scout agent on …") or that Claude will delegate to automatically.

## The agents

| Agent | Role | Access |
|-------|------|--------|
| `recon-scout` | Maps the in-scope attack surface via subfinder/dnsx/httpx/katana/gau: hosts, endpoints, tech stack, entry points, prioritized leads. | Passive first; active only after scope confirmed |
| `web-vuln-hunter` | Actively tests in-scope web targets for OWASP-class bugs (XSS, IDOR, SSRF, injection, auth/logic flaws). | In-scope targets, non-destructive PoCs |
| `api-hunter` | REST/GraphQL testing: BOLA/IDOR, broken function-level auth, mass assignment, excessive data exposure, GraphQL abuse. | In-scope APIs, provided test accounts |
| `mobile-recon` | Statically unpacks in-scope APK/IPA for endpoints, secrets, deep links, insecure config. | Static analysis only |
| `code-auditor` | Static security review (semgrep/gitleaks + manual data-flow) of source you're authorized to read. | Read-only |
| `triage-dedup` | Pre-submission check: scope, duplicate likelihood, accepted-risk, severity sanity, evidence gaps. | Read-only research |
| `report-writer` | Turns confirmed findings into reproducible, platform-ready reports (severity, impact, remediation). | Local files |

## Toolchain

`.claude/tools/setup.sh` installs the real tooling the agents drive — idempotent, safe to re-run:

`subfinder`, `dnsx`, `httpx`, `katana`, `gau`, `ffuf` (Go) · `nuclei` + templates · `semgrep`, `gitleaks`.

The **SessionStart hook** in `.claude/settings.json` runs the installer automatically at the start of every session (log: `/tmp/bb-setup.log`). `.claude/tools/scope-guard.sh` filters host/URL streams against a `scope.txt` allowlist so out-of-scope assets are dropped before any probing.

Run it once per session before active recon/audit work:

```bash
bash .claude/tools/setup.sh
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
```

To auto-run it at session start, wire it into a SessionStart hook in `.claude/settings.json` (ask me and I'll add it). Mobile tools (`apktool`, `jadx`, `dex2jar`) are installed on demand by `mobile-recon`.

## Suggested workflow

```
recon-scout ─┬─► web-vuln-hunter ─┐
             └─► api-hunter ──────┤
mobile-recon ────────────────────┤─►  triage-dedup ─►  report-writer
code-auditor (if code access) ───┘
```

1. **recon-scout** (and **mobile-recon** for apps) build the target inventory.
2. **web-vuln-hunter** / **api-hunter** / **code-auditor** find and confirm issues.
3. **triage-dedup** vets each confirmed finding for scope + duplicate risk.
4. **report-writer** writes up what survives triage.

## Rules of engagement (baked into every agent)

- **Scope is law.** Only ever act against assets a specific program lists as in scope. When in doubt, treat it as out of scope and stop.
- **Confirm before acting.** Paste the program's scope and rules of engagement at the start; the active agents ask for it.
- **No harm.** Respect rate limits and testing windows. No DoS, no destructive actions, no exfiltration of real user data, no persistence or pivoting.
- **Only your accounts.** Test with accounts you own or the program provisions — never others' credentials.
- **Responsible disclosure.** No public disclosure without authorization; follow the program's coordinated timeline.

These agents are for legal, authorized security testing (bug bounty programs, pentests with written permission, CTFs, and your own systems) — not for testing systems you don't have permission to test.

## Customizing

Each agent's `tools:` frontmatter limits what it can do. Tighten or loosen per your setup, and edit the system-prompt bodies to add program-specific rules, preferred tooling, or your report template.
