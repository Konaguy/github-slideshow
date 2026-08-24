# Bug Bounty Agents

A suite of Claude Code subagents for **authorized** bug bounty hunting and responsible disclosure. Each agent is a specialist you can invoke by name (e.g. "use the recon-scout agent on …") or that Claude will delegate to automatically.

## The agents

| Agent | Role | Access |
|-------|------|--------|
| `recon-scout` | Maps the in-scope attack surface: hosts, endpoints, tech stack, entry points, prioritized leads. | Passive first; active only after scope is confirmed |
| `web-vuln-hunter` | Actively tests in-scope web targets for OWASP-class bugs (XSS, IDOR, SSRF, injection, auth/logic flaws). | In-scope targets only, non-destructive PoCs |
| `code-auditor` | Static security review of source you're authorized to read; traces source→sink to find exploitable bugs. | Read-only |
| `report-writer` | Turns confirmed findings into reproducible, platform-ready reports with severity, impact, remediation. | Local files |

## Suggested workflow

```
recon-scout  →  web-vuln-hunter  ─┐
                                  ├─►  report-writer
code-auditor (if code access) ────┘
```

1. **recon-scout** builds a target inventory (`recon-<target>.md`).
2. **web-vuln-hunter** and/or **code-auditor** work from that inventory to find and confirm issues.
3. **report-writer** writes up each *confirmed* finding for submission.

## Rules of engagement (baked into every agent)

- **Scope is law.** Only ever act against assets a specific program lists as in scope. When in doubt, treat it as out of scope and stop.
- **Confirm before acting.** Paste the program's scope and rules of engagement at the start of a session; the active agents will ask for it.
- **No harm.** Respect rate limits and testing windows. No DoS, no destructive actions, no exfiltration of real user data, no persistence or pivoting.
- **Only your accounts.** Test with accounts you own or the program provisions — never others' credentials.
- **Responsible disclosure.** No public disclosure without authorization; follow the program's coordinated timeline.

These agents are for legal, authorized security testing (bug bounty programs, pentest engagements with written permission, CTFs, and your own systems). They are not for testing systems you don't have permission to test.

## Customizing

Each agent's `tools:` frontmatter limits what it can do. Tighten or loosen per your setup, and edit the system prompt bodies to add program-specific rules, preferred tooling, or your report template.
