"""Admin console (charter §5.J "dashboards", §1.2 "centralized visibility").

Renders a self-contained HTML page from a PhantomInstance's real state: the
audit log, snapshot chain, storage providers, forensic vault, quarantine
queue, threat-intel counters, and compliance evidence. Nothing here
invents data -- a section with no underlying state says so rather than
showing a plausible-looking zero.

## Static render, not a live console

`render()` produces a point-in-time page. There is no server, no polling,
and no auto-refresh: the timestamp in the header is when it was generated,
and that is the honest framing for state read once off disk. A real
deployment needs a service with authentication behind it -- see the
security note below.

## Escaping is load-bearing here

This page displays strings an attacker chose. Quarantined filenames come
from the payload that was blocked (`RANSOM_NOTE_README.txt`,
`invoice.pdf.exe`), audit events embed those paths, and vault reasons
quote them back. A filename is an injection vector into the very console
the responder reads during an incident, so **every interpolated value goes
through `esc()`** -- there is no "this field is safe" exception, because
the fields that look safest are the ones the attacker names.

## What this is not

No authentication, no authorization, no multi-tenancy: whoever can run the
command can render every case in the vault. That is a property of the
prototype (nothing in Phantom has an identity model yet), and it is why
this ships as a file you generate rather than a service you expose.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from phantom.metrics import RPO_TARGET_SECONDS, RTO_TARGET_SECONDS


def esc(value) -> str:
    """HTML-escape any value, including quotes. Use for EVERY interpolation."""
    return html.escape(str(value), quote=True)


@dataclass
class Regeneration:
    """One completed rebuild, reconstructed from the audit log."""
    sequence: int
    timestamp: str
    reason: str
    rto_seconds: float
    rpo_seconds: float
    rto_pass: bool
    rpo_pass: bool


@dataclass
class QuarantineBatch:
    batch_id: str
    findings: dict  # relpath -> list of {rule, severity, reason}

    @property
    def file_count(self) -> int:
        return len(self.findings)


@dataclass
class DashboardData:
    instance_id: str
    generated_at: str
    status: dict
    regenerations: list = field(default_factory=list)
    quarantine_batches: list = field(default_factory=list)
    vault_entries: list = field(default_factory=list)
    compliance: Optional[object] = None
    audit_events: list = field(default_factory=list)


def collect(phantom, compliance: bool = True) -> DashboardData:
    """Gather everything the page shows from a PhantomInstance."""
    import time

    status = phantom.status()

    # Regenerations come from the audit log rather than a separate store:
    # the log is already the system of record for what happened and when.
    regenerations = []
    triggered_reasons = []
    for event in phantom.audit.tail(10_000):
        if event.get("event") == "regeneration_triggered":
            triggered_reasons.append(event.get("reason", "unknown"))
        elif event.get("event") == "regeneration_complete":
            reason = triggered_reasons.pop(0) if triggered_reasons else "unknown"
            regenerations.append(Regeneration(
                sequence=len(regenerations) + 1,
                timestamp=event.get("ts", ""),
                reason=reason,
                rto_seconds=float(event.get("rto_seconds", 0.0)),
                rpo_seconds=float(event.get("rpo_seconds", 0.0)),
                rto_pass=bool(event.get("rto_pass", False)),
                rpo_pass=bool(event.get("rpo_pass", False)),
            ))

    quarantine_batches = []
    quarantine_root = phantom.quarantine.root
    if quarantine_root.exists():
        for batch_dir in sorted(p for p in quarantine_root.iterdir() if p.is_dir()):
            manifest = batch_dir / "manifest.json"
            if manifest.exists():
                quarantine_batches.append(
                    QuarantineBatch(batch_id=batch_dir.name, findings=json.loads(manifest.read_text()))
                )

    report = None
    if compliance:
        try:
            report = phantom.compliance.generate()
        except Exception:  # a reporting failure must not take the console down
            report = None

    return DashboardData(
        instance_id=phantom.instance_id,
        generated_at=time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        status=status,
        regenerations=regenerations,
        quarantine_batches=quarantine_batches,
        vault_entries=phantom.vault.entries(),
        compliance=report,
        audit_events=phantom.audit.tail(25),
    )


# -- rendering ----------------------------------------------------------------

def render(data: DashboardData) -> str:
    return _PAGE.format(
        title=esc(f"Phantom console — {data.instance_id}"),
        css=_CSS,
        header=_render_header(data),
        tiles=_render_tiles(data),
        recovery=_render_recovery(data),
        providers=_render_providers(data),
        vault=_render_vault(data),
        quarantine=_render_quarantine(data),
        compliance=_render_compliance(data),
        audit=_render_audit(data),
    )


def _render_header(data: DashboardData) -> str:
    posture, tone = _posture(data)
    return f"""
    <header class="head">
      <div>
        <h1>Phantom console</h1>
        <p class="sub">Instance <code>{esc(data.instance_id)}</code> &middot;
           generated {esc(data.generated_at)}</p>
      </div>
      <div class="posture {tone}"><span class="dot"></span>{esc(posture)}</div>
    </header>
    <p class="note">Point-in-time render, not a live view. Re-run
       <code>phantom dashboard render</code> to refresh.</p>
    """


def _posture(data: DashboardData):
    """Overall posture from the signals that would actually page someone."""
    vault = data.status.get("forensic_vault", {})
    providers = data.status.get("providers", {})
    down = [name for name, state in providers.items() if not state.startswith("available")]

    if not vault.get("chain_intact", True):
        return "Chain of custody broken", "critical"
    if providers and len(down) == len(providers):
        return "All storage providers unavailable", "critical"
    if down:
        return f"{len(down)} of {len(providers)} providers degraded", "warning"
    failed = [r for r in data.regenerations if not (r.rto_pass and r.rpo_pass)]
    if failed:
        return f"{len(failed)} recovery/recoveries missed target", "warning"
    return "Nominal", "good"


def _render_tiles(data: DashboardData) -> str:
    latest = data.regenerations[-1] if data.regenerations else None
    vault = data.status.get("forensic_vault", {})
    intel = data.status.get("threat_intel", {})

    if latest:
        rto = _tile("Last RTO", f"{latest.rto_seconds:.2f}s", f"target &lt; {RTO_TARGET_SECONDS}s",
                    "good" if latest.rto_pass else "critical", "PASS" if latest.rto_pass else "FAIL")
        rpo = _tile("Last RPO", f"{latest.rpo_seconds:.2f}s", f"target &lt; {RPO_TARGET_SECONDS}s",
                    "good" if latest.rpo_pass else "critical", "PASS" if latest.rpo_pass else "FAIL")
    else:
        rto = _tile("Last RTO", "&mdash;", "no regeneration recorded yet", "muted", "")
        rpo = _tile("Last RPO", "&mdash;", "no regeneration recorded yet", "muted", "")

    chain_intact = vault.get("chain_intact", True)
    chain = _tile(
        "Custody chain", "Intact" if chain_intact else "BROKEN",
        f"{vault.get('case_count', 0)} case(s) in vault",
        "good" if chain_intact else "critical",
        "VERIFIED" if chain_intact else "TAMPERED",
    )
    snaps = _tile("Snapshots", f"{data.status.get('snapshot_count', 0):,}",
                  f"{intel.get('known_bad_hashes', 0)} known-bad hash(es)", "muted", "")
    return f'<div class="tiles">{rto}{rpo}{chain}{snaps}</div>'


def _tile(label: str, value: str, sub: str, tone: str, badge: str) -> str:
    badge_html = f'<span class="badge {tone}">{esc(badge)}</span>' if badge else ""
    return f"""
    <div class="tile">
      <div class="tile-label">{esc(label)}</div>
      <div class="tile-value {tone}">{value}</div>
      <div class="tile-sub">{sub} {badge_html}</div>
    </div>"""


def _render_recovery(data: DashboardData) -> str:
    """Recovery time per rebuild. Discrete events -> bars, not a line."""
    if not data.regenerations:
        return _section("Recovery history", _empty("No regenerations recorded yet."))

    peak = max(r.rto_seconds for r in data.regenerations) or 1.0
    bars = []
    for r in data.regenerations:
        height = max(2.0, 100.0 * r.rto_seconds / peak)
        passed = r.rto_pass and r.rpo_pass
        tone = "good" if passed else "critical"
        tip = (f"#{r.sequence} · {r.reason} · RTO {r.rto_seconds:.2f}s "
               f"· RPO {r.rpo_seconds:.2f}s · {'within target' if passed else 'MISSED TARGET'}"
               f" · {r.timestamp}")
        # A shape marker, not just a red bar: pass/fail must survive
        # colour-blindness and greyscale printing.
        marker = '' if passed else '<div class="bar-flag" aria-hidden="true">&#10007;</div>'
        bars.append(
            f'<div class="bar-slot" title="{esc(tip)}" tabindex="0">'
            f'{marker}<div class="bar {tone}" style="height:{height:.1f}%"></div>'
            f'<div class="bar-label">{r.sequence}</div></div>'
        )

    rows = "".join(
        f"<tr><td>{r.sequence}</td><td>{esc(r.timestamp)}</td><td>{esc(r.reason)}</td>"
        f"<td class='num'>{r.rto_seconds:.3f}</td><td class='num'>{r.rpo_seconds:.3f}</td>"
        f"<td>{_pill(r.rto_pass and r.rpo_pass)}</td></tr>"
        for r in data.regenerations
    )
    body = f"""
    <p class="cap">Recovery time per rebuild, newest right. Peak
       {peak:.2f}s against a {RTO_TARGET_SECONDS}s target &mdash; bars are
       scaled to the peak, not to the target, or every bar would be
       invisible. A &#10007; marks a rebuild that missed RTO or RPO.</p>
    <div class="chart" role="img" aria-label="Recovery time per rebuild">{''.join(bars)}</div>
    <details><summary>Table view</summary>
      <div class="scroll"><table>
        <thead><tr><th>#</th><th>Completed</th><th>Trigger</th>
          <th class="num">RTO (s)</th><th class="num">RPO (s)</th><th>Result</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
    </details>"""
    return _section("Recovery history", body)


def _render_providers(data: DashboardData) -> str:
    providers = data.status.get("providers", {})
    if not providers:
        return _section("Storage providers", _empty("No providers configured."))
    items = []
    for name, state in sorted(providers.items()):
        ok = state.startswith("available")
        items.append(
            f'<li><span class="swatch {"good" if ok else "critical"}"></span>'
            f'<code>{esc(name)}</code><span class="state">{esc(state)}</span></li>'
        )
    body = (f'<ul class="providers">{"".join(items)}</ul>'
            '<p class="cap">Blobs fan out to every available provider on write and '
            'fail over across them on read, so a single outage degrades rather than '
            'blocks recovery.</p>')
    return _section("Storage providers", body)


def _render_vault(data: DashboardData) -> str:
    vault = data.status.get("forensic_vault", {})
    problems = vault.get("problems", [])
    if problems:
        listed = "".join(f"<li>{esc(p)}</li>" for p in problems)
        banner = f'<div class="alert critical"><strong>Chain verification failed.</strong><ul>{listed}</ul></div>'
    else:
        banner = '<div class="alert good"><strong>Chain verified.</strong> Every entry commits to its predecessor.</div>'

    if not data.vault_entries:
        return _section("Forensic vault", banner + _empty("No evidence captured yet."))

    rows = "".join(
        f"<tr><td>{esc(getattr(e, 'sequence', ''))}</td><td>{esc(getattr(e, 'captured_at', ''))}</td>"
        f"<td><code>{esc(getattr(e, 'case_id', ''))}</code></td><td>{esc(getattr(e, 'reason', ''))}</td>"
        f"<td>{esc(getattr(e, 'custodian', ''))}</td>"
        f"<td><code class='hash'>{esc(str(getattr(e, 'entry_hash', ''))[:16])}…</code></td></tr>"
        for e in data.vault_entries
    )
    body = f"""{banner}
    <div class="scroll"><table>
      <thead><tr><th>Seq</th><th>Captured</th><th>Case</th><th>Reason</th>
        <th>Custodian</th><th>Entry hash</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    <p class="cap">An integrity ledger &mdash; it makes tampering detectable. It is
       not a legally defensible chain of custody, which additionally needs WORM
       storage, signed timestamps, and per-custodian signatures.</p>"""
    return _section("Forensic vault", body)


def _render_quarantine(data: DashboardData) -> str:
    if not data.quarantine_batches:
        return _section("Quarantine review queue", _empty("Nothing quarantined."))

    blocks = []
    for batch in data.quarantine_batches:
        rows = []
        for relpath, findings in sorted(batch.findings.items()):
            for finding in findings:
                sev = str(finding.get("severity", "")).lower()
                tone = {"high": "critical", "medium": "warning"}.get(sev, "muted")
                rows.append(
                    f"<tr><td><code>{esc(relpath)}</code></td>"
                    f"<td><code>{esc(finding.get('rule', ''))}</code></td>"
                    f"<td><span class='badge {tone}'>{esc(sev or 'n/a')}</span></td>"
                    f"<td>{esc(finding.get('reason', ''))}</td></tr>"
                )
        blocks.append(f"""
        <div class="batch">
          <h3>{esc(batch.batch_id)} <span class="count">{batch.file_count} file(s) held</span></h3>
          <div class="scroll"><table>
            <thead><tr><th>File</th><th>Rule</th><th>Severity</th><th>Finding</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table></div>
        </div>""")

    body = ("".join(blocks) +
            '<p class="cap">Held back from a restore, not deleted &mdash; the bytes are '
            'kept for review. Filenames here were chosen by whoever wrote the payload.</p>')
    return _section("Quarantine review queue", body)


def _render_compliance(data: DashboardData) -> str:
    report = data.compliance
    if report is None:
        return _section("Compliance evidence", _empty("No compliance report available."))

    rows = "".join(
        f"<tr><td><code>{esc(c.control_id)}</code></td><td>{esc(c.objective)}</td>"
        f"<td><code>{esc(c.evidence_source)}</code></td>"
        f"<td class='num'>{esc(c.event_count)}</td><td>{_pill(c.satisfied)}</td></tr>"
        for c in report.controls
    )
    gaps = "".join(f"<li>{esc(g)}</li>" for g in report.gaps)
    gaps_html = (f'<div class="alert warning"><strong>Gaps ({len(report.gaps)})</strong><ul>{gaps}</ul></div>'
                 if report.gaps else '<div class="alert good"><strong>No gaps reported.</strong></div>')
    body = f"""
    <div class="alert muted"><strong>Not a certification.</strong> {esc(report.disclaimer)}</div>
    {gaps_html}
    <div class="scroll"><table>
      <thead><tr><th>Control</th><th>Objective</th><th>Evidence</th>
        <th class="num">Events</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""
    return _section("Compliance evidence", body)


def _render_audit(data: DashboardData) -> str:
    if not data.audit_events:
        return _section("Audit trail", _empty("No audit events."))
    rows = []
    for event in reversed(data.audit_events):
        name = event.get("event", "")
        detail = {k: v for k, v in event.items() if k not in ("ts", "event")}
        rows.append(
            f"<tr><td class='ts'>{esc(event.get('ts', ''))}</td>"
            f"<td><code>{esc(name)}</code></td>"
            f"<td class='detail'>{esc(json.dumps(detail, default=str)) if detail else ''}</td></tr>"
        )
    body = (f'<div class="scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Detail</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
            '<p class="cap">Newest first, last 25. The audit log has no hash chain, '
            'unlike the vault &mdash; an administrator could edit it undetected.</p>')
    return _section("Audit trail", body)


def _section(title: str, body: str) -> str:
    return f'<section><h2>{esc(title)}</h2>{body}</section>'


def _empty(message: str) -> str:
    return f'<p class="empty">{esc(message)}</p>'


def _pill(ok: bool) -> str:
    return (f'<span class="badge {"good" if ok else "critical"}">'
            f'{"PASS" if ok else "FAIL"}</span>')


# -- page shell ---------------------------------------------------------------

_CSS = """
:root {
  color-scheme: light;
  --plane:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e;
  --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7;
  --series:#2a78d6;
  --good:#0ca30c; --warning:#fab219; --critical:#d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --plane:#0d0d0d; --surface:#1a1a19; --ink:#fff; --ink2:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --axis:#383835;
    --series:#3987e5;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --plane:#0d0d0d; --surface:#1a1a19; --ink:#fff; --ink2:#c3c2b7;
  --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --series:#3987e5;
}
* { box-sizing:border-box; }
body {
  margin:0; padding:clamp(16px,3vw,40px); background:var(--plane); color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
.wrap { max-width:1100px; margin:0 auto; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.9em; }
h1 { font-size:clamp(20px,3vw,26px); margin:0 0 4px; letter-spacing:-.01em; }
h2 { font-size:15px; margin:0 0 12px; text-transform:uppercase;
     letter-spacing:.07em; color:var(--ink2); }
h3 { font-size:14px; margin:0 0 8px; }
.head { display:flex; flex-wrap:wrap; gap:12px; align-items:center;
        justify-content:space-between; margin-bottom:6px; }
.sub { margin:0; color:var(--ink2); font-size:13px; }
.note { margin:0 0 24px; color:var(--muted); font-size:12px; }
.posture { display:flex; align-items:center; gap:8px; padding:6px 14px; border-radius:999px;
           font-size:13px; font-weight:600; border:1px solid var(--grid); background:var(--surface); }
.posture .dot { width:9px; height:9px; border-radius:50%; background:var(--muted); }
.posture.good .dot{background:var(--good)} .posture.good{color:var(--good)}
.posture.warning .dot{background:var(--warning)} .posture.warning{color:var(--ink)}
.posture.critical .dot{background:var(--critical)} .posture.critical{color:var(--critical)}
section { background:var(--surface); border:1px solid var(--grid); border-radius:12px;
          padding:18px; margin-bottom:16px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
         gap:12px; margin-bottom:16px; }
.tile { background:var(--surface); border:1px solid var(--grid); border-radius:12px; padding:16px; }
.tile-label { font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
.tile-value { font-size:28px; font-weight:650; letter-spacing:-.02em; margin:6px 0 4px;
              font-variant-numeric:tabular-nums; }
.tile-value.good{color:var(--good)} .tile-value.critical{color:var(--critical)}
.tile-value.muted{color:var(--ink2)}
.tile-sub { font-size:12px; color:var(--ink2); }
.badge { display:inline-block; padding:1px 7px; border-radius:999px; font-size:10px;
         font-weight:700; letter-spacing:.04em; border:1px solid currentColor; }
.badge.good{color:var(--good)} .badge.critical{color:var(--critical)}
.badge.warning{color:var(--ink2)} .badge.muted{color:var(--muted)}
.chart { display:flex; align-items:flex-end; justify-content:flex-start; gap:6px;
         height:150px; padding:8px 0 0; border-bottom:1px solid var(--axis); overflow-x:auto; }
/* Fixed slot width, not flex:1 -- with two or three rebuilds recorded,
   stretching would strand each bar in its own quadrant. */
.bar-slot { display:flex; flex-direction:column; justify-content:flex-end; align-items:center;
            flex:0 0 44px; height:100%; gap:4px; }
.bar { width:100%; max-width:44px; border-radius:4px 4px 0 0; background:var(--series);
       box-shadow:0 0 0 2px var(--surface); }
.bar.good { background:var(--series); }
.bar.critical { background:var(--critical); }
.bar-slot:hover .bar, .bar-slot:focus .bar { outline:2px solid var(--ink); outline-offset:1px; }
.bar-label { font-size:10px; color:var(--muted); font-variant-numeric:tabular-nums; }
.bar-flag { font-size:12px; line-height:1; color:var(--critical); font-weight:700; }
.cap { font-size:12px; color:var(--ink2); margin:10px 0 0; }
.empty { color:var(--muted); font-style:italic; margin:0; }
.scroll { overflow-x:auto; -webkit-overflow-scrolling:touch; }
table { border-collapse:collapse; width:100%; font-size:13px; min-width:520px; }
th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--grid);
         vertical-align:top; }
th { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted);
     font-weight:600; white-space:nowrap; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
td.ts { white-space:nowrap; color:var(--ink2); }
td.detail { color:var(--ink2); word-break:break-word; max-width:420px; }
.hash { color:var(--ink2); }
.providers { list-style:none; margin:0; padding:0; display:grid; gap:8px; }
.providers li { display:flex; align-items:center; gap:10px; }
.swatch { width:10px; height:10px; border-radius:50%; flex:none; }
.swatch.good{background:var(--good)} .swatch.critical{background:var(--critical)}
.state { color:var(--ink2); font-size:12px; }
.alert { border:1px solid var(--grid); border-left-width:3px; border-radius:8px;
         padding:10px 14px; margin:0 0 12px; font-size:13px; }
.alert ul { margin:6px 0 0; padding-left:18px; }
.alert.good{border-left-color:var(--good)}
.alert.warning{border-left-color:var(--warning)}
.alert.critical{border-left-color:var(--critical)}
.alert.muted{border-left-color:var(--muted); color:var(--ink2)}
.batch { margin-bottom:16px; }
.count { font-weight:400; color:var(--muted); font-size:12px; }
details { margin-top:12px; }
summary { cursor:pointer; font-size:12px; color:var(--ink2); }
"""

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
{header}
{tiles}
{recovery}
{providers}
{vault}
{quarantine}
{compliance}
{audit}
</div>
</body>
</html>
"""


def render_to_file(phantom, out_path: Path, compliance: bool = True) -> Path:
    data = collect(phantom, compliance=compliance)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(data), encoding="utf-8")
    return out_path
