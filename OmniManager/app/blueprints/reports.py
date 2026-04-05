from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import func
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.vulnerability import VulnerabilityScanResult
from app.models.software import SoftwareScanResult

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/")
@login_required
def index():
    return render_template("reports/index.html")


@reports_bp.route("/patch-compliance")
@login_required
def patch_compliance():
    endpoints = Endpoint.query.order_by(Endpoint.hostname).all()

    rows = []
    for ep in endpoints:
        missing   = PatchScanResult.query.filter_by(endpoint_id=ep.id, status="missing").count()
        installed = PatchScanResult.query.filter_by(endpoint_id=ep.id, status="installed").count()
        critical  = PatchScanResult.query.filter_by(endpoint_id=ep.id, status="missing", severity="critical").count()
        total     = missing + installed
        pct       = round(installed / total * 100) if total else None
        rows.append({
            "endpoint": ep,
            "missing": missing,
            "installed": installed,
            "critical": critical,
            "total": total,
            "compliance_pct": pct,
        })

    total_missing   = sum(r["missing"] for r in rows)
    total_installed = sum(r["installed"] for r in rows)
    total_critical  = sum(r["critical"] for r in rows)

    return render_template(
        "reports/patch_compliance.html",
        rows=rows,
        total_missing=total_missing,
        total_installed=total_installed,
        total_critical=total_critical,
    )


@reports_bp.route("/vuln-summary")
@login_required
def vuln_summary():
    endpoints = Endpoint.query.order_by(Endpoint.hostname).all()

    rows = []
    for ep in endpoints:
        by_sev = dict(
            db.session.query(VulnerabilityScanResult.severity, func.count())
            .filter_by(endpoint_id=ep.id, status="open")
            .group_by(VulnerabilityScanResult.severity)
            .all()
        )
        total = sum(by_sev.values())
        if total or True:  # include endpoints with 0 vulns too
            rows.append({"endpoint": ep, "by_sev": by_sev, "total": total})

    rows.sort(key=lambda r: r["total"], reverse=True)

    severity_totals = {}
    for r in rows:
        for sev, cnt in r["by_sev"].items():
            severity_totals[sev] = severity_totals.get(sev, 0) + cnt

    return render_template(
        "reports/vuln_summary.html",
        rows=rows,
        severity_totals=severity_totals,
    )
