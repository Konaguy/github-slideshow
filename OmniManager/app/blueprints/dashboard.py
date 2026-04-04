from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.vulnerability import VulnerabilityScanResult

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    # ── KPI counts ────────────────────────────────────────────────────────────
    total_endpoints = Endpoint.query.count()
    online  = Endpoint.query.filter_by(status="online").count()
    offline = Endpoint.query.filter_by(status="offline").count()
    unknown = Endpoint.query.filter_by(status="unknown").count()

    missing_patches  = PatchScanResult.query.filter_by(status="missing").count()
    critical_patches = PatchScanResult.query.filter_by(status="missing", severity="critical").count()
    installed_patches = PatchScanResult.query.filter_by(status="installed").count()

    total_vulns   = VulnerabilityScanResult.query.filter_by(status="open").count()
    critical_vulns = VulnerabilityScanResult.query.filter_by(status="open", severity="critical").count()

    recent_endpoints = Endpoint.query.order_by(Endpoint.updated_at.desc()).limit(5).all()

    # ── Chart: patch severity breakdown (missing only) ────────────────────────
    patch_severity_rows = (
        db.session.query(PatchScanResult.severity, func.count(PatchScanResult.id))
        .filter_by(status="missing")
        .group_by(PatchScanResult.severity)
        .all()
    )
    patch_severity = {row[0]: row[1] for row in patch_severity_rows}

    # ── Chart: vulnerability severity breakdown (open only) ───────────────────
    vuln_severity_rows = (
        db.session.query(VulnerabilityScanResult.severity, func.count(VulnerabilityScanResult.id))
        .filter_by(status="open")
        .group_by(VulnerabilityScanResult.severity)
        .all()
    )
    vuln_severity = {row[0]: row[1] for row in vuln_severity_rows}

    return render_template(
        "dashboard/index.html",
        # KPI
        total_endpoints=total_endpoints,
        online=online,
        offline=offline,
        unknown=unknown,
        missing_patches=missing_patches,
        critical_patches=critical_patches,
        installed_patches=installed_patches,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        recent_endpoints=recent_endpoints,
        # Chart data
        patch_severity=patch_severity,
        vuln_severity=vuln_severity,
    )
