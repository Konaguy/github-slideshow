from flask import Blueprint, render_template
from flask_login import login_required
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.software import SoftwareScanResult
from app.models.vulnerability import VulnerabilityScanResult

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    total_endpoints = Endpoint.query.count()
    online = Endpoint.query.filter_by(status="online").count()
    offline = Endpoint.query.filter_by(status="offline").count()
    unknown = Endpoint.query.filter_by(status="unknown").count()

    missing_patches = PatchScanResult.query.filter_by(status="missing").count()
    critical_patches = PatchScanResult.query.filter_by(status="missing", severity="critical").count()

    total_vulns = VulnerabilityScanResult.query.filter_by(status="open").count()
    critical_vulns = VulnerabilityScanResult.query.filter_by(status="open", severity="critical").count()

    recent_endpoints = Endpoint.query.order_by(Endpoint.updated_at.desc()).limit(5).all()

    return render_template(
        "dashboard/index.html",
        total_endpoints=total_endpoints,
        online=online,
        offline=offline,
        unknown=unknown,
        missing_patches=missing_patches,
        critical_patches=critical_patches,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        recent_endpoints=recent_endpoints,
    )
