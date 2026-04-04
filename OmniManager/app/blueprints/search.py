from flask import Blueprint, render_template, request
from flask_login import login_required
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.software import SoftwareScanResult
from app.models.vulnerability import VulnerabilityScanResult

search_bp = Blueprint("search", __name__)

_MAX_PER_CATEGORY = 10


@search_bp.route("/")
@login_required
def results():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("search/results.html", q=q, categories=[])

    like = f"%{q}%"

    endpoints = Endpoint.query.filter(
        db.or_(
            Endpoint.hostname.ilike(like),
            Endpoint.ip_address.ilike(like),
            Endpoint.domain.ilike(like),
            Endpoint.tags.ilike(like),
        )
    ).limit(_MAX_PER_CATEGORY).all()

    patches = PatchScanResult.query.filter(
        db.or_(
            PatchScanResult.kb_id.ilike(like),
            PatchScanResult.title.ilike(like),
        )
    ).order_by(PatchScanResult.scanned_at.desc()).limit(_MAX_PER_CATEGORY).all()

    software = SoftwareScanResult.query.filter(
        db.or_(
            SoftwareScanResult.name.ilike(like),
            SoftwareScanResult.publisher.ilike(like),
        )
    ).order_by(SoftwareScanResult.name).limit(_MAX_PER_CATEGORY).all()

    vulns = VulnerabilityScanResult.query.filter(
        db.or_(
            VulnerabilityScanResult.cve_id.ilike(like),
            VulnerabilityScanResult.title.ilike(like),
            VulnerabilityScanResult.affected_component.ilike(like),
        )
    ).order_by(VulnerabilityScanResult.cvss_score.desc()).limit(_MAX_PER_CATEGORY).all()

    categories = [
        {"label": "Endpoints", "icon": "bi-pc-display", "items": endpoints, "type": "endpoint"},
        {"label": "Patches", "icon": "bi-patch-check", "items": patches, "type": "patch"},
        {"label": "Software", "icon": "bi-box-seam", "items": software, "type": "software"},
        {"label": "Vulnerabilities", "icon": "bi-shield-exclamation", "items": vulns, "type": "vuln"},
    ]

    return render_template("search/results.html", q=q, categories=categories)
