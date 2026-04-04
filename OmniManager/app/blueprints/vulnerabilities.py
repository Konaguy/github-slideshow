import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required
from app.extensions import db, socketio
from app.models.endpoint import Endpoint
from app.models.vulnerability import VulnerabilityScanResult
from app.services.vuln_service import VulnerabilityService
from app.utils.bulk_scan import run_bulk_scan

vulnerabilities_bp = Blueprint("vulnerabilities", __name__)


@vulnerabilities_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "open")
    endpoint_id = request.args.get("endpoint_id", type=int)

    query = VulnerabilityScanResult.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if endpoint_id:
        query = query.filter_by(endpoint_id=endpoint_id)

    results = query.order_by(
        VulnerabilityScanResult.cvss_score.desc(),
        VulnerabilityScanResult.scanned_at.desc()
    ).paginate(page=page, per_page=50, error_out=False)

    endpoints = Endpoint.query.order_by(Endpoint.hostname).all()
    return render_template(
        "vulnerabilities/index.html",
        results=results,
        endpoints=endpoints,
        severity_filter=severity_filter,
        status_filter=status_filter,
        endpoint_id=endpoint_id,
    )


@vulnerabilities_bp.route("/scan/<int:endpoint_id>", methods=["POST"])
@login_required
def scan(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    room = f"vuln_scan_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = VulnerabilityService(ep_fresh)
            results, err = svc.scan(socketio=socketio, room=room)
            if err:
                socketio.emit("vuln_scan_error", {"error": err}, to=room)
            else:
                socketio.emit("vuln_scan_complete", {"count": len(results)}, to=room)

    threading.Thread(target=_run, daemon=True).start()
    flash(f"Vulnerability scan started for {ep_hostname}.", "info")
    return redirect(url_for("vulnerabilities.index", endpoint_id=endpoint_id))


@vulnerabilities_bp.route("/<int:vuln_id>/status", methods=["POST"])
@login_required
def update_status(vuln_id):
    vuln = db.get_or_404(VulnerabilityScanResult, vuln_id)
    ep = db.get_or_404(Endpoint, vuln.endpoint_id)
    new_status = request.form.get("status", "").strip()

    svc = VulnerabilityService(ep)
    success, err = svc.update_status(vuln_id, new_status)
    if success:
        flash(f"Vulnerability {vuln.cve_id} status updated to '{new_status}'.", "success")
    else:
        flash(f"Error: {err}", "danger")

    return redirect(url_for("vulnerabilities.index", endpoint_id=ep.id))


@vulnerabilities_bp.route("/<int:vuln_id>")
@login_required
def detail(vuln_id):
    vuln = db.get_or_404(VulnerabilityScanResult, vuln_id)
    ep = db.get_or_404(Endpoint, vuln.endpoint_id)
    return render_template("vulnerabilities/detail.html", vuln=vuln, endpoint=ep)


@vulnerabilities_bp.route("/summary")
@login_required
def summary():
    from sqlalchemy import func
    by_severity = db.session.query(
        VulnerabilityScanResult.severity,
        func.count(VulnerabilityScanResult.id)
    ).filter_by(status="open").group_by(VulnerabilityScanResult.severity).all()

    by_endpoint = db.session.query(
        Endpoint.hostname,
        func.count(VulnerabilityScanResult.id)
    ).join(VulnerabilityScanResult, Endpoint.id == VulnerabilityScanResult.endpoint_id
    ).filter(VulnerabilityScanResult.status == "open"
    ).group_by(Endpoint.hostname
    ).order_by(func.count(VulnerabilityScanResult.id).desc()
    ).limit(10).all()

    return render_template("vulnerabilities/summary.html", by_severity=by_severity, by_endpoint=by_endpoint)


@vulnerabilities_bp.route("/scan-all", methods=["POST"])
@login_required
def scan_all():
    """Scan all online (and optionally unknown) endpoints for vulnerabilities."""
    include_unknown = request.form.get("include_unknown") == "1"
    statuses = ["online", "unknown"] if include_unknown else ["online"]
    endpoint_ids = [
        ep.id for ep in Endpoint.query.filter(Endpoint.status.in_(statuses)).all()
    ]
    if not endpoint_ids:
        flash("No online endpoints to scan.", "warning")
        return redirect(url_for("vulnerabilities.index"))

    app = current_app._get_current_object()

    def _scan(ep_id):
        ep = db.session.get(Endpoint, ep_id)
        VulnerabilityService(ep).scan()

    run_bulk_scan(app, endpoint_ids, _scan, label="vulnerability scan")
    flash(f"Vulnerability scan started on {len(endpoint_ids)} endpoint(s) — results will appear as scans complete.", "info")
    return redirect(url_for("vulnerabilities.index"))
