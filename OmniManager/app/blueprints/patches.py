import csv
import io
import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, Response
from flask_login import login_required
from app.extensions import db, socketio
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.services.patch_service import PatchService
from app.utils.bulk_scan import run_bulk_scan
from app.utils.audit import log_action

patches_bp = Blueprint("patches", __name__)


@patches_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "missing")
    endpoint_id = request.args.get("endpoint_id", type=int)

    query = PatchScanResult.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if endpoint_id:
        query = query.filter_by(endpoint_id=endpoint_id)

    results = query.order_by(PatchScanResult.scanned_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    endpoints = Endpoint.query.order_by(Endpoint.hostname).all()
    return render_template(
        "patches/index.html",
        results=results,
        endpoints=endpoints,
        severity_filter=severity_filter,
        status_filter=status_filter,
        endpoint_id=endpoint_id,
    )


@patches_bp.route("/scan/<int:endpoint_id>", methods=["POST"])
@login_required
def scan(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    room = f"patch_scan_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = PatchService(ep_fresh)
            results, err = svc.scan(socketio=socketio, room=room)
            if err:
                socketio.emit("scan_error", {"error": err}, to=room)
            else:
                socketio.emit("scan_complete", {"count": len(results)}, to=room)

    threading.Thread(target=_run, daemon=True).start()
    log_action("patch.scan", object_type="endpoint", object_id=ep_id, detail=ep_hostname)
    flash(f"Patch scan started for {ep_hostname}. Watch the live feed.", "info")
    return redirect(url_for("patches.scan_status", endpoint_id=ep_id))


@patches_bp.route("/scan/<int:endpoint_id>/status")
@login_required
def scan_status(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    return render_template("patches/scan_status.html", endpoint=ep)


@patches_bp.route("/install", methods=["POST"])
@login_required
def install():
    endpoint_id = request.form.get("endpoint_id", type=int)
    kb_id = request.form.get("kb_id", "").strip()

    if not endpoint_id or not kb_id:
        flash("Endpoint and KB ID are required.", "danger")
        return redirect(url_for("patches.index"))

    ep = db.get_or_404(Endpoint, endpoint_id)
    room = f"patch_install_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = PatchService(ep_fresh)
            success, err = svc.install(kb_id, socketio=socketio, room=room)
            if not success:
                socketio.emit("install_error", {"kb_id": kb_id, "error": err}, to=room)

    threading.Thread(target=_run, daemon=True).start()
    log_action("patch.install", object_type="patch", object_id=kb_id,
               detail=f"KB{kb_id} on {ep_hostname}")
    flash(f"Installing KB{kb_id} on {ep_hostname}…", "info")
    return redirect(url_for("patches.index", endpoint_id=endpoint_id))


@patches_bp.route("/install-all", methods=["POST"])
@login_required
def install_all():
    endpoint_id = request.form.get("endpoint_id", type=int)
    ep = db.get_or_404(Endpoint, endpoint_id)
    missing_kb_ids = [
        pr.kb_id for pr in
        PatchScanResult.query.filter_by(endpoint_id=ep.id, status="missing").all()
    ]
    room = f"patch_install_all_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = PatchService(ep_fresh)
            for kb_id in missing_kb_ids:
                svc.install(kb_id, socketio=socketio, room=room)

    threading.Thread(target=_run, daemon=True).start()
    flash(f"Installing {len(missing_kb_ids)} patches on {ep_hostname}…", "info")
    return redirect(url_for("patches.index", endpoint_id=endpoint_id))


@patches_bp.route("/scan-all", methods=["POST"])
@login_required
def scan_all():
    """Scan all online (and optionally unknown) endpoints for missing patches."""
    include_unknown = request.form.get("include_unknown") == "1"
    statuses = ["online", "unknown"] if include_unknown else ["online"]
    endpoint_ids = [
        ep.id for ep in Endpoint.query.filter(Endpoint.status.in_(statuses)).all()
    ]
    if not endpoint_ids:
        flash("No online endpoints to scan.", "warning")
        return redirect(url_for("patches.index"))

    app = current_app._get_current_object()

    def _scan(ep_id):
        ep = db.session.get(Endpoint, ep_id)
        PatchService(ep).scan()

    run_bulk_scan(app, endpoint_ids, _scan, label="patch scan")
    flash(f"Patch scan started on {len(endpoint_ids)} endpoint(s) — results will appear as scans complete.", "info")
    return redirect(url_for("patches.index"))


@patches_bp.route("/approval-queue")
@login_required
def approval_queue():
    pending = PatchScanResult.query.filter_by(status="missing", approved=False).order_by(
        PatchScanResult.scanned_at.desc()
    ).all()
    return render_template("patches/approval.html", pending=pending)


@patches_bp.route("/approve/<int:result_id>", methods=["POST"])
@login_required
def approve(result_id):
    from flask_login import current_user
    result = db.get_or_404(PatchScanResult, result_id)
    result.approved = True
    result.approved_by = current_user.username
    db.session.commit()
    log_action("patch.approve", object_type="patch", object_id=result_id,
               detail=f"KB{result.kb_id} approved for endpoint {result.endpoint_id}")
    return jsonify({"ok": True})


@patches_bp.route("/reject/<int:result_id>", methods=["POST"])
@login_required
def reject(result_id):
    result = db.get_or_404(PatchScanResult, result_id)
    db.session.delete(result)
    db.session.commit()
    log_action("patch.reject", object_type="patch", object_id=result_id)
    return jsonify({"ok": True})


@patches_bp.route("/dismiss/<int:result_id>", methods=["POST"])
@login_required
def dismiss(result_id):
    result = db.get_or_404(PatchScanResult, result_id)
    db.session.delete(result)
    db.session.commit()
    return jsonify({"ok": True})


@patches_bp.route("/export")
@login_required
def export_csv():
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "missing")
    endpoint_id = request.args.get("endpoint_id", type=int)

    query = PatchScanResult.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if endpoint_id:
        query = query.filter_by(endpoint_id=endpoint_id)

    rows = query.order_by(PatchScanResult.scanned_at.desc()).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Endpoint", "KB ID", "Title", "Severity", "Status", "Scanned At", "Installed At"])
    for r in rows:
        w.writerow([
            r.endpoint.hostname,
            r.kb_id,
            r.title or "",
            r.severity,
            r.status,
            r.scanned_at.strftime("%Y-%m-%d %H:%M") if r.scanned_at else "",
            r.installed_at.strftime("%Y-%m-%d %H:%M") if r.installed_at else "",
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=patches.csv"},
    )
