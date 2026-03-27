import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required
from app.extensions import db, socketio
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.services.patch_service import PatchService

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
    ep = Endpoint.query.get_or_404(endpoint_id)
    room = f"patch_scan_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = PatchService(ep)
            results, err = svc.scan(socketio=socketio, room=room)
            if err:
                socketio.emit("scan_error", {"error": err}, room=room)
            else:
                socketio.emit("scan_complete", {"count": len(results)}, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    flash(f"Patch scan started for {ep.hostname}. Watch the live feed.", "info")
    return redirect(url_for("patches.scan_status", endpoint_id=ep.id))


@patches_bp.route("/scan/<int:endpoint_id>/status")
@login_required
def scan_status(endpoint_id):
    ep = Endpoint.query.get_or_404(endpoint_id)
    return render_template("patches/scan_status.html", endpoint=ep)


@patches_bp.route("/install", methods=["POST"])
@login_required
def install():
    endpoint_id = request.form.get("endpoint_id", type=int)
    kb_id = request.form.get("kb_id", "").strip()

    if not endpoint_id or not kb_id:
        flash("Endpoint and KB ID are required.", "danger")
        return redirect(url_for("patches.index"))

    ep = Endpoint.query.get_or_404(endpoint_id)
    room = f"patch_install_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = PatchService(ep)
            success, err = svc.install(kb_id, socketio=socketio, room=room)
            if not success:
                socketio.emit("install_error", {"kb_id": kb_id, "error": err}, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    flash(f"Installing KB{kb_id} on {ep.hostname}…", "info")
    return redirect(url_for("patches.index", endpoint_id=endpoint_id))


@patches_bp.route("/install-all", methods=["POST"])
@login_required
def install_all():
    endpoint_id = request.form.get("endpoint_id", type=int)
    ep = Endpoint.query.get_or_404(endpoint_id)
    missing = PatchScanResult.query.filter_by(endpoint_id=ep.id, status="missing").all()
    room = f"patch_install_all_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = PatchService(ep)
            for pr in missing:
                svc.install(pr.kb_id, socketio=socketio, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    flash(f"Installing {len(missing)} patches on {ep.hostname}…", "info")
    return redirect(url_for("patches.index", endpoint_id=endpoint_id))


@patches_bp.route("/dismiss/<int:result_id>", methods=["POST"])
@login_required
def dismiss(result_id):
    result = PatchScanResult.query.get_or_404(result_id)
    db.session.delete(result)
    db.session.commit()
    return jsonify({"ok": True})
