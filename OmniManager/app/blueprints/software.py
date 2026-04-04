import csv
import io
import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, Response
from flask_login import login_required
from app.extensions import db, socketio
from app.models.endpoint import Endpoint
from app.models.software import Software, SoftwareScanResult
from app.services.software_service import SoftwareService
from app.utils.bulk_scan import run_bulk_scan
from app.utils.audit import log_action

software_bp = Blueprint("software", __name__)


@software_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()
    endpoint_id = request.args.get("endpoint_id", type=int)

    query = SoftwareScanResult.query
    if q:
        query = query.filter(SoftwareScanResult.name.ilike(f"%{q}%"))
    if endpoint_id:
        query = query.filter_by(endpoint_id=endpoint_id)

    results = query.order_by(SoftwareScanResult.name).paginate(
        page=page, per_page=50, error_out=False
    )
    endpoints = Endpoint.query.order_by(Endpoint.hostname).all()
    return render_template(
        "software/index.html",
        results=results,
        endpoints=endpoints,
        q=q,
        endpoint_id=endpoint_id,
    )


@software_bp.route("/catalog")
@login_required
def catalog():
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()
    query = Software.query
    if q:
        query = query.filter(
            db.or_(
                Software.name.ilike(f"%{q}%"),
                Software.publisher.ilike(f"%{q}%"),
            )
        )
    catalog_items = query.order_by(Software.name).paginate(page=page, per_page=25, error_out=False)
    return render_template("software/catalog.html", catalog_items=catalog_items, q=q)


@software_bp.route("/catalog/add", methods=["GET", "POST"])
@login_required
def add_catalog():
    if request.method == "POST":
        sw = Software(
            name=request.form.get("name", "").strip(),
            publisher=request.form.get("publisher", "").strip(),
            version=request.form.get("version", "").strip(),
            install_command=request.form.get("install_command", "").strip(),
            uninstall_command=request.form.get("uninstall_command", "").strip(),
            silent_args=request.form.get("silent_args", "").strip(),
            category=request.form.get("category", "").strip(),
            description=request.form.get("description", "").strip(),
        )
        db.session.add(sw)
        db.session.commit()
        flash(f"'{sw.name}' added to catalog.", "success")
        return redirect(url_for("software.catalog"))
    return render_template("software/add_catalog.html")


@software_bp.route("/scan/<int:endpoint_id>", methods=["POST"])
@login_required
def scan(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    room = f"sw_scan_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = SoftwareService(ep_fresh)
            results, err = svc.scan(socketio=socketio, room=room)
            if err:
                socketio.emit("sw_scan_error", {"error": err}, to=room)
            else:
                socketio.emit("sw_scan_complete", {"count": len(results)}, to=room)

    threading.Thread(target=_run, daemon=True).start()
    flash(f"Software scan started for {ep_hostname}.", "info")
    return redirect(url_for("software.index", endpoint_id=endpoint_id))


@software_bp.route("/uninstall/<int:software_id>", methods=["POST"])
@login_required
def uninstall(software_id):
    sw = db.get_or_404(SoftwareScanResult, software_id)
    ep_id = sw.endpoint_id
    sw_name = sw.name
    room = f"sw_uninstall_{ep_id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = SoftwareService(ep_fresh)
            svc.uninstall(software_id, socketio=socketio, room=room)

    threading.Thread(target=_run, daemon=True).start()
    log_action("software.uninstall", object_type="software", object_id=software_id, detail=f"'{sw_name}' on endpoint {ep_id}")
    flash(f"Uninstall of '{sw_name}' started.", "info")
    return redirect(url_for("software.index", endpoint_id=ep_id))


@software_bp.route("/install", methods=["POST"])
@login_required
def install():
    endpoint_id = request.form.get("endpoint_id", type=int)
    catalog_id = request.form.get("catalog_id", type=int)

    ep = db.get_or_404(Endpoint, endpoint_id)
    sw = db.get_or_404(Software, catalog_id)
    room = f"sw_install_{ep.id}"
    ep_id = ep.id
    ep_hostname = ep.hostname
    sw_install_command = sw.install_command
    sw_name = sw.name

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            ep_fresh = db.session.get(Endpoint, ep_id)
            svc = SoftwareService(ep_fresh)
            svc.remote_install(sw_install_command, sw_name, socketio=socketio, room=room)

    threading.Thread(target=_run, daemon=True).start()
    log_action("software.install", object_type="software", object_id=catalog_id,
               detail=f"'{sw_name}' on {ep_hostname}")
    flash(f"Installing '{sw_name}' on {ep_hostname}…", "info")
    return redirect(url_for("software.index", endpoint_id=endpoint_id))


@software_bp.route("/scan-all", methods=["POST"])
@login_required
def scan_all():
    """Scan all online (and optionally unknown) endpoints for installed software."""
    include_unknown = request.form.get("include_unknown") == "1"
    statuses = ["online", "unknown"] if include_unknown else ["online"]
    endpoint_ids = [
        ep.id for ep in Endpoint.query.filter(Endpoint.status.in_(statuses)).all()
    ]
    if not endpoint_ids:
        flash("No online endpoints to scan.", "warning")
        return redirect(url_for("software.index"))

    app = current_app._get_current_object()

    def _scan(ep_id):
        ep = db.session.get(Endpoint, ep_id)
        SoftwareService(ep).scan()

    run_bulk_scan(app, endpoint_ids, _scan, label="software scan")
    flash(f"Software scan started on {len(endpoint_ids)} endpoint(s) — results will appear as scans complete.", "info")
    return redirect(url_for("software.index"))


@software_bp.route("/export")
@login_required
def export_csv():
    q_str = request.args.get("q", "").strip()
    endpoint_id = request.args.get("endpoint_id", type=int)

    query = SoftwareScanResult.query
    if q_str:
        query = query.filter(SoftwareScanResult.name.ilike(f"%{q_str}%"))
    if endpoint_id:
        query = query.filter_by(endpoint_id=endpoint_id)

    rows = query.order_by(SoftwareScanResult.name).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Endpoint", "Name", "Publisher", "Version", "Install Date", "Status"])
    for s in rows:
        w.writerow([
            s.endpoint.hostname,
            s.name,
            s.publisher or "",
            s.version or "",
            s.install_date or "",
            s.status,
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=software.csv"},
    )
