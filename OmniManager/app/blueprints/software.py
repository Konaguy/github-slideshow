import threading
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required
from app.extensions import db, socketio
from app.models.endpoint import Endpoint
from app.models.software import Software, SoftwareScanResult
from app.services.software_service import SoftwareService

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
    ep = Endpoint.query.get_or_404(endpoint_id)
    room = f"sw_scan_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = SoftwareService(ep)
            results, err = svc.scan(socketio=socketio, room=room)
            if err:
                socketio.emit("sw_scan_error", {"error": err}, room=room)
            else:
                socketio.emit("sw_scan_complete", {"count": len(results)}, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    flash(f"Software scan started for {ep.hostname}.", "info")
    return redirect(url_for("software.index", endpoint_id=endpoint_id))


@software_bp.route("/uninstall/<int:software_id>", methods=["POST"])
@login_required
def uninstall(software_id):
    sw = SoftwareScanResult.query.get_or_404(software_id)
    ep = Endpoint.query.get_or_404(sw.endpoint_id)
    room = f"sw_uninstall_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = SoftwareService(ep)
            success, err = svc.uninstall(software_id, socketio=socketio, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    flash(f"Uninstall of '{sw.name}' started.", "info")
    return redirect(url_for("software.index", endpoint_id=ep.id))


@software_bp.route("/install", methods=["POST"])
@login_required
def install():
    endpoint_id = request.form.get("endpoint_id", type=int)
    catalog_id = request.form.get("catalog_id", type=int)

    ep = Endpoint.query.get_or_404(endpoint_id)
    sw = Software.query.get_or_404(catalog_id)
    room = f"sw_install_{ep.id}"

    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            svc = SoftwareService(ep)
            svc.remote_install(sw.install_command, sw.name, socketio=socketio, room=room)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    flash(f"Installing '{sw.name}' on {ep.hostname}…", "info")
    return redirect(url_for("software.index", endpoint_id=endpoint_id))
