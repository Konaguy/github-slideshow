from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.group import EndpointGroup
from app.utils.audit import log_action
from app.utils.bulk_scan import run_bulk_scan

groups_bp = Blueprint("groups", __name__)


@groups_bp.route("/")
@login_required
def index():
    groups = EndpointGroup.query.order_by(EndpointGroup.name).all()
    return render_template("groups/index.html", groups=groups)


@groups_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "POST":
        name  = request.form.get("name", "").strip()
        desc  = request.form.get("description", "").strip()
        color = request.form.get("color", "#6366f1").strip()
        if not name:
            flash("Name is required.", "danger")
            return redirect(url_for("groups.new"))
        if EndpointGroup.query.filter_by(name=name).first():
            flash("A group with that name already exists.", "danger")
            return redirect(url_for("groups.new"))
        g = EndpointGroup(name=name, description=desc, color=color)
        db.session.add(g)
        db.session.commit()
        log_action("group.create", object_type="group", object_id=g.id, detail=name)
        flash(f"Group '{name}' created.", "success")
        return redirect(url_for("groups.detail", group_id=g.id))
    return render_template("groups/new.html")


@groups_bp.route("/<int:group_id>")
@login_required
def detail(group_id):
    group = db.get_or_404(EndpointGroup, group_id)
    all_endpoints = Endpoint.query.order_by(Endpoint.hostname).all()
    return render_template("groups/detail.html", group=group, all_endpoints=all_endpoints)


@groups_bp.route("/<int:group_id>/members", methods=["POST"])
@login_required
def update_members(group_id):
    group = db.get_or_404(EndpointGroup, group_id)
    selected_ids = request.form.getlist("endpoint_ids", type=int)
    group.members = Endpoint.query.filter(Endpoint.id.in_(selected_ids)).all()
    db.session.commit()
    flash(f"Group members updated ({len(selected_ids)} endpoint(s)).", "success")
    return redirect(url_for("groups.detail", group_id=group_id))


@groups_bp.route("/<int:group_id>/delete", methods=["POST"])
@login_required
def delete(group_id):
    group = db.get_or_404(EndpointGroup, group_id)
    name = group.name
    db.session.delete(group)
    db.session.commit()
    log_action("group.delete", object_type="group", object_id=group_id, detail=name)
    flash(f"Group '{name}' deleted.", "success")
    return redirect(url_for("groups.index"))


@groups_bp.route("/<int:group_id>/scan-patches", methods=["POST"])
@login_required
def scan_patches(group_id):
    group = db.get_or_404(EndpointGroup, group_id)
    endpoint_ids = [ep.id for ep in group.members if ep.status == "online"]
    if not endpoint_ids:
        flash("No online endpoints in this group.", "warning")
        return redirect(url_for("groups.detail", group_id=group_id))
    app = current_app._get_current_object()
    def _scan(ep_id):
        from app.services.patch_service import PatchService
        ep = db.session.get(Endpoint, ep_id)
        if ep: PatchService(ep).scan()
    run_bulk_scan(app, endpoint_ids, _scan, label=f"group patch scan [{group.name}]")
    flash(f"Patch scan started for {len(endpoint_ids)} endpoint(s) in '{group.name}'.", "info")
    return redirect(url_for("groups.detail", group_id=group_id))
