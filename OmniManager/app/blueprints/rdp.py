import subprocess
import sys
import socket
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required
from app.extensions import db
from app.models.endpoint import Endpoint

rdp_bp = Blueprint("rdp", __name__)


def _launch_mstsc(ip_address, port=3389, username=None, fullscreen=False):
    """Launch mstsc.exe (Windows Remote Desktop) for the given host."""
    if sys.platform != "win32":
        return False, "RDP launch requires Windows (mstsc.exe)"

    args = ["mstsc", f"/v:{ip_address}:{port}"]
    if fullscreen:
        args.append("/f")
    if username:
        args.extend(["/u", username])

    try:
        subprocess.Popen(args, shell=False)
        return True, None
    except FileNotFoundError:
        return False, "mstsc.exe not found. Ensure Remote Desktop is available."
    except Exception as e:
        return False, str(e)


@rdp_bp.route("/")
@login_required
def index():
    endpoints = Endpoint.query.filter_by(status="online").order_by(Endpoint.hostname).all()
    all_endpoints = Endpoint.query.order_by(Endpoint.hostname).all()
    return render_template("rdp/index.html", endpoints=endpoints, all_endpoints=all_endpoints)


@rdp_bp.route("/launch/<int:endpoint_id>", methods=["POST"])
@login_required
def launch(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    port = request.form.get("port", 3389, type=int)
    fullscreen = bool(request.form.get("fullscreen"))
    username = request.form.get("username", ep.winrm_username or "").strip()

    success, err = _launch_mstsc(ep.ip_address, port=port, username=username, fullscreen=fullscreen)
    if success:
        flash(f"RDP session launched for {ep.hostname} ({ep.ip_address}).", "success")
    else:
        flash(f"RDP launch failed: {err}", "danger")

    return redirect(url_for("rdp.index"))


@rdp_bp.route("/launch/custom", methods=["POST"])
@login_required
def launch_custom():
    ip_address = request.form.get("ip_address", "").strip()
    port = request.form.get("port", 3389, type=int)
    username = request.form.get("username", "").strip()
    fullscreen = bool(request.form.get("fullscreen"))

    if not ip_address:
        flash("IP address is required.", "danger")
        return redirect(url_for("rdp.index"))

    success, err = _launch_mstsc(ip_address, port=port, username=username, fullscreen=fullscreen)
    if success:
        flash(f"RDP session launched for {ip_address}:{port}.", "success")
    else:
        flash(f"RDP launch failed: {err}", "danger")

    return redirect(url_for("rdp.index"))


@rdp_bp.route("/status/<int:endpoint_id>")
@login_required
def status(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    port = request.args.get("port", 3389, type=int)
    try:
        with socket.create_connection((ep.ip_address, port), timeout=3):
            reachable = True
    except Exception:
        reachable = False

    return jsonify({
        "hostname": ep.hostname,
        "ip_address": ep.ip_address,
        "port": port,
        "rdp_reachable": reachable,
    })
