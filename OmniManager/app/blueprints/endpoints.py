from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required
from sqlalchemy import select
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.software import SoftwareScanResult
from app.models.vulnerability import VulnerabilityScanResult
from app.models.metric import EndpointMetric
from app.services.winrm_service import WinRMService
from app.utils.audit import log_action

endpoints_bp = Blueprint("endpoints", __name__)


@endpoints_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "")

    query = Endpoint.query
    if q:
        query = query.filter(
            db.or_(
                Endpoint.hostname.ilike(f"%{q}%"),
                Endpoint.ip_address.ilike(f"%{q}%"),
                Endpoint.domain.ilike(f"%{q}%"),
            )
        )
    if status_filter in ("online", "offline", "unknown"):
        query = query.filter_by(status=status_filter)

    endpoints = query.order_by(Endpoint.hostname).paginate(page=page, per_page=25, error_out=False)
    return render_template("endpoints/index.html", endpoints=endpoints, q=q, status_filter=status_filter)


@endpoints_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        if not hostname or not ip_address:
            flash("Hostname and IP address are required.", "danger")
            return redirect(url_for("endpoints.new"))

        ep = Endpoint(
            hostname=hostname,
            ip_address=ip_address,
            domain=request.form.get("domain", "").strip(),
            winrm_username=request.form.get("winrm_username", "").strip(),
            winrm_password=request.form.get("winrm_password", ""),
            winrm_port=int(request.form.get("winrm_port") or 5985),
            winrm_transport=request.form.get("winrm_transport", "ntlm"),
            tags=request.form.get("tags", "").strip(),
            notes=request.form.get("notes", "").strip(),
        )
        db.session.add(ep)
        db.session.commit()
        log_action("endpoint.create", object_type="endpoint", object_id=ep.id,
                   detail=f"{hostname} ({ip_address})")
        flash(f"Endpoint '{hostname}' added.", "success")
        return redirect(url_for("endpoints.detail", endpoint_id=ep.id))

    return render_template("endpoints/new.html")


@endpoints_bp.route("/<int:endpoint_id>")
@login_required
def detail(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)

    recent_patches = db.session.scalars(
        select(PatchScanResult)
        .where(PatchScanResult.endpoint_id == ep.id)
        .order_by(PatchScanResult.scanned_at.desc())
        .limit(50)
    ).all()

    recent_software = db.session.scalars(
        select(SoftwareScanResult)
        .where(SoftwareScanResult.endpoint_id == ep.id)
        .order_by(SoftwareScanResult.name)
        .limit(50)
    ).all()

    recent_vulns = db.session.scalars(
        select(VulnerabilityScanResult)
        .where(VulnerabilityScanResult.endpoint_id == ep.id)
        .order_by(VulnerabilityScanResult.cvss_score.desc())
        .limit(50)
    ).all()

    return render_template(
        "endpoints/detail.html",
        endpoint=ep,
        recent_patches=recent_patches,
        recent_software=recent_software,
        recent_vulns=recent_vulns,
    )


@endpoints_bp.route("/<int:endpoint_id>/edit", methods=["GET", "POST"])
@login_required
def edit(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)

    if request.method == "POST":
        ep.hostname = request.form.get("hostname", ep.hostname).strip()
        ep.ip_address = request.form.get("ip_address", ep.ip_address).strip()
        ep.domain = request.form.get("domain", "").strip()
        ep.winrm_username = request.form.get("winrm_username", "").strip()
        new_pw = request.form.get("winrm_password", "")
        if new_pw:
            ep.winrm_password = new_pw
        ep.winrm_port = int(request.form.get("winrm_port") or 5985)
        ep.winrm_transport = request.form.get("winrm_transport", "ntlm")
        ep.tags = request.form.get("tags", "").strip()
        ep.notes = request.form.get("notes", "").strip()
        db.session.commit()
        flash("Endpoint updated.", "success")
        return redirect(url_for("endpoints.detail", endpoint_id=ep.id))

    return render_template("endpoints/edit.html", endpoint=ep)


@endpoints_bp.route("/<int:endpoint_id>/delete", methods=["POST"])
@login_required
def delete(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    name = ep.hostname
    db.session.delete(ep)
    db.session.commit()
    log_action("endpoint.delete", object_type="endpoint", object_id=endpoint_id,
               detail=name)
    flash(f"Endpoint '{name}' deleted.", "success")
    return redirect(url_for("endpoints.index"))


@endpoints_bp.route("/<int:endpoint_id>/ping", methods=["POST"])
@login_required
def ping(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    svc = WinRMService(ep)
    reachable = svc.ping()
    ep.status = "online" if reachable else "offline"
    ep.last_ping = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": ep.status, "reachable": reachable})


@endpoints_bp.route("/<int:endpoint_id>/refresh", methods=["POST"])
@login_required
def refresh(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    svc = WinRMService(ep)
    info, err = svc.get_system_info()
    if err:
        return jsonify({"error": err}), 400

    ep.os_name = info.get("OSName", ep.os_name)
    ep.os_version = info.get("OSVersion", ep.os_version)
    ep.architecture = info.get("Architecture", ep.architecture)
    ep.domain = info.get("Domain", ep.domain)
    ep.last_user = info.get("LastUser", ep.last_user)
    ep.status = "online"
    ep.last_seen = datetime.utcnow()
    db.session.commit()
    flash("Endpoint information refreshed.", "success")
    return redirect(url_for("endpoints.detail", endpoint_id=ep.id))


@endpoints_bp.route("/import", methods=["GET", "POST"])
@login_required
def import_csv():
    if request.method == "POST":
        csv_file = request.files.get("csv_file")
        if not csv_file:
            flash("No file uploaded.", "danger")
            return redirect(url_for("endpoints.import_csv"))

        import csv, io
        stream = io.StringIO(csv_file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)
        added = 0
        for row in reader:
            hostname = (row.get("hostname") or "").strip()
            ip = (row.get("ip_address") or "").strip()
            if not hostname or not ip:
                continue
            if not Endpoint.query.filter_by(hostname=hostname).first():
                ep = Endpoint(
                    hostname=hostname,
                    ip_address=ip,
                    domain=row.get("domain", "").strip(),
                    winrm_username=row.get("winrm_username", "").strip(),
                    winrm_password=row.get("winrm_password", ""),
                    tags=row.get("tags", "").strip(),
                )
                db.session.add(ep)
                added += 1
        db.session.commit()
        flash(f"Imported {added} endpoint(s).", "success")
        return redirect(url_for("endpoints.index"))

    return render_template("endpoints/import.html")


@endpoints_bp.route("/<int:endpoint_id>/metrics", methods=["POST"])
@login_required
def collect_metrics(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    svc = WinRMService(ep)
    script = (
        "$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average;"
        "$os = Get-CimInstance Win32_OperatingSystem;"
        "$disk = Get-PSDrive C;"
        "$ramPct = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1);"
        "$ramFreeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2);"
        "$diskTotalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2);"
        "$diskFreeGB = [math]::Round($disk.Free / 1GB, 2);"
        "$diskPct = [math]::Round($disk.Used / ($disk.Used + $disk.Free) * 100, 1);"
        "Write-Output \"$cpu|$ramPct|$ramFreeGB|$diskPct|$diskFreeGB|$diskTotalGB\""
    )
    result, err = svc.run_ps(script)
    if err:
        return jsonify({"error": err}), 400
    try:
        parts = result.strip().split("|")
        m = EndpointMetric(
            endpoint_id=ep.id,
            cpu_percent=float(parts[0]),
            ram_percent=float(parts[1]),
            ram_free_gb=float(parts[2]),
            disk_percent=float(parts[3]),
            disk_free_gb=float(parts[4]),
            disk_total_gb=float(parts[5]),
        )
        db.session.add(m)
        db.session.commit()
        return jsonify({
            "cpu_percent": m.cpu_percent,
            "ram_percent": m.ram_percent,
            "ram_free_gb": m.ram_free_gb,
            "disk_percent": m.disk_percent,
            "disk_free_gb": m.disk_free_gb,
            "disk_total_gb": m.disk_total_gb,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@endpoints_bp.route("/import-ad", methods=["GET", "POST"])
@login_required
def import_ad():
    if request.method == "POST":
        server = request.form.get("server", "").strip()
        base_dn = request.form.get("base_dn", "").strip()
        bind_user = request.form.get("bind_user", "").strip()
        bind_pass = request.form.get("bind_pass", "")

        if not server or not base_dn:
            flash("Server and Base DN are required.", "danger")
            return redirect(url_for("endpoints.import_ad"))

        try:
            from ldap3 import Server as LdapServer, Connection, ALL, SUBTREE
            ldap_srv = LdapServer(server, get_info=ALL)
            conn_kwargs = {"auto_bind": True}
            if bind_user:
                conn_kwargs["user"] = bind_user
                conn_kwargs["password"] = bind_pass
            conn = Connection(ldap_srv, **conn_kwargs)
            conn.search(
                base_dn,
                "(objectCategory=computer)",
                search_scope=SUBTREE,
                attributes=["dNSHostName", "operatingSystem", "name"],
            )
            added = 0
            for entry in conn.entries:
                hostname = str(entry.dNSHostName or entry.name).strip()
                if not hostname:
                    continue
                if not Endpoint.query.filter_by(hostname=hostname).first():
                    ep = Endpoint(
                        hostname=hostname,
                        ip_address="0.0.0.0",
                        os_name=str(entry.operatingSystem) if entry.operatingSystem else None,
                    )
                    db.session.add(ep)
                    added += 1
            db.session.commit()
            log_action("endpoint.import_ad", detail=f"Imported {added} endpoints from {server}")
            flash(f"AD import complete — {added} new endpoint(s) added.", "success")
            return redirect(url_for("endpoints.index"))
        except ImportError:
            flash("ldap3 package not installed. Run: pip install ldap3", "danger")
        except Exception as exc:
            flash(f"AD import failed: {exc}", "danger")

    return render_template("endpoints/import_ad.html")
