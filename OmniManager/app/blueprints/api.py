from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.extensions import db
from app.models.endpoint import Endpoint
from app.models.patch import PatchScanResult
from app.models.software import SoftwareScanResult
from app.models.vulnerability import VulnerabilityScanResult

api_bp = Blueprint("api", __name__)


def _endpoint_dict(ep):
    return {
        "id": ep.id,
        "hostname": ep.hostname,
        "ip_address": ep.ip_address,
        "domain": ep.domain,
        "os_name": ep.os_name,
        "os_version": ep.os_version,
        "architecture": ep.architecture,
        "status": ep.status,
        "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
        "tags": ep.tag_list,
    }


def _patch_dict(p):
    return {
        "id": p.id,
        "endpoint_id": p.endpoint_id,
        "kb_id": p.kb_id,
        "title": p.title,
        "severity": p.severity,
        "status": p.status,
        "scanned_at": p.scanned_at.isoformat() if p.scanned_at else None,
    }


def _sw_dict(s):
    return {
        "id": s.id,
        "endpoint_id": s.endpoint_id,
        "name": s.name,
        "publisher": s.publisher,
        "version": s.version,
        "status": s.status,
        "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
    }


def _vuln_dict(v):
    return {
        "id": v.id,
        "endpoint_id": v.endpoint_id,
        "cve_id": v.cve_id,
        "title": v.title,
        "severity": v.severity,
        "cvss_score": v.cvss_score,
        "status": v.status,
        "scanned_at": v.scanned_at.isoformat() if v.scanned_at else None,
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@api_bp.route("/endpoints")
@login_required
def list_endpoints():
    eps = Endpoint.query.order_by(Endpoint.hostname).all()
    return jsonify([_endpoint_dict(e) for e in eps])


@api_bp.route("/endpoints/<int:endpoint_id>")
@login_required
def get_endpoint(endpoint_id):
    ep = db.get_or_404(Endpoint, endpoint_id)
    return jsonify(_endpoint_dict(ep))


@api_bp.route("/endpoints/<int:endpoint_id>/patches")
@login_required
def endpoint_patches(endpoint_id):
    db.get_or_404(Endpoint, endpoint_id)
    patches = PatchScanResult.query.filter_by(endpoint_id=endpoint_id).all()
    return jsonify([_patch_dict(p) for p in patches])


@api_bp.route("/endpoints/<int:endpoint_id>/software")
@login_required
def endpoint_software(endpoint_id):
    db.get_or_404(Endpoint, endpoint_id)
    software = SoftwareScanResult.query.filter_by(endpoint_id=endpoint_id).all()
    return jsonify([_sw_dict(s) for s in software])


@api_bp.route("/endpoints/<int:endpoint_id>/vulnerabilities")
@login_required
def endpoint_vulnerabilities(endpoint_id):
    db.get_or_404(Endpoint, endpoint_id)
    vulns = VulnerabilityScanResult.query.filter_by(endpoint_id=endpoint_id).all()
    return jsonify([_vuln_dict(v) for v in vulns])


# ── Summary stats ──────────────────────────────────────────────────────────────

@api_bp.route("/stats")
@login_required
def stats():
    return jsonify({
        "endpoints": {
            "total": Endpoint.query.count(),
            "online": Endpoint.query.filter_by(status="online").count(),
            "offline": Endpoint.query.filter_by(status="offline").count(),
            "unknown": Endpoint.query.filter_by(status="unknown").count(),
        },
        "patches": {
            "missing": PatchScanResult.query.filter_by(status="missing").count(),
            "critical": PatchScanResult.query.filter_by(status="missing", severity="critical").count(),
            "installed": PatchScanResult.query.filter_by(status="installed").count(),
        },
        "vulnerabilities": {
            "open": VulnerabilityScanResult.query.filter_by(status="open").count(),
            "critical": VulnerabilityScanResult.query.filter_by(status="open", severity="critical").count(),
            "mitigated": VulnerabilityScanResult.query.filter_by(status="mitigated").count(),
        },
    })


# ── Patch actions ──────────────────────────────────────────────────────────────

@api_bp.route("/patches/scan", methods=["POST"])
@login_required
def scan_patches():
    data = request.get_json(force=True, silent=True) or {}
    endpoint_id = data.get("endpoint_id")
    if not endpoint_id:
        return jsonify({"error": "endpoint_id required"}), 400

    ep = db.get_or_404(Endpoint, endpoint_id)
    from app.services.patch_service import PatchService
    svc = PatchService(ep)
    results, err = svc.scan()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"scanned": len(results)})


@api_bp.route("/patches/install", methods=["POST"])
@login_required
def install_patch():
    data = request.get_json(force=True, silent=True) or {}
    endpoint_id = data.get("endpoint_id")
    kb_id = data.get("kb_id", "").strip()
    if not endpoint_id or not kb_id:
        return jsonify({"error": "endpoint_id and kb_id required"}), 400

    ep = db.get_or_404(Endpoint, endpoint_id)
    from app.services.patch_service import PatchService
    svc = PatchService(ep)
    success, err = svc.install(kb_id)
    if not success:
        return jsonify({"error": err}), 500
    return jsonify({"installed": kb_id})
