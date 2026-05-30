from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request

from app.api import api_bp
from app.models import CVE, Vulnerability
from app.validators import CVE_PATTERN


@api_bp.route("/cve/<string:cveId>", methods=["GET"])
def get_cve(cveId):
    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    if not CVE_PATTERN.match(cveId):
        return jsonify({"code": 400, "message": "Invalid CVE ID format (expected CVE-YYYY-NNNNN)"}), 400

    cve = CVE.query.get(cveId)
    if not cve:
        return jsonify({"code": 404, "message": "CVE not found"}), 404

    related = []
    for link in cve.vuln_links:
        v = Vulnerability.query.get(link.vulnId)
        if v:
            related.append({"vulnId": v.vulnId, "name": v.name})

    return jsonify(
        {"cveId": cve.cveId, "description": cve.description, "relatedVulnerabilities": related}
    ), 200
