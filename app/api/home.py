from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app import db
from app.api import api_bp
from app.models import Account, Vulnerability, CVE, CompletedQuestion, CompletedCTF


@api_bp.route("/home", methods=["GET"])
def home():
    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    user_id = int(get_jwt_identity())
    user = db.session.get(Account, user_id)
    if not user:
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    completed_question_ids = {
        cq.questionId
        for cq in CompletedQuestion.query.filter_by(userId=user_id).all()
    }
    completed_ctf_ids = {
        cc.ctfId
        for cc in CompletedCTF.query.filter_by(userId=user_id).all()
    }

    vuln_list = []
    for v in Vulnerability.query.all():
        total_questions = len(v.questions)
        done_questions = sum(1 for q in v.questions if q.questionId in completed_question_ids)

        # A module is complete only when its CTF challenge is solved.
        # If the vulnerability has no CTF, fall back to full question completion.
        if v.ctfId is not None:
            ctf_completed = v.ctfId in completed_ctf_ids
            progress = 1.0 if ctf_completed else 0.0
        else:
            ctf_completed = False
            progress = 1.0 if (total_questions > 0 and done_questions == total_questions) else 0.0

        vuln_list.append({
            "vulnId": v.vulnId,
            "name": v.name,
            "progress": progress,
            "ctfCompleted": ctf_completed,
            "questionsCompleted": done_questions,
            "questionsTotal": total_questions,
        })

    cve_list = [{"cveId": c.cveId} for c in CVE.query.all()]

    # --- CVE NATURAL SORTING IMPLEMENTATION ---
    def cve_sort_key(cve_dict):
        # Splits 'CVE-2026-1234' into ['CVE', '2026', '1234']
        parts = cve_dict["cveId"].split("-")
        try:
            # Sort by year (int) first, then sequence number (int)
            return (int(parts[1]), int(parts[2]))
        except (IndexError, ValueError):
            # Fallback to standard string sorting if formatting is unusual
            return (0, cve_dict["cveId"])

    cve_list.sort(key=cve_sort_key)
    # ------------------------------------------

    return jsonify({"username": user.username, "vulnerabilities": vuln_list, "cves": cve_list}), 200