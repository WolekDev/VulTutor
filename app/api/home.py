from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.api import api_bp
from app.models import Account, Vulnerability, CVE, CompletedQuestion, CompletedCTF


@api_bp.route("/home", methods=["GET"])
def home():
    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify({"code": 401, "message": "Unauthorized"}), 401

    user_id = int(get_jwt_identity())
    user = Account.query.get(user_id)
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

    return jsonify({"username": user.username, "vulnerabilities": vuln_list, "cves": cve_list}), 200
