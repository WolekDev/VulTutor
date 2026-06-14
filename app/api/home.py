from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from sqlalchemy import or_

from app import db
from app.api import api_bp
from app.models import Account, Vulnerability, CVE, CompletedQuestion, CompletedCTF, CVEVulnerability


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

    # --- PARSE QUERY PARAMETERS ---
    v_page = request.args.get("v_page", 1, type=int)
    v_search = request.args.get("v_search", "", type=str).strip()

    c_page = request.args.get("c_page", 1, type=int)
    c_search = request.args.get("c_search", "", type=str).strip()
    c_vuln_id = request.args.get("vuln_id", "", type=str).strip()

    # --- SEPARATED PER-PAGE LIMITS ---
    VULNS_PER_PAGE = 3  # Limited to 3 per page as requested
    CVES_PER_PAGE = 6   # Limited to 6 per page as requested

    # --- USER PROGRESS DATA ---
    completed_question_ids = {
        cq.questionId
        for cq in CompletedQuestion.query.filter_by(userId=user_id).all()
    }
    completed_ctf_ids = {
        cc.ctfId
        for cc in CompletedCTF.query.filter_by(userId=user_id).all()
    }

    # --- 1. VULNERABILITIES QUERY (with filtering & pagination) ---
    v_query = Vulnerability.query
    if v_search:
        v_query = v_query.filter(Vulnerability.name.ilike(f"%{v_search}%"))
    
    # Using the new VULNS_PER_PAGE limit
    v_pagination = v_query.paginate(page=v_page, per_page=VULNS_PER_PAGE, error_out=False)

    vuln_list = []
    for v in v_pagination.items:
        total_questions = len(v.questions)
        done_questions = sum(1 for q in v.questions if q.questionId in completed_question_ids)

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

    # --- 2. CVES QUERY (with advanced filtering & pagination) ---
    c_query = CVE.query
    
    # Filter by linked vulnerability if requested
    if c_vuln_id and c_vuln_id.isdigit():
        c_query = c_query.join(CVE.vuln_links).filter(CVEVulnerability.vulnId == int(c_vuln_id))
    
    # Filter by CVE code text string
    if c_search:
        c_query = c_query.filter(CVE.cveId.ilike(f"%{c_search}%"))

    # Natural sorting application before slicing for pagination
    all_filtered_cves = c_query.all()

    def cve_sort_key(cve_obj):
        parts = cve_obj.cveId.split("-")
        try:
            return (int(parts[1]), int(parts[2]))
        except (IndexError, ValueError):
            return (0, cve_obj.cveId)

    all_filtered_cves.sort(key=cve_sort_key)

    # Manual in-memory pagination windowing using CVES_PER_PAGE
    total_cves = len(all_filtered_cves)
    start_idx = (c_page - 1) * CVES_PER_PAGE
    end_idx = start_idx + CVES_PER_PAGE
    paginated_cves = all_filtered_cves[start_idx:end_idx]

    cve_list = [{"cveId": c.cveId} for c in paginated_cves]

    # --- 3. ALL VULNERABILITIES FOR FILTER DROP-DOWN ---
    filter_options = [{"vulnId": v.vulnId, "name": v.name} for v in Vulnerability.query.order_by(Vulnerability.name).all()]

    return jsonify({
        "username": user.username,
        "vulnerabilities": vuln_list,
        "v_pagination": {
            "current_page": v_page,
            "has_next": v_pagination.has_next,
            "has_prev": v_pagination.has_prev,
            "total_pages": v_pagination.pages
        },
        "cves": cve_list,
        "c_pagination": {
            "current_page": c_page,
            "has_next": end_idx < total_cves,
            "has_prev": start_idx > 0,
            "total_pages": (total_cves + CVES_PER_PAGE - 1) // CVES_PER_PAGE
        },
        "filter_options": filter_options
    }), 200