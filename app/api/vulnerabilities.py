from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from marshmallow import ValidationError

from app import db
from app.api import api_bp
from app.models import Vulnerability, Question, CTF, CompletedQuestion, CompletedCTF
from app.validators import AnswerSchema, FlagSchema

_answer_schema = AnswerSchema()
_flag_schema = FlagSchema()


def _require_auth():
    """Verify JWT and return (user_id, None) or (None, error_response)."""
    try:
        verify_jwt_in_request()
        return int(get_jwt_identity()), None
    except Exception:
        return None, (jsonify({"code": 401, "message": "Unauthorized"}), 401)


# ---------------------------------------------------------------------------
# GET /vulnerabilities/{vulnId}/description
# ---------------------------------------------------------------------------
@api_bp.route("/vulnerabilities/<int:vulnId>/description", methods=["GET"])
def get_vuln_description(vulnId):
    user_id, err = _require_auth()
    if err:
        return err

    vuln = db.session.get(Vulnerability, vulnId)
    if not vuln:
        return jsonify({"code": 404, "message": "Vulnerability not found"}), 404

    return jsonify({"vulnId": vuln.vulnId, "name": vuln.name, "description": vuln.description}), 200


# ---------------------------------------------------------------------------
# GET /vulnerabilities/{vulnId}/questions
# ---------------------------------------------------------------------------
@api_bp.route("/vulnerabilities/<int:vulnId>/questions", methods=["GET"])
def get_vuln_questions(vulnId):
    user_id, err = _require_auth()
    if err:
        return err

    vuln = db.session.get(Vulnerability, vulnId)
    if not vuln:
        return jsonify({"code": 404, "message": "Vulnerability not found"}), 404

    completed_ids = {
        cq.questionId
        for cq in CompletedQuestion.query.filter_by(userId=user_id).all()
    }

    questions = sorted(vuln.questions, key=lambda q: q.questionNumber)
    q_list = []
    for q in questions:
        hints = sorted(q.hints, key=lambda h: h.hintNumber)
        q_list.append(
            {
                "questionId": q.questionId,
                "questionNumber": q.questionNumber,
                "question": q.question,
                "completed": q.questionId in completed_ids,
                "hints": [
                    {"hintId": h.hintId, "hintNumber": h.hintNumber, "hint": h.hint}
                    for h in hints
                ],
            }
        )

    return jsonify({"vulnId": vulnId, "questions": q_list}), 200


# ---------------------------------------------------------------------------
# POST /vulnerabilities/{vulnId}/questions/{questionId}
# ---------------------------------------------------------------------------
@api_bp.route("/vulnerabilities/<int:vulnId>/questions/<int:questionId>", methods=["POST"])
def submit_answer(vulnId, questionId):
    user_id, err = _require_auth()
    if err:
        return err

    if not request.is_json:
        return jsonify({"code": 400, "message": "Request body must be JSON"}), 400

    try:
        data = _answer_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify({"code": 400, "message": exc.messages}), 400

    vuln = db.session.get(Vulnerability, vulnId)
    if not vuln:
        return jsonify({"code": 404, "message": "Vulnerability not found"}), 404

    question = Question.query.filter_by(questionId=questionId, vulnId=vulnId).first()
    if not question:
        return jsonify({"code": 404, "message": "Question not found"}), 404

    correct = data["answer"].strip().lower() == question.answer.strip().lower()

    if correct:
        if not CompletedQuestion.query.filter_by(userId=user_id, questionId=questionId).first():
            db.session.add(CompletedQuestion(userId=user_id, questionId=questionId))
            db.session.commit()
        return jsonify({"correct": True, "message": "Correct answer!"}), 200

    return jsonify({"correct": False, "message": "Incorrect answer. Try again!"}), 200


# ---------------------------------------------------------------------------
# GET /vulnerabilities/{vulnId}/ctf
# ---------------------------------------------------------------------------
@api_bp.route("/vulnerabilities/<int:vulnId>/ctf", methods=["GET"])
def get_ctf(vulnId):
    user_id, err = _require_auth()
    if err:
        return err

    vuln = db.session.get(Vulnerability, vulnId)
    if not vuln:
        return jsonify({"code": 404, "message": "Vulnerability not found"}), 404

    if not vuln.ctfId:
        return jsonify({"code": 404, "message": "No CTF challenge for this vulnerability"}), 404

    ctf = db.session.get(CTF, vuln.ctfId)
    completed = (
        CompletedCTF.query.filter_by(userId=user_id, ctfId=ctf.ctfId).first() is not None
    )

    return jsonify(
        {
            "ctfId": ctf.ctfId,
            "description": ctf.description,
            "path": ctf.path,
            "completed": completed,
        }
    ), 200


# ---------------------------------------------------------------------------
# POST /vulnerabilities/{vulnId}/ctf
# ---------------------------------------------------------------------------
@api_bp.route("/vulnerabilities/<int:vulnId>/ctf", methods=["POST"])
def submit_flag(vulnId):
    user_id, err = _require_auth()
    if err:
        return err

    if not request.is_json:
        return jsonify({"code": 400, "message": "Request body must be JSON"}), 400

    try:
        data = _flag_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return jsonify({"code": 400, "message": exc.messages}), 400

    vuln = db.session.get(Vulnerability, vulnId)
    if not vuln:
        return jsonify({"code": 404, "message": "Vulnerability not found"}), 404

    if not vuln.ctfId:
        return jsonify({"code": 404, "message": "No CTF challenge for this vulnerability"}), 404

    ctf = db.session.get(CTF, vuln.ctfId)
    correct = data["flag"].strip() == ctf.flag.strip()

    if correct:
        if not CompletedCTF.query.filter_by(userId=user_id, ctfId=ctf.ctfId).first():
            db.session.add(CompletedCTF(userId=user_id, ctfId=ctf.ctfId))
            db.session.commit()
        return jsonify({"correct": True, "message": "Correct! You successfully exploited the CTF challenge."}), 200

    return jsonify({"correct": False, "message": "Incorrect flag. Keep trying!"}), 200
