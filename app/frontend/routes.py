from flask import render_template, redirect, url_for

from app.frontend import frontend_bp


@frontend_bp.route("/")
def index():
    return redirect(url_for("frontend.login"))


@frontend_bp.route("/login")
def login():
    return render_template("login.html")


@frontend_bp.route("/register")
def register():
    return render_template("register.html")


@frontend_bp.route("/home")
def home():
    return render_template("home.html")


@frontend_bp.route("/vulnerability/<int:vuln_id>")
def vulnerability(vuln_id):
    return render_template("vulnerability.html", vuln_id=vuln_id)


@frontend_bp.route("/vulnerability/<int:vuln_id>/questions")
def questions(vuln_id):
    return render_template("questions.html", vuln_id=vuln_id)


@frontend_bp.route("/vulnerability/<int:vuln_id>/ctf")
def ctf(vuln_id):
    return render_template("ctf.html", vuln_id=vuln_id)


@frontend_bp.route("/cve/<string:cve_id>")
def cve(cve_id):
    return render_template("cve.html", cve_id=cve_id)


@frontend_bp.route("/account")
def account():
    return render_template("account.html")
