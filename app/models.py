from app import db


class Account(db.Model):
    __tablename__ = "Account"

    userId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    passwordHash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)

    completed_questions = db.relationship(
        "CompletedQuestion", back_populates="user", cascade="all, delete-orphan"
    )
    completed_ctfs = db.relationship(
        "CompletedCTF", back_populates="user", cascade="all, delete-orphan"
    )


class CTF(db.Model):
    __tablename__ = "CTF"

    ctfId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.Text, nullable=False)
    path = db.Column(db.String(512), nullable=False)
    flag = db.Column(db.String(255), nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="ctf", uselist=False)


class Vulnerability(db.Model):
    __tablename__ = "Vulnerability"

    vulnId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ctfId = db.Column(db.Integer, db.ForeignKey("CTF.ctfId"), nullable=True)

    ctf = db.relationship("CTF", back_populates="vulnerability")
    questions = db.relationship(
        "Question", back_populates="vulnerability", cascade="all, delete-orphan"
    )
    cve_links = db.relationship(
        "CVEVulnerability", back_populates="vulnerability", cascade="all, delete-orphan"
    )


class CVE(db.Model):
    __tablename__ = "CVE"

    cveId = db.Column(db.Text, primary_key=True)
    description = db.Column(db.Text, nullable=False)

    vuln_links = db.relationship(
        "CVEVulnerability", back_populates="cve", cascade="all, delete-orphan"
    )


class CVEVulnerability(db.Model):
    __tablename__ = "CVEVulnerability"

    cveId = db.Column(db.Text, db.ForeignKey("CVE.cveId"), primary_key=True)
    vulnId = db.Column(db.Integer, db.ForeignKey("Vulnerability.vulnId"), primary_key=True)

    cve = db.relationship("CVE", back_populates="vuln_links")
    vulnerability = db.relationship("Vulnerability", back_populates="cve_links")


class Question(db.Model):
    __tablename__ = "Question"

    questionId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vulnId = db.Column(db.Integer, db.ForeignKey("Vulnerability.vulnId"), nullable=False)
    questionNumber = db.Column(db.Integer, nullable=False)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)

    vulnerability = db.relationship("Vulnerability", back_populates="questions")
    hints = db.relationship(
        "Hint", back_populates="question", cascade="all, delete-orphan"
    )
    completed_by = db.relationship(
        "CompletedQuestion", back_populates="question", cascade="all, delete-orphan"
    )


class Hint(db.Model):
    __tablename__ = "Hint"

    hintId = db.Column(db.Integer, primary_key=True, autoincrement=True)
    questionId = db.Column(db.Integer, db.ForeignKey("Question.questionId"), nullable=False)
    hintNumber = db.Column(db.Integer, nullable=False)
    hint = db.Column(db.Text, nullable=False)

    question = db.relationship("Question", back_populates="hints")


class CompletedQuestion(db.Model):
    __tablename__ = "CompletedQuestion"

    userId = db.Column(db.Integer, db.ForeignKey("Account.userId"), primary_key=True)
    questionId = db.Column(db.Integer, db.ForeignKey("Question.questionId"), primary_key=True)

    user = db.relationship("Account", back_populates="completed_questions")
    question = db.relationship("Question", back_populates="completed_by")


class CompletedCTF(db.Model):
    __tablename__ = "CompletedCTF"

    userId = db.Column(db.Integer, db.ForeignKey("Account.userId"), primary_key=True)
    ctfId = db.Column(db.Integer, db.ForeignKey("CTF.ctfId"), primary_key=True)

    user = db.relationship("Account", back_populates="completed_ctfs")
    ctf = db.relationship("CTF")
