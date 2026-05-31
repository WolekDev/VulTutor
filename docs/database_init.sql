-- =============================================================
-- VulTutor
-- =============================================================

-- Account: stores user credentials and profile info
CREATE TABLE Account (
    userId       INT          NOT NULL,
    username     VARCHAR(255) NOT NULL,
    passwordHash VARCHAR(255) NOT NULL,
    email        VARCHAR(255) NOT NULL,
    CONSTRAINT pk_account PRIMARY KEY (userId)
);

-- CTF: capture-the-flag challenges with a hidden flag
CREATE TABLE CTF (
    ctfId       INT          NOT NULL,
    description TEXT         NOT NULL,
    path        VARCHAR(512) NOT NULL,
    flag        VARCHAR(255) NOT NULL,
    CONSTRAINT pk_ctf PRIMARY KEY (ctfId)
);

-- Vulnerability: security vulnerability modules, optionally linked to a CTF
CREATE TABLE Vulnerability (
    vulnId      INT          NOT NULL,
    name        VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL,
    ctfId       INT          NULL,
    CONSTRAINT pk_vulnerability  PRIMARY KEY (vulnId),
    CONSTRAINT fk_vuln_ctf       FOREIGN KEY (ctfId) REFERENCES CTF (ctfId)
);

-- CVE: Common Vulnerabilities and Exposures records
CREATE TABLE CVE (
    cveId       TEXT NOT NULL,
    description TEXT NOT NULL,
    CONSTRAINT pk_cve PRIMARY KEY (cveId)
);

-- CVEVulnerability: many-to-many link between CVE records and vulnerability modules
CREATE TABLE CVEVulnerability (
    cveId  TEXT NOT NULL,
    vulnId INT  NOT NULL,
    CONSTRAINT pk_cve_vulnerability PRIMARY KEY (cveId, vulnId),
    CONSTRAINT fk_cvevuln_cve       FOREIGN KEY (cveId)  REFERENCES CVE (cveId),
    CONSTRAINT fk_cvevuln_vuln      FOREIGN KEY (vulnId) REFERENCES Vulnerability (vulnId)
);

-- Question: quiz questions belonging to a vulnerability module
CREATE TABLE Question (
    questionId     INT  NOT NULL,
    vulnId         INT  NOT NULL,
    questionNumber INT  NOT NULL,
    question       TEXT NOT NULL,
    answer         TEXT NOT NULL,
    CONSTRAINT pk_question      PRIMARY KEY (questionId),
    CONSTRAINT fk_question_vuln FOREIGN KEY (vulnId) REFERENCES Vulnerability (vulnId)
);

-- Hint: ordered hints that belong to a question
CREATE TABLE Hint (
    hintId      INT  NOT NULL,
    questionId  INT  NOT NULL,
    hintNumber  INT  NOT NULL,
    hint        TEXT NOT NULL,
    CONSTRAINT pk_hint           PRIMARY KEY (hintId),
    CONSTRAINT fk_hint_question  FOREIGN KEY (questionId) REFERENCES Question (questionId)
);

-- CompletedQuestion: tracks which questions a user has answered
CREATE TABLE CompletedQuestion (
    userId     INT NOT NULL,
    questionId INT NOT NULL,
    CONSTRAINT pk_completed_question      PRIMARY KEY (userId, questionId),
    CONSTRAINT fk_compq_account           FOREIGN KEY (userId)     REFERENCES Account (userId),
    CONSTRAINT fk_compq_question          FOREIGN KEY (questionId) REFERENCES Question (questionId)
);

-- CompletedCTF: tracks which CTF challenges a user has finished
CREATE TABLE CompletedCTF (
    userId INT NOT NULL,
    ctfId  INT NOT NULL,
    CONSTRAINT pk_completed_ctf   PRIMARY KEY (userId, ctfId),
    CONSTRAINT fk_compctf_account FOREIGN KEY (userId) REFERENCES Account (userId),
    CONSTRAINT fk_compctf_ctf     FOREIGN KEY (ctfId)  REFERENCES CTF (ctfId)
);