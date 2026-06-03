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
                "Use SQL injection to bypass the login form and authenticate as 'admin' without knowing the password.\n"
                "The backend query is:\n"
                "  SELECT * FROM users WHERE username='<input>' AND password='<input>'\n"
            ),
            path="/instance/ctf/sqli_login.zip",
            flag="sqli_bypass_success",
        )
        ctf_buff_over = CTF(
            description=(
                "You are using a self-checkout terminal at the supermarket.\n"
                "You need to access the admin dashboard.\n"
                "You know that the admin's user id is 0.\n"
            ),
            path="/instance/ctf/buffer_overflow.zip",
            flag="admin_dashboard_secret",
        )
        ctf_int_over = CTF(
            description=(
                "You want to buy a extremely anticipated game but you have absolutely no money to pay for it.\n"
                "The game store uses a 'Name Your Price' system (like itch.io) instead of a fixed price.\n"
                "You know the store uses uint16_t to store the price.\n"
            ),
            path="/instance/ctf/integer_overflow.zip",
            flag="yay_free_gta6",
        )
        ctf_race_cond = CTF(
            description=(
                "NOT IMPLEMENTED\n"
            ),
            path="/instance/ctf/race_condition.zip",
            flag="flag",
        )
        ctf_uaf = CTF(
            description=(
                "NOT IMPLEMENTED\n"
            ),
            path="/instance/ctf/use_after_free.zip",
            flag="flag",
        )
        db.session.add_all([ctf_sqli, ctf_buff_over, ctf_int_over, ctf_race_cond, ctf_uaf])
        db.session.flush()

        # ------------------------------------------------------------------
        # Vulnerabilities
        # ------------------------------------------------------------------
        vuln_sqli = Vulnerability(
            name="SQL Injection",
            ctfId=ctf_sqli.ctfId,
            description=(
                "SQL Injection (SQLi) is a web security vulnerability that allows an attacker "
                "to interfere with the database queries made by an application.\n\n"
                "Attackers can use it to:\n"
                "• View data they are not normally able to retrieve\n"
                "• Bypass authentication (e.g. login without a password)\n"
                "• Modify or delete data\n"
                "• In severe cases, execute OS commands on the server\n\n"
                "Example vulnerable query:\n"
                "  SELECT * FROM users WHERE username='<user>' AND password='<pass>'\n\n"
                "With input admin'-- this becomes:\n"
                "  SELECT * FROM users WHERE username='admin'--' AND password=''\n\n"
                "The -- comments out the password check, allowing login without a password.\n\n"
                "Prevention: use parameterised queries / prepared statements, validate and "
                "whitelist input, apply least-privilege to DB accounts."
            ),
        )
        vuln_buff_over = Vulnerability(
            name="Buffer Overflow",
            ctfId=ctf_buff_over.ctfId,
            description=(
                "Buffer Overflow is a memory corruption vulnerability that occurs when a "
                "program writes more data into a fixed-size buffer than it can hold. \n"
                "This can happen when using funcitons that dont bound check the buffer like gets() or strcpy() in C.\n\n"
                "Example vulnerable C code:\n"
                "  char buf[64];\n"
                "  strcpy(buf, user_input);\n\n"
                "If user_input exceeds 64 characters, the extra bytes overwrite adjacent stack "
                "memory such as saved frame pointers and return addresses.\n"
                "An attacker can use this overflow to overwrite the return address and redirect "
                "execution to injected code, or to corrupt control data and trigger a crash.\n\n"
                "Prevention: use bounds checked APIs, validate input sizes, "
                "or use memory-safe languages."
            ),
        )
        vuln_int_over = Vulnerability(
            name="Integer Overflow",
            ctfId=ctf_int_over.ctfId,
            description=(
                "Integer Overflow happens when an arithmetic operation produces a result that is "
                "too large for the variable's storage type.\n\n"
                "Example vulnerable C code:\n"
                "  uint8_t count = 0;\n"
                "  scanf(\"%zu\", &count);\n\n"
                "If the input is bugger than 255, count is wrap around and size becomes "
                "much smaller than expected. The program then allocates a buffer that is too "
                "small and a later write of count items overflows it.\n"
                "Unsigned overflow wraps around in C, while signed overflow is undefined behavior. "
                "Attackers can use this to bypass bounds checking and trigger memory corruption.\n\n"
                "Prevention: validate operands before arithmetic, use checked integer operations, "
                "and reject values that would overflow size calculations."
            ),
        )
        vuln_race_cond = Vulnerability(
            name="Race Condition",
            ctfId=ctf_race_cond.ctfId,
            description=(
                "A Race Condition occurs when multiple threads or processes access shared state "
                "without proper synchronization, so the result can depend on timing.\n\n"
                "The most common type is called TOCTOU (Time Of Check Time of Use).\n"
                "Example TOCTOU bug:\n"
                "  if (!file_exists(path)) {\n"
                "      create_file(path);\n"
                "  }\n\n"
                "If another thread or attacker changes the file between the existence check and the "
                "create operation, the program can behave incorrectly or create the wrong file.\n"
                "Another example is checking permissions on a resource and then using it later:\n"
                "  if (has_access(user, file)) open(file);\n"
                "An attacker can swap the file during the window and bypass authorization.\n"
                "Race conditions can lead to privilege escalation, data corruption, or security checks "
                "being bypassed.\n\n"
                "Prevention: use locks or atomic operations around shared resources, "
                "and keep critical sections small and protected."
            ),
        )
        vuln_uaf = Vulnerability(
            name="Use After Free",
            ctfId=ctf_uaf.ctfId,
            description=(
                "Use After Free is a memory safety bug where code continues to use a pointer "
                "after the memory it references has been freed.\n\n"
                "Example vulnerable C code:\n"
                "  char *p = malloc(64);\n"
                "  free(p);\n"
                "  strcpy(p, \"hello\");\n\n"
                "After free, p still points to the old address. If that block has been reused by "
                "another allocation, writing through p can corrupt the new object and may allow "
                "attacker-controlled data to influence execution.\n"
                "A use-after-free bug can be exploited to execute arbitrary code when the freed "
                "memory is recycled for attacker-controlled content.\n\n"
                "Prevention: set pointers to NULL after free or choose "
                "memory-safe languages."
            ),
        )
        db.session.add_all([vuln_sqli, vuln_buff_over, vuln_int_over, vuln_race_cond, vuln_uaf])
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

            # Buffer Overflow
            Question(vulnId=vuln_buff_over.vulnId, questionNumber=1,
                     question="Which unsafe C function reads input without checking the destination buffer size?",
                     answer="gets"),
            Question(vulnId=vuln_buff_over.vulnId, questionNumber=2,
                     question="The easiest way to prevent buffer overflow is to verify that the buffer is within its size limit. What is this called?",
                     answer="bound check"),

            # Integer Overflow
            Question(vulnId=vuln_int_over.vulnId, questionNumber=1,
                     question="What term describes when an arithmetic operation produces a value larger than the data type can represent?",
                     answer="overflow"),
            Question(vulnId=vuln_int_over.vulnId, questionNumber=2,
                     question=("In this vulnerable C code, after what value will the count variable overflow:\n"
                        "  uint8_t count = 0;\n"
                        "  scanf(\"%zu\", &count);\n"),
                     answer="255"),

            # Race Condition
            Question(vulnId=vuln_race_cond.vulnId, questionNumber=1,
                     question="What race condition variant occurs when a resource is checked and then used later, allowing its state to change in between?",
                     answer="TOCTOU"),
            Question(vulnId=vuln_race_cond.vulnId, questionNumber=2,
                     question="What concurrency primitive is often used to prevent race conditions by protecting a critical section?",
                     answer="lock"),

            # Use After Free
            Question(vulnId=vuln_uaf.vulnId, questionNumber=1,
                     question="What type of memory error occurs when code dereferences a pointer after the memory has been freed?",
                     answer="use after free"),
            Question(vulnId=vuln_uaf.vulnId, questionNumber=2,
                     question="After freeing memory, what safe value should you assign to the pointer?",
                     answer="NULL"),
        ]
        db.session.add_all(questions)
        db.session.flush()
        
        q_sqli = [q.questionId for q in questions if q.vulnId == vuln_sqli.vulnId]
        q_buff_over = [q.questionId for q in questions if q.vulnId == vuln_buff_over.vulnId]
        q_int_over = [q.questionId for q in questions if q.vulnId == vuln_int_over.vulnId]
        q_race_cond = [q.questionId for q in questions if q.vulnId == vuln_race_cond.vulnId]
        q_uaf = [q.questionId for q in questions if q.vulnId == vuln_uaf.vulnId]

        # ------------------------------------------------------------------
        # Hints
        # ------------------------------------------------------------------
        hints = [
            # SQLi Q1
            Hint(questionId=q_sqli[0], hintNumber=1,
                 hint="After what symbol in a line, everything is ignored?"),
            Hint(questionId=q_sqli[0], hintNumber=2,
                 hint="The single line comment in SQL"),

            # SQLi Q2
            Hint(questionId=q_sqli[1], hintNumber=1,
                 hint="Think about set operations"),
            Hint(questionId=q_sqli[1], hintNumber=2,
                 hint="A set operation that combines sets into one"),
            
            # Buffer Overflow Q1
            Hint(questionId=q_buff_over[0], hintNumber=1,
                hint="This unsafe C function was removed from the standard because it doesnt limit input length"),
            Hint(questionId=q_buff_over[0], hintNumber=2,
                hint="The function name is three letters and starts with 'g'"),

            # Buffer Overflow Q2
            Hint(questionId=q_buff_over[1], hintNumber=1,
                hint="A runtime check on the _____s of the buffer"),

            # Integer Overflow Q1
            Hint(questionId=q_int_over[0], hintNumber=1,
                hint="This word describes when a value exceeds the maximum representable range of its type."),
            Hint(questionId=q_int_over[0], hintNumber=2,
                hint="It is the opposite of underflow."),

            # Integer Overflow Q2
            Hint(questionId=q_int_over[1], hintNumber=1,
                hint="See the type of the count variable"),
            Hint(questionId=q_int_over[1], hintNumber=2,
                hint="What is the maximum value in a unsigned 8 bit integer?"),

            # Race Condition Q1
            Hint(questionId=q_race_cond[0], hintNumber=1,
                hint="Name for the sequence of checking and then using a resource."),
            Hint(questionId=q_race_cond[0], hintNumber=2,
                hint="It stands for time-of-check to time-of-use."),

            # Race Condition Q2
            Hint(questionId=q_race_cond[1], hintNumber=1,
                hint="This primitive allows only one thread to enter a critical section at a time."),
            Hint(questionId=q_race_cond[1], hintNumber=2,
                hint="It is often called a mutex or mutual exclusion object."),

            # Use After Free Q1
            Hint(questionId=q_uaf[0], hintNumber=1,
                hint="This error occurs after free when a stale pointer is used again."),
            Hint(questionId=q_uaf[0], hintNumber=2,
                hint="It is one of the common memory safety bugs in C/C++ along with buffer overflow and double free."),

            # Use After Free Q2
            Hint(questionId=q_uaf[1], hintNumber=1,
                hint="Setting a pointer to this value after free helps detect later accidental use."),
            Hint(questionId=q_uaf[1], hintNumber=2,
                hint="The safe value represents no valid memory address."),
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
                    "An error-based SQL Injection (SQLI) vulnerability in WebERP v4.15.2 allows"
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
            CVEVulnerability(cveId="CVE-2025-49717", vulnId=vuln_buff_over.vulnId),
            CVEVulnerability(cveId="CVE-2021-46667", vulnId=vuln_int_over.vulnId),
            CVEVulnerability(cveId="CVE-2026-33827", vulnId=vuln_race_cond.vulnId),
            CVEVulnerability(cveId="CVE-2026-2441", vulnId=vuln_uaf.vulnId),
        ]
        db.session.add_all(links)

        db.session.commit()

    print("Database seeded successfully!")
    print("Test credentials:")
    print("  Username : student")
    print("  Password : password123")


if __name__ == "__main__":
    seed()
