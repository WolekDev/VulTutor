# Tables

## `Account`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `userId` | INT | PRIMARY KEY | Unique identifier for each user |
| `username` | VARCHAR | NOT NULL | Display name used for login and UI |
| `passwordHash` | VARCHAR | NOT NULL | Bcrypt/hashed password (never plaintext) |
| `email` | VARCHAR | NOT NULL | User's email address |

---

## `Vulnerability`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `vulnId` | INT | PRIMARY KEY | Unique identifier for the vulnerability |
| `name` | VARCHAR | NOT NULL | Short name/title of the vulnerability (e.g. "SQL Injection") |
| `description` | TEXT | NOT NULL | Full description of the vulnerability |
| `ctfId` | INT | FOREIGN KEY -> `CTF.ctfId` | Associated CTF challenge, if any |

---

## `CTF`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `ctfId` | INT | PRIMARY KEY | Unique identifier for the CTF challenge |
| `description` | TEXT | NOT NULL | Overview of the CTF scenario |
| `path` | VARCHAR | NOT NULL | File system or URL path to the challenge resources |
| `flag` | VARCHAR | NOT NULL | The correct flag string the user must find |

---

## `Question`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `questionId` | INT | PRIMARY KEY | Unique identifier for the question |
| `vulnId` | INT | FOREIGN KEY -> `Vulnerability.vulnId` | The vulnerability this question belongs to |
| `questionNumber` | INT | NOT NULL | Ordering number of the question within its module |
| `question` | TEXT | NOT NULL | The question text shown to the user |
| `answer` | TEXT | NOT NULL | The correct answer |

---

## `Hint`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `hintId` | INT | PRIMARY KEY | Unique identifier for the hint |
| `questionId` | INT | FOREIGN KEY -> `Question.questionId` | The question this hint belongs to |
| `hintNumber` | INT | NOT NULL | Order in which hints should be revealed |
| `hint` | TEXT | NOT NULL | The hint text shown to the user |

---

## `CVE`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `cveId` | TEXT | PRIMARY KEY | Unique identifier for the CVE record |
| `description` | TEXT | NOT NULL | Description of the CVE |

---

## `CVEVulnerability`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `cveId` | TEXT | FOREIGN KEY -> `CVE.cveId` | Reference to the CVE |
| `vulnId` | INT | FOREIGN KEY -> `Vulnerability.vulnId` | Reference to the vulnerability module |

---

## `CompletedQuestion`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `userId` | INT | FOREIGN KEY -> `Account.userId` | The user who completed the question |
| `questionId` | INT | FOREIGN KEY -> `Question.questionId` | The question that was completed |

---

## `CompletedCTF`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `userId` | INT | FOREIGN KEY -> `Account.userId` | The user who completed the CTF |
| `ctfId` | INT | FOREIGN KEY -> `CTF.ctfId` | The CTF challenge that was completed |
