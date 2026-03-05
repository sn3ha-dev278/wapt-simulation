# Web Application Penetration Testing - Simulation

A web application penetration testing report series conducted against a deliberately vulnerable banking application built on ASP.NET Core (Kestrel). This portfolio documents 23 findings across six vulnerability categories, ranging from Low-severity information disclosures to Critical-severity privilege escalation chains.

The assessment was conducted as a practical exercise to demonstrate proficiency in web application penetration testing methodology, manual exploitation, and professional security reporting.

---

## Target

| Field | Details |
|---|---|
| **Application** | A deliberately vulnerable banking web application |
| **Stack** | ASP.NET Core / Kestrel / Microsoft SQL Server 2022 / Linux (Ubuntu 22.04) |
| **Base URL** | `http://localhost:1337` |
| **Assessment Type** | Black-box Web Application Penetration Test (WAPT) |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite Professional | Proxy, CSRF PoC generation, Collaborator (OOB exfiltration) |
| Gobuster | Directory and endpoint enumeration |
| ffuf | Parameter fuzzing |
| SecLists | Wordlists for enumeration and fuzzing |
| exiftool | PDF metadata extraction |
| curl | Manual HTTP request crafting |


---


## Notable Attack Chains

The findings in this assessment are not isolated — several form multi-stage exploitation chains that demonstrate how low-severity disclosures can escalate into critical compromise:

**Chain 1 — Database Compromise via SQLi**
Issue #04 (unmanaged error on `'`) → Issue #08 (UNION-based SQLi) → full plaintext credential dump for all users

**Chain 2 — Source Code Retrieval via Information Disclosure + Path Traversal**
Issue #03 (stack trace exposes `/app/Services/UploadFileBL.cs`) → Issue #11 (path traversal retrieves full source file) → XXE indicator discovered in source

**Chain 3 — Internal Network Exfiltration via SSRF**
Issue #01 (Swagger exposes `storeapi:8080`) → Issue #12 (SSRF reaches internal API) → Issue #11 (path traversal exfiltrates stored response)

**Chain 4 — Admin Account Takeover via XSS + Insecure Password Update**
Issue #09 Vector B (stored XSS fires on `/admin`) → session cookie stolen → Issue #16 (no current password required) → admin password reset → persistent admin access

**Chain 5 — Unauthenticated Full Admin Access**
Issue #05 (HTML comment discloses `/api/Auth/RegisterAdmin`) → Issue #20 Vector A (unauthenticated admin registration) → Issue #13 (root RCE via admin panel command injection)

**Chain 6 — Financial Fraud via Cookie Manipulation**
Issue #21 (insecure cookie structure identified) → Issue #18 Vector D (cookie email substitution reads victim purchase history) → Issue #19 Vector B (cookie manipulation charges purchases to victim account)

---

## Report Structure

Each report follows a consistent bug bounty writeup format:

- **Metadata table** — target, severity, CVSS score, vector, category
- **Summary** — concise description of the vulnerability and its significance
- **Steps to Reproduce** — numbered, command-line reproducible steps
- **Proof of Concept** — raw HTTP requests and responses with sensitive data redacted
- **Impact** — specific, contextualised consequences for this application
- **Recommended Mitigations** — concrete, implementation-specific fixes with code examples

Sensitive data including session cookies, credentials, email addresses, UUIDs, and internal hostnames has been redacted throughout all reports.
