# Issue #17 — Weak Password Policy Enforced Client-Side Only

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/api/Auth/Register`   |
| **Severity**  | Medium                                                |
| **CVSS v3.1** | 5.3                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N                  |
| **Category**  | Broken Authentication — Weak Password Policy  |

---

## Summary

The registration page enforces a minimum password length of five characters via a client-side JavaScript check. This validation is not replicated on the server — the API endpoint `/api/Auth/Register` accepts and persists any password value, regardless of length or complexity, when the request is sent directly without passing through the browser's JavaScript execution context.

A single-character password was registered and used to authenticate successfully, confirming that the server applies no password policy whatsoever. In a banking application where account access controls protect financial assets, this represents a meaningful weakening of the authentication layer.

---

## Steps to Reproduce

1. Intercept or bypass the registration form entirely by sending a direct API request with a single-character password:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/Register" \
     -H "Content-Type: application/json" \
     -H "X-Requested-With: XMLHttpRequest" \
     -d '{"UserName":"[REDACTED]","Password":"p"}'
   ```

2. Observe that the server responds with `HTTP 200` and `{}`, confirming the account was created.
3. Immediately log in using the weak password:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/Login" \
     -H "Content-Type: application/json" \
     -d '{"UserName":"[REDACTED]","Password":"p"}'
   ```

4. Observe that the server issues a valid `SessionId` cookie, confirming authentication succeeded with a single-character password.

---

## Proof of Concept

### Stage 1 — Registration with Single-Character Password

The client-side validation that would normally block this is implemented as follows in the registration page source:

```javascript
if (document.getElementById("passwordConfirm").value.length < 5) {
    document.getElementById('notEnoughChars').style.display = 'block';
    document.getElementById('submitbutton').disabled = true;
    document.getElementById("passwordConfirm").classList.add("mystyle");
    return;
}
```

This check runs entirely in the browser. Bypassing it requires nothing more than sending the API request directly.

**Request:**

```http
POST /api/Auth/Register HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 46
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Origin: http://localhost:1337
Referer: http://localhost:1337/auth/register

{"UserName":"[REDACTED]","Password":"p"}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 15:58:55 GMT
Server: Kestrel
Content-Length: 2

{}
```

The account was created with a one-character password. No server-side rejection or validation error was returned.

---

### Stage 2 — Successful Login with Weak Password

**Request:**

```http
POST /api/Auth/Login HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 44
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Origin: http://localhost:1337
Referer: http://localhost:1337/auth/login

{"UserName":"[REDACTED]","Password":"p"}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 16:00:07 GMT
Server: Kestrel
Set-Cookie: SessionId=[REDACTED]; expires=Tue, 08 Jul 2025 16:00:07 GMT; path=/
Content-Length: 237

{"id":0,"userName":"[REDACTED]","password":null,...,"status":"ok",...}
```

A valid session was issued, confirming the weak password is accepted as a legitimate credential.

---

## Impact

- **Trivially brute-forceable accounts** — a one-character password drawn from a standard ASCII set has fewer than 100 possible values. In the absence of account lockout or rate limiting, this is exhausted in milliseconds. Any user who registers (or is registered) via the API with a weak password is effectively unprotected.
- **Client-side bypass is trivial** — the JavaScript validation requires no special tooling to circumvent. Any proxy (Burp Suite, mitmproxy) or a simple `curl` command is sufficient. Client-side-only validation provides no security guarantee and should never be treated as a control.
- **Compounding risk with plaintext storage** — as established in Issue #08, passwords are stored in plaintext. Weak passwords combined with plaintext storage mean that any database read access (via SQLi, path traversal, or backup exposure) yields immediately usable credentials with no cracking required.
- **Credential stuffing surface** — accounts created with common single-word or single-character passwords are immediately vulnerable to credential stuffing from any leaked password list, with no computation barrier.
- **Regulatory exposure** — financial services applications are typically subject to password complexity requirements under frameworks such as PCI-DSS (Requirement 8.3) and NIST SP 800-63B. The absence of server-side enforcement likely places the application out of compliance.

---

## Recommended Mitigations

1. **Enforce password policy server-side** at the API layer. Client-side validation should be treated as a UX convenience only — it must be mirrored by server-side validation that cannot be bypassed:

   ```csharp
   public class RegisterRequest
   {
       [Required]
       [MinLength(12, ErrorMessage = "Password must be at least 12 characters.")]
       [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$",
           ErrorMessage = "Password must contain uppercase, lowercase, digit, and special character.")]
       public string Password { get; set; }
   }
   ```

2. **Adopt NIST SP 800-63B guidance** for password policy: prioritise minimum length (at least 8 characters, ideally 12+) over complexity rules, and check new passwords against a list of known-compromised passwords (e.g. the HaveIBeenPwned dataset).

3. **Hash passwords using a strong, salted algorithm** before storage (bcrypt, Argon2, or PBKDF2). This is a prerequisite control that must accompany any password policy improvement — strong policies are rendered moot if the hash is weak or storage is plaintext (see Issue #08).

4. **Implement rate limiting and account lockout** on the login endpoint to prevent brute-force attacks against accounts with weak passwords that may already exist in the database.

5. **Update the client-side minimum** to match the server-side policy once it is implemented, so the UX feedback remains consistent with what the server will actually accept.