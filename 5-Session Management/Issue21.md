# Issue #21 — Insecure Session Cookie Design

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/api/Auth/Login`      |
| **Severity**  | Critical                                              |
| **CVSS v3.1** | 9.1                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N                 |
| **Category**  | Broken Authentication — Insecure Session Management  |

---

## Summary

The application implements a custom session cookie with a structured, partially readable format that embeds the authenticated user's email address and role directly as client-controlled fields. The cookie is not an opaque, randomly generated token — it is a composite value that encodes identity and privilege claims in a format that is trivially decodable and manipulable by any user.

The structure of the cookie was reverse-engineered through inspection of the login response and URL/base64 decoding. The three fields — username, HMAC, and role — are not cryptographically bound to one another, meaning either the username or the role can be independently substituted without invalidating the HMAC. This design flaw is the root cause of the horizontal privilege escalation (Issue #19), the vertical privilege escalation (Issue #20), and several of the IDOR vulnerabilities (Issue #18) documented elsewhere in this report.

---

## Steps to Reproduce

1. Log in to the application with any valid account:

   ```bash
   curl -si -X POST "http://localhost:1337/api/Auth/Login" \
     -H "Content-Type: application/json" \
     -d '{"UserName":"[REDACTED]","Password":"[REDACTED]"}' \
     | grep Set-Cookie
   ```

2. Capture the `SessionId` cookie value from the `Set-Cookie` response header.
3. URL-decode the cookie value.
4. Split the decoded string on `&` — observe three distinct segments.
5. Base64-decode the first segment — observe the authenticated user's email address in plaintext.
6. Note the third segment — observe the numeric role value (`0` for standard user, `100` for admin).
7. Modify either segment and re-encode — confirm the server accepts the modified cookie by accessing a protected endpoint.

---

## Proof of Concept

### Cookie Structure Analysis

**Login request:**

```http
POST /api/Auth/Login HTTP/1.1
Host: localhost:1337
Content-Type: application/json

{"UserName":"[REDACTED]","Password":"[REDACTED]"}
```

**Login response (Set-Cookie header):**

```http
HTTP/1.1 200 OK
Set-Cookie: SessionId=[REDACTED-ENCODED]; expires=Thu, 10 Jul 2025 09:24:12 GMT; path=/
```

The login response body also returns the cookie value in plaintext inside the JSON response under the `cookie` field — a separate information disclosure that confirms the cookie is human-readable by design.

### Decoding the Cookie

Starting from the raw cookie value, the following decoding chain reveals its structure:

**Step 1 — URL decode:**

```
[REDACTED-BASE64]==&[REDACTED-HMAC]&100
```

**Step 2 — Split on `&`:**

| Segment | Value | Meaning |
|---------|-------|---------|
| 1 | `[REDACTED-BASE64]==` | base64-encoded user email |
| 2 | `[REDACTED-HMAC]` | 64-character hex string (HMAC or hash) |
| 3 | `100` | UserRight / role value |

**Step 3 — base64-decode segment 1:**

```
[REDACTED-EMAIL]
```

The authenticated user's full email address is stored in the cookie in base64 — a trivially reversible encoding, not encryption.

### HMAC Does Not Bind All Fields

The critical flaw is that the HMAC in segment 2 does not authenticate both segment 1 and segment 3 together. As demonstrated in Issues #18, #19, and #20:

- Replacing segment 1 (the email) while keeping segment 2 (the HMAC) unchanged results in a cookie the server accepts, allowing impersonation of arbitrary users
- Replacing segment 3 (the role) from `0` to `100` while keeping segment 2 unchanged results in a cookie the server accepts with admin privileges

This confirms that the HMAC either covers only one field, or is not verified at all server-side.

---

## Impact

This finding is the architectural root cause of multiple critical vulnerabilities confirmed throughout this assessment:

- **Issue #18 (IDOR — Store History)** — exploited by replacing the email segment to read another user's purchase history
- **Issue #19 (Horizontal Privilege Escalation — BuyProduct)** — exploited by replacing the email segment to charge purchases to a victim's account
- **Issue #20 (Vertical Privilege Escalation — Cookie Role Manipulation)** — exploited by changing the role segment from `0` to `100` to gain admin access
- **Username and role disclosure** — any authenticated user can decode their own cookie and read their email and role claim. If the cookie is ever leaked (via XSS, network interception, or logs), the victim's identity and privilege level are immediately apparent with no cryptographic attack required.
- **No session invalidation surface** — because the cookie is stateless and self-describing, the server has no server-side session record to invalidate. This means stolen cookies cannot be revoked without a full re-architecture, and password changes (Issue #16) do not automatically expire active sessions.
- **Login response leaks raw cookie** — the JSON body of the login response includes the full cookie value in a `cookie` field alongside the session header. This double-disclosure increases the likelihood of the value being logged, cached, or intercepted.

---

## Recommended Mitigations

1. **Replace the custom cookie with a cryptographically random, opaque session token.** The token should be a securely generated random value (minimum 128 bits) that maps to a server-side session record. No identity or role information should be derivable from the token itself:

   ```csharp
   // Generate a secure random session token
   var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

   // Store identity and role server-side, keyed by the token
   _sessionStore.Set(token, new SessionData
   {
       Username = user.UserName,
       Role = user.Role,
       Expiry = DateTime.UtcNow.AddHours(24)
   });

   Response.Cookies.Append("SessionId", token, new CookieOptions
   {
       HttpOnly = true,
       Secure = true,
       SameSite = SameSiteMode.Strict
   });
   ```

2. **Never embed user identity or role claims in a client-side cookie.** All session attributes — including username and privileges — must be stored server-side and retrieved by the server using the opaque token. The client should have no visibility into these values.

3. **If a stateless token format is preferred**, adopt a standard signed format such as JWT with a strong algorithm (e.g. HS256 or RS256), ensuring all claims — including role — are covered by the signature. The signing key must be kept server-side and never derived from user-visible data.

4. **Invalidate sessions server-side on password change and logout.** A server-side session store enables explicit revocation — if a password is changed, all existing session tokens for that account can be deleted from the store, preventing session reuse after an account takeover.

5. **Remove the `cookie` field from the login response body.** Returning the session token in both the `Set-Cookie` header and the JSON response body doubles the exposure surface with no benefit to the legitimate client. The browser handles the cookie automatically via the header; the JSON field is unnecessary and potentially harmful.

6. **Set `HttpOnly` and `Secure` flags on the session cookie** to prevent JavaScript access and restrict transmission to HTTPS connections:

   ```csharp
   new CookieOptions
   {
       HttpOnly = true,   // Prevents XSS-based cookie theft
       Secure = true,     // HTTPS only
       SameSite = SameSiteMode.Strict  // CSRF mitigation
   }
   ```