# Issue #05 — Sensitive Admin Endpoint Disclosed via HTML Comment

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/auth/register`  |
| **Severity**  | Medium                                           |
| **CVSS v3.1** | 5.3                                              |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure / Security Misconfiguration |

---

## Summary

The application's registration page (`/auth/register`) contains JavaScript code commented out within the HTML source that references a privileged API endpoint: `/api/Auth/RegisterAdmin`. The comment includes a fully functional AJAX call — complete with the HTTP method, endpoint path, expected request body structure, and field names — that would allow any user to register an admin account. Although the code is not executed in the rendered page, it is trivially discoverable by anyone who views the page source, requiring no tools beyond a browser.

This constitutes a significant access control weakness: the existence and interface of a sensitive admin registration endpoint is exposed to the public, dramatically reducing the effort required to abuse it.

---

## Steps to Reproduce

1. Navigate to `http://localhost:1337/auth/register` in any browser.
2. Open the page source (`Ctrl+U` in most browsers, or right-click → **View Page Source**).
3. Search for `RegisterAdmin` or `btnRegister` in the source.
4. Observe the commented-out JavaScript block disclosing the `/api/Auth/RegisterAdmin` endpoint, the expected JSON payload structure, and the field names `UserName` and `Password`.
5. Using the disclosed information, craft a direct request to the endpoint:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/RegisterAdmin" \
     -H "Content-Type: application/json" \
     -d '{"UserName": "attacker@evil.com", "Password": "<password>"}'
   ```

6. Observe whether the endpoint is live and accepts the registration request.

---

## Proof of Concept

The following block was found verbatim in the HTML source of `http://localhost:1337/auth/register`:

```javascript
//$('.btnRegister').on('click', function (event) {
//    $.ajax({
//        type: "POST",
//        url: "/api/Auth/RegisterAdmin",
//        data: JSON.stringify({ "UserName": $('.UserEmail').val(), "Password": $('.Password').val() }),
//        contentType: 'application/json',
//        success: data => {
//            console.log('SUCESSS');
//            var parsedData = JSON.parse(data);
//            if (parsedData.status == "ok") {
//                $('.cd-popup4').addClass('is-visible');  //show popup
//                setTimeout(function () {
//                    window.location.href = "/Auth/Login";
//                }, 8000)
//            } else {
//                console.log('ERROR1');
//                $('.cd-popup3').addClass('is-visible');  //show popup
//            }
//        },
//        error: data => {
//            console.log('ERROR');
//                $('.cd-popup3').addClass('is-visible');  //show popup
//        }
//    });
//});
```

The comment discloses the following information in full:

| Detail | Value |
|---|---|
| **Endpoint** | `POST /api/Auth/RegisterAdmin` |
| **Content-Type** | `application/json` |
| **Parameter — username** | `UserName` |
| **Parameter — password** | `Password` |
| **Success condition** | `parsedData.status == "ok"` |

This is sufficient to fully reconstruct and send a valid admin registration request without any prior knowledge of the application.

---

## Impact

- **Privileged endpoint discovery** — the `/api/Auth/RegisterAdmin` route would not appear in normal application usage or standard enumeration, yet it is handed to any visitor via the page source. The Swagger schema (Issue #01) may further corroborate its existence.
- **Potential unauthorised admin account creation** — if the endpoint lacks server-side access controls (e.g. requiring an existing admin session or a secret token), any unauthenticated user can register an admin account, leading to full application compromise.
- **Reduced attack complexity** — the disclosed payload structure eliminates all guesswork. An attacker does not need to fuzz parameter names or content types; the application provides a ready-made exploit template.
- **Chaining risk** — combined with the API schema exposed in Issue #01, an attacker gains both the endpoint inventory and, here, the exact request format for one of the most sensitive operations in the application.

---

## Recommended Mitigations

1. **Remove all commented-out code from production HTML.** HTML comments are delivered to every client and are not a safe mechanism for hiding functionality. Establish a pre-deployment review or automated linting step to catch this:

   ```bash
   # Example: grep for commented JS blocks during CI
   grep -rn "//.*ajax\|//.*url.*api" ./wwwroot/
   ```

2. **Enforce strict server-side authorisation on the admin registration endpoint.** The `/api/Auth/RegisterAdmin` route must require an authenticated admin session or a one-time provisioning token — regardless of whether the endpoint is documented or discoverable:

   ```csharp
   [HttpPost("RegisterAdmin")]
   [Authorize(Roles = "Admin")]
   public async Task<IActionResult> RegisterAdmin([FromBody] RegisterRequest request)
   { ... }
   ```

3. **Consider removing the endpoint entirely** if self-service admin registration is not a required feature. Admin accounts should ideally be provisioned through an internal, out-of-band process rather than a public-facing API.

4. **Audit all HTML templates and static assets** for other instances of commented-out code, internal URLs, credentials, or configuration values before deployment.
