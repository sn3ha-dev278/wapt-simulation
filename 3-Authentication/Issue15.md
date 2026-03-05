# Issue #15 — User Enumeration via Autocomplete API

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/Search/FindUser` |
| **Severity**  | Medium                                                |
| **CVSS v3.1** | 4.3                                                   |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N                  |
| **Category**  | Broken Access Control — User Enumeration              |

---

## Summary

The transaction creation page includes an autocomplete feature that helps users select a recipient email address. This feature is powered by the `/api/Search/FindUser` endpoint, which accepts a `term` query parameter and returns a list of matching registered users. When `term` is set to an empty string, the endpoint returns the complete list of every registered account in the application in a single unauthenticated-equivalent response.

This constitutes a full user enumeration vulnerability — the entire user base is disclosed to any authenticated user with a single request, requiring no iteration, no guessing, and no special privileges beyond a valid session.

---

## Steps to Reproduce

1. Log in to the application and navigate to **Create Transaction**.
2. Send the following request with an empty `term` parameter:

   ```bash
   curl -s "http://localhost:1337/api/Search/FindUser?term=" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

3. Observe that the response contains a JSON array listing every registered user's email address in the application.

---

## Proof of Concept

**Request:**

```http
GET /api/Search/FindUser?term= HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Referer: http://localhost:1337/Transaction/Create
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 15:49:55 GMT
Server: Kestrel
Content-Length: 409

["[REDACTED]","[REDACTED]","[REDACTED]", ... "[REDACTED]"]
```

> **Note:** The full list of email addresses returned in the response has been redacted. During testing, the endpoint returned all registered accounts in the application in a single response, including standard user accounts, service accounts, and the admin account.

The response confirms:
- **All user email addresses** are returned when `term` is empty, with no pagination or result cap enforced
- **The admin account** is included in the listing alongside regular users
- **Service-style accounts** (e.g. accounts resembling internal or system users) are also disclosed, suggesting the endpoint queries the full `UserData` table without any role-based filtering

---

## Impact

- **Complete user base disclosure** — a single request enumerates every registered account, providing an attacker with a ready-made target list for credential attacks, phishing campaigns, or social engineering without any prior knowledge of the application's users.
- **Stored XSS delivery amplified** — as noted in Issue #09, the stored XSS in the transaction `Reason` field can be delivered to any registered user by sending them a transaction. This endpoint eliminates the need for the attacker to know any victim email addresses in advance, making mass XSS payload delivery trivial: enumerate all users, then send a malicious transaction to each one.
- **SQL injection cross-reference** — the same user list was already extractable via the SQL injection in Issue #08. However, that attack required chaining multiple payloads and database enumeration. This endpoint provides the same data to a low-privileged authenticated user in a single, zero-effort GET request.
- **Credential stuffing enablement** — the disclosed email addresses, combined with the plaintext passwords extracted via Issue #08, provide a complete credential set that can be used for account takeover on this application and for credential stuffing against other services where users may have reused passwords.
- **Admin account exposure** — the inclusion of admin account identifiers in the enumeration output allows an attacker to precisely target privileged accounts for phishing, password spraying, or XSS-based session hijacking (Issue #09, Vector B).

---

## Recommended Mitigations

1. **Require a minimum `term` length** before executing any search query. A minimum of 2–3 characters prevents full enumeration while preserving the autocomplete user experience:

   ```csharp
   [HttpGet("FindUser")]
   [Authorize]
   public IActionResult FindUser(string term)
   {
       if (string.IsNullOrWhiteSpace(term) || term.Length < 3)
           return Ok(Array.Empty<string>());

       var results = _userService.SearchUsers(term);
       return Ok(results);
   }
   ```

2. **Cap the number of results returned** to a small, fixed maximum (e.g. 5–10) regardless of how many matches exist. This limits the data exposed per request and prevents bulk extraction even if a short `term` is used.

3. **Exclude privileged accounts from autocomplete results.** Admin and service accounts should never appear in user-facing search results. Apply a role-based filter before returning any results:

   ```csharp
   var results = _userService.SearchUsers(term)
       .Where(u => u.Role != "Admin")
       .Take(10);
   ```

4. **Rate-limit the endpoint** to prevent automated enumeration even with a non-empty `term`. A small number of requests per minute per session is sufficient for legitimate autocomplete usage and significantly raises the cost of scripted enumeration.

5. **Consider returning display names instead of email addresses** in autocomplete suggestions, reserving full email disclosure only for the moment a user is explicitly selected and the transaction is submitted.