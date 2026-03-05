# Issue #23 — Missing Content Security Policy (CSP)

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                     |
| **Severity**  | Medium                                                   |
| **CVSS v3.1** | 4.3                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N                  |
| **Category**  | Security Misconfiguration — Missing Security Headers  |

---

## Summary

The application does not set a `Content-Security-Policy` (CSP) response header on any page. CSP is a browser-enforced defence-in-depth mechanism that restricts which scripts, styles, and resources a page is permitted to load and execute. Its absence means that any successful XSS injection — of which two were confirmed in this assessment (Issues #09 and #10) — faces no browser-level barrier to executing arbitrary JavaScript, loading external resources, or exfiltrating data to attacker-controlled servers.

While the absence of CSP is not independently exploitable, it is a significant omission in the context of this application, which is already affected by multiple confirmed XSS vulnerabilities.

---

## Steps to Reproduce

1. Send any request to the application and inspect the response headers:

   ```bash
   curl -si "http://localhost:1337/" \
     -H "Cookie: SessionId=[REDACTED]" \
     | grep -i "content-security-policy"
   ```

2. Observe that no `Content-Security-Policy` header is present in the response.

---

## Proof of Concept

**Request:**

```http
GET / HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Fri, 11 Jul 2025 13:35:49 GMT
Server: Kestrel
Content-Length: 25850

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
...
```

No `Content-Security-Policy`, `X-Content-Type-Options`, or `X-Frame-Options` headers are present in the response. The full set of security headers is absent, indicating that HTTP security header configuration has not been addressed at the application or server level.

---

## Impact

- **XSS amplification** — the stored XSS (Issue #09) and reflected XSS (Issue #10) confirmed in this assessment both relied on the absence of CSP to execute successfully. A strict CSP that disallows inline scripts and restricts `script-src` to trusted origins would have prevented or significantly limited the exploitability of both findings, even without fixing the underlying injection vulnerabilities.
- **Out-of-band exfiltration unrestricted** — the weaponised reflected XSS payload in Issue #10 demonstrated cookie exfiltration to an external server via `fetch()`. A CSP `connect-src` directive restricting outbound connections to `'self'` would have blocked this exfiltration channel entirely.
- **No browser-level fallback defence** — without CSP, the application relies entirely on server-side input validation and output encoding as its only XSS defences. When those controls fail — as they have in this assessment — there is no secondary browser-enforced layer to limit the damage.
- **Clickjacking exposure** — the absence of `X-Frame-Options` or a CSP `frame-ancestors` directive means the application can be embedded in an iframe on an attacker-controlled page, enabling clickjacking attacks against authenticated users.

---

## Recommended Mitigations

1. **Implement a Content Security Policy** as a response header, starting with a restrictive baseline and relaxing only as necessary. For an ASP.NET Core application, this can be applied globally via middleware:

   ```csharp
   app.Use(async (context, next) =>
   {
       context.Response.Headers.Add(
           "Content-Security-Policy",
           "default-src 'self'; " +
           "script-src 'self'; " +
           "style-src 'self'; " +
           "img-src 'self' data:; " +
           "connect-src 'self'; " +
           "frame-ancestors 'none'; " +
           "object-src 'none';"
       );
       await next();
   });
   ```

2. **Adopt a CSP deployment approach.** Rather than deploying a strict policy immediately and risking breaking functionality, use `Content-Security-Policy-Report-Only` in staging to log violations without enforcing them, refine the policy based on the reports, then switch to enforcement mode in production.

3. **Add complementary security headers** alongside CSP to address related attack surfaces:

   ```csharp
   context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
   context.Response.Headers.Add("X-Frame-Options", "DENY");
   context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
   context.Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
   ```

4. **Prioritise fixing the underlying XSS vulnerabilities** (Issues #09 and #10) rather than relying on CSP alone. CSP is a defence-in-depth control, not a substitute for proper output encoding — a sufficiently weak policy or a JSONP endpoint in scope can still be abused to bypass it.