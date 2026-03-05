# Issue #07 — Server Banner Exposed in HTTP Response Headers

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb — `http://localhost:1337`                |
| **Severity**  | Low                                              |
| **CVSS v3.1** | 3.1                                              |
| **Vector**    | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure / Security Misconfiguration |

---

## Summary

Every HTTP response returned by the application includes a `Server: Kestrel` header, which identifies the underlying web server as Microsoft's Kestrel — the default ASP.NET Core HTTP server. While this does not constitute a vulnerability in isolation, it reduces the effort required for targeted reconnaissance by confirming the technology stack without any active probing. This finding has been observed consistently across all interactions with the application throughout this assessment, and is noted here as a dedicated issue given that it represents a remediable misconfiguration.

---

## Steps to Reproduce

1. Send any HTTP request to the application — no authentication or special tooling required:

   ```bash
   curl -s -I http://localhost:1337/
   ```

2. Observe the `Server` header in the response:

   ```
   Server: Kestrel
   ```

---

## Proof of Concept

**Request:**

```http
GET / HTTP/1.1
Host: localhost:1337
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Sat, 05 Jul 2025 15:43:01 GMT
Server: Kestrel
Content-Length: 25316

<!DOCTYPE html>
<html>
<head>
...
```

The `Server: Kestrel` header is present on the root response and has been consistently observed on every endpoint tested during this assessment — including error responses (Issues #03 and #04), static file responses (Issue #02), and API responses (Issue #01). This means the header is emitted globally at the server level rather than by individual controllers, and must be suppressed at the host configuration layer.

---

## Impact

- **Technology stack confirmation** — the header unambiguously identifies the server as Kestrel, confirming the application is built on ASP.NET Core. Combined with the OpenAPI schema title (`BankWeb API v1`) disclosed in Issue #01, an attacker has a precise technology fingerprint with minimal effort.
- **Targeted CVE lookup** — knowing the server is Kestrel allows an attacker to search for version-specific vulnerabilities in the ASP.NET Core runtime, HTTP/2 handling, or middleware components. If the Kestrel version is also discoverable (e.g. via verbose error pages), the attack surface narrows further.
- **Reduced reconnaissance time** — in a black-box assessment, technology identification typically requires active probing and analysis of behavioural differences. The `Server` header eliminates this step entirely, lowering the barrier for automated scanning tools to apply targeted payloads.
- **Compound risk** — this header is present on every response in the application, meaning every other finding in this report has also leaked this information as a side effect. It is a systemic issue rather than an endpoint-specific one.

---

## Recommended Mitigations

1. **Suppress the `Server` header at the Kestrel configuration level** in `Program.cs` or `appsettings`:

   ```csharp
   builder.WebHost.ConfigureKestrel(options =>
   {
       options.AddServerHeader = false;
   });
   ```

2. **If running behind a reverse proxy** (e.g. Nginx, IIS, or Azure Application Gateway), suppress or overwrite the header at the proxy layer as well, since proxy servers may re-introduce their own `Server` header:

   ```nginx
   # Nginx example
   server_tokens off;
   ```

3. **Review all other response headers** for unnecessary information disclosure. Common headers to audit include `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and `X-Generator`, all of which can be suppressed via middleware:

   ```csharp
   app.Use(async (context, next) =>
   {
       context.Response.Headers.Remove("X-Powered-By");
       await next();
   });
   ```