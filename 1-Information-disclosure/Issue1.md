# Issue #01 — Swagger UI & API Schema Publicly Exposed

| Field        | Details                                      |
|--------------|----------------------------------------------|
| **Target**   | BankWeb API — `http://localhost:1337`        |
| **Severity** | Medium                                       |
| **CVSS v3.1**| 5.3                                          |
| **Vector**   | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N          |
| **Category** | Information Disclosure / Security Misconfiguration |

---

## Summary

The application's Swagger UI and its underlying OpenAPI schema (`swagger.json`) are accessible to unauthenticated users over the network. The schema — titled **BankWeb API v1** — enumerates all available API endpoints, accepted parameters, request/response structures, and potentially sensitive business logic. In a production banking context, this level of disclosure gives an attacker a full reconnaissance map of the attack surface without requiring any authentication or prior knowledge of the application.

---

---

## Steps to Reproduce

1. Run a general directory brute-force against the target:
   ```bash
   gobuster dir \
     -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u http://localhost:1337
   ```
2. Run an API-specific endpoint scan:
   ```bash
   gobuster dir \
     -w SecLists/Discovery/Web-Content/api/api-endpoints.txt \
     -u http://localhost:1337
   ```
3. Observe that both scans return **HTTP 200** for:
   - `http://localhost:1337/swagger/index.html`
   - `http://localhost:1337/swagger/v1/swagger.json`
4. Navigate to `http://localhost:1337/swagger/index.html` in a browser — the full interactive Swagger UI loads without any authentication prompt.
5. Fetch the raw schema directly:
   ```bash
   curl -s http://localhost:1337/swagger/v1/swagger.json | jq .
   ```
6. Observe the complete OpenAPI 3.0.1 specification for **BankWeb API v1** is returned, including all endpoints, parameters, and response models.

---

## Proof of Concept

### Request 1 — Swagger UI

```http
GET /swagger/index.html HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Date: Fri, 04 Jul 2025 17:28:37 GMT
Server: Kestrel
Content-Length: 4755

<!-- HTML for static distribution bundle build -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Swagger UI</title>
...
```

The server returned the full Swagger UI — a browser-based interactive console allowing anyone to browse and invoke API endpoints directly.

---

### Request 2 — OpenAPI Schema

```http
GET /swagger/v1/swagger.json HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Date: Sat, 05 Jul 2025 15:18:22 GMT
Server: Kestrel
Content-Length: 27069

{
  "openapi": "3.0.1",
  "info": {
    "title": "BankWeb API",
    "version": "v1"
  },
...
```

The response body (27,069 bytes) contains the full OpenAPI 3.0.1 specification for the BankWeb API, including all routes, HTTP methods, input schemas, and response models.

> **Note:** The `Server: Kestrel` response header also confirms the application is running on ASP.NET Core, which narrows the technology stack for a potential attacker.

---

## Impact

Exposed API documentation in a financial application carries significant downstream risk:

- **Endpoint enumeration without effort** — an attacker gains an instant, structured list of every route in the application, including any undocumented or administrative endpoints that would otherwise require extensive fuzzing to discover.
- **Accelerated attack chain** — knowledge of parameter names, data types, and expected inputs dramatically reduces the time needed to craft injection payloads (SQLi, XSS, IDOR, etc.) against individual endpoints.
- **Business logic exposure** — in a banking API, the schema may reveal account management, fund transfer, or authentication flows, making it trivial to understand how the system behaves before ever sending a malicious request.
- **Technology fingerprinting** — the `Server: Kestrel` header, combined with the OpenAPI schema title and version, gives an attacker precise knowledge of the stack to look up known CVEs.

---

## Recommended Mitigations

1. **Disable Swagger in production.** In ASP.NET Core, Swagger registration is typically gated behind an environment check — ensure it is strictly limited to `Development`:

   ```csharp
   if (app.Environment.IsDevelopment())
   {
       app.UseSwagger();
       app.UseSwaggerUI();
   }
   ```

2. **Restrict access by network policy** if internal API documentation is required in non-development environments. Limit `/swagger/*` routes to internal IP ranges via a reverse proxy or middleware.

3. **Remove or suppress the `Server` header** to avoid unnecessary technology disclosure:

   ```csharp
   builder.WebHost.ConfigureKestrel(options =>
   {
       options.AddServerHeader = false;
   });
   ```

4. **Audit the schema contents** before any exposure, even internally — remove any endpoints, descriptions, or example values that reveal sensitive business logic or internal identifiers.

---
