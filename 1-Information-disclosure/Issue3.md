# Issue #03 — Exposed Stack Traces Leak Internal Application Details

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337`            |
| **Severity**  | Medium                                           |
| **CVSS v3.1** | 5.3                                              |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure / Improper Error Handling |

---

## Summary

The application returns unhandled exception stack traces directly to the client in at least two distinct scenarios. The traces expose internal implementation details including absolute file system paths, class and method names, source file names, and line numbers. This level of detail significantly aids an attacker during the reconnaissance phase, providing a precise map of the server-side codebase structure without requiring any special privileges.

Two triggerable vectors were identified:

- **Vector A** — uploading a non-XML file to the transaction upload endpoint
- **Vector B** — submitting a tampered session cookie on any authenticated request

---

## Steps to Reproduce

### Vector A — Transaction Upload

1. Log in to the application and navigate to the **Transactions** page.
2. Locate the file upload functionality.
3. Upload any non-XML file (e.g. a plain `.txt` file with arbitrary content):
   ```
   File: plain.txt
   Content: plain
   ```
4. Observe that the server responds with **HTTP 500** and a full plain-text stack trace in the response body.

### Vector B — Cookie Manipulation

1. Log in to the application and capture the `SessionId` cookie value from browser DevTools or a proxy (e.g. Burp Suite).
2. Modify a single character anywhere in the cookie value to produce an invalid session token.
3. Send any request to the application (e.g. `GET /`) with the tampered cookie.
4. Observe that the server responds with **HTTP 500** and an HTML page containing a full stack trace.

---

## Proof of Concept

### Vector A — Transaction Upload

**Request:**

```http
POST /upload/UploadTransactions HTTP/1.1
Host: localhost:1337
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqzPhA2GWXGfAJ1Wu
Content-Length: 192
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Referer: http://localhost:1337/Transaction
Cookie: SessionId=[REDACTED]

------WebKitFormBoundaryqzPhA2GWXGfAJ1Wu
Content-Disposition: form-data; name="files"; filename="plain.txt"
Content-Type: text/plain

plain

------WebKitFormBoundaryqzPhA2GWXGfAJ1Wu--
```

**Response:**

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/plain; charset=utf-8
Date: Sat, 05 Jul 2025 15:40:21 GMT
Server: Kestrel
Content-Length: 4078

System.Xml.XmlException: Data at the root level is invalid. Line 1, position 1.
   at System.Xml.XmlTextReaderImpl.Throw(Exception e)
   at System.Xml.XmlTextReaderImpl.Throw(String res, String arg)
   at System.Xml.XmlTextReaderImpl.ParseRootLevelWhitespace()
   ...
```

The trace further exposes internal class hierarchy and absolute server paths:

```
SecureBank.Services.UploadFileBL.ParseXml(string xml) in UploadFileBL.cs
SecureBank.Services.UploadFileBL.UploadFile(MemoryStream stream) in UploadFileBL.cs
SecureBank.Controllers.UploadController.UploadTransactions() in UploadController.cs
```

```
at SecureBank.Services.UploadFileBL.ParseXml(String xml) in /app/Services/UploadFileBL.cs:line 48
at SecureBank.Services.UploadFileBL.UploadFile(MemoryStream stream) in /app/Services/UploadFileBL.cs:line 21
at SecureBank.Controllers.UploadController.UploadTransactions() in /app/Controllers/UploadController.cs:line 40
```

---

### Vector B — Cookie Manipulation

**Request (tampered cookie):**

```http
GET / HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Cookie: SessionId=[REDACTED-TAMPERED]
```

**Response:**

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=utf-8
Date: Tue, 08 Jul 2025 08:13:30 GMT
Server: Kestrel
Content-Length: 22132

<!DOCTYPE html>
<html lang="iv" xmlns="http://www.w3.org/1999/xhtml">
  <head>
  ...
```

The response body (22,132 bytes) is an HTML error page containing a full stack trace. The significantly larger response size compared to Vector A suggests a more verbose diagnostic page, consistent with ASP.NET Core's built-in developer exception page being enabled in a non-development environment.

> **Note:** Cookie values have been redacted in both requests. The original and tampered values differ by a single character in the base64-encoded segment — demonstrating that no special knowledge is required to trigger this error path.

---

## Impact

- **File system path disclosure** — absolute server paths (e.g. `/app/Services/UploadFileBL.cs`) confirm the deployment directory structure, which can assist in path traversal or local file inclusion attacks.
- **Source code structure exposure** — class names, method names, and line numbers reveal the internal architecture of the application, making it significantly easier to reason about code logic and identify additional attack surfaces.
- **Low-effort trigger** — both vectors are trivially reproducible: one requires only uploading a wrong file type, the other requires flipping a single character in a cookie. No authentication bypass or elevated privileges are needed for Vector A.
- **Chaining risk** — the disclosed paths and class names directly correlate with the API routes exposed via Swagger (Issue #01), allowing an attacker to cross-reference documentation with implementation details for more targeted exploitation.

---

## Recommended Mitigations

1. **Disable the developer exception page in production.** ASP.NET Core's `UseDeveloperExceptionPage()` should never be active outside of a development environment:

   ```csharp
   if (app.Environment.IsDevelopment())
   {
       app.UseDeveloperExceptionPage();
   }
   else
   {
       app.UseExceptionHandler("/error");
   }
   ```

2. **Implement a global exception handler** that returns a generic, user-facing error message with a correlation ID — without leaking any internal details:

   ```csharp
   app.UseExceptionHandler(err => err.Run(async context =>
   {
       context.Response.StatusCode = 500;
       await context.Response.WriteAsJsonAsync(new
       {
           error = "An unexpected error occurred.",
           reference = Guid.NewGuid()
       });
   }));
   ```

3. **Validate file types server-side** before attempting to parse uploaded content. Reject non-XML uploads early with a structured `400 Bad Request` response rather than allowing the XML parser to throw an unhandled exception:

   ```csharp
   if (!file.ContentType.Equals("application/xml", StringComparison.OrdinalIgnoreCase))
       return BadRequest(new { error = "Only XML files are accepted." });
   ```

4. **Harden session cookie handling** so that a malformed or tampered cookie results in a graceful redirect to the login page rather than an unhandled exception. Validate cookie integrity before any deserialization or lookup occurs.

5. **Log exceptions server-side** using structured logging (e.g. Serilog, Application Insights) so that full diagnostic information is retained internally without being surfaced to the client.