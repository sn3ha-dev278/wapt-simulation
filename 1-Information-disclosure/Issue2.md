# Issue #02 — Unauthenticated Directory Listing Exposed

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337`            |
| **Severity**  | Medium                                           |
| **CVSS v3.1** | 5.3                                              |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure / Security Misconfiguration |

---

## Summary

The `/docs/` directory of the application is publicly accessible and has directory listing enabled, allowing any unauthenticated user to browse its contents. The directory contains internal documents — including legal agreements and what appears to be an internal meeting record — none of which are protected by any form of authentication or access control. This exposure can be reached both through active enumeration and passively via a link embedded in the application's registration flow.

---

## Steps to Reproduce

1. Run a directory brute-force against the target to discover the `/docs/` path:
   ```bash
   git clone --depth 1 https://github.com/danielmiessler/SecLists.git

   gobuster dir \
     -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u http://localhost:1337
   ```
2. Observe that `http://localhost:1337/docs/` returns **HTTP 200**.
3. Navigate directly to `http://localhost:1337/docs/` in a browser — a full directory listing is rendered with no authentication prompt.
4. Alternatively, reach the directory passively:
   - Visit the application's registration page.
   - Click the **Terms and Conditions** link, which resolves to `http://localhost:1337/docs/legal.pdf`.
   - Trim the path to `http://localhost:1337/docs/` to access the listing.
5. From the listing, directly download any file — for example, the internal meeting document — without providing any credentials:
   ```bash
   curl -O http://localhost:1337/docs/[REDACTED-FILENAME].pdf
   ```

---

## Proof of Concept

### Request 1 — Directory Listing

```http
GET /docs/ HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 2335
Content-Type: text/html; charset=utf-8
Date: Sat, 05 Jul 2025 15:20:08 GMT
Server: Kestrel

<!DOCTYPE html>
<html lang="iv">
<head>
  <title>Index of /docs/</title>
...
  <tbody>
    <tr class="file">
      <td class="name"><a href="./legal.pdf">legal.pdf</a></td>
      <td class="length">145,119</td>
      <td class="modified">[REDACTED]</td>
    </tr>
    <tr class="file">
      <td class="name"><a href="./privacy policy.pdf">privacy policy.pdf</a></td>
      <td class="length">18,005</td>
      <td class="modified">[REDACTED]</td>
    </tr>
    <tr class="file">
      <td class="name"><a href="./[REDACTED-FILENAME].pdf">[REDACTED-FILENAME].pdf</a></td>
      <td class="length">3,287</td>
      <td class="modified">[REDACTED]</td>
    </tr>
  </tbody>
...
```

The server renders a full HTML directory index, exposing the names, sizes, and last-modified timestamps of all files present. One of the listed files appears to be an internal document based on its naming convention.

---

### Request 2 — Unauthenticated File Download

```http
GET /docs/[REDACTED-FILENAME].pdf HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 3287
Content-Type: application/pdf
Date: Sat, 05 Jul 2025 15:21:23 GMT
Server: Kestrel
Accept-Ranges: bytes
ETag: "[REDACTED]"
Last-Modified: [REDACTED]

%PDF-1.4
...
```

The server delivers the full PDF content with no authentication check. The presence of `Accept-Ranges: bytes` also means the file can be retrieved in partial chunks, which is consistent with a completely unrestricted static file server.

---

## Impact

- **Unintended file exposure** — directory listing reveals the names and metadata of every file under `/docs/`, including documents that were likely never intended for public access.
- **Passive attack vector** — the `/docs/legal.pdf` link on the registration page gives any visitor a direct foothold into the directory path, meaning exploitation requires no enumeration tools whatsoever.
- **Sensitive document access** — internal documents (e.g. meeting records) are directly downloadable without authentication, potentially exposing confidential business information, personnel details, or internal processes.
- **Metadata leakage** — file names, sizes, and last-modified timestamps are disclosed, which can reveal internal naming conventions, development timelines, and operational patterns useful for further attacks.

---

## Recommended Mitigations

1. **Disable directory listing** on the static file middleware. In ASP.NET Core, directory browsing must be explicitly enabled — verify it is not configured in `Program.cs`:

   ```csharp
   // Remove or ensure this is NOT present in production
   app.UseDirectoryBrowser();
   ```

2. **Enforce authentication on the `/docs/` path.** Any document not intended for public consumption should require a valid session before being served:

   ```csharp
   app.MapStaticAssets("/docs/{fileName}", requireAuthorization: true);
   ```

3. **Restrict publicly served files** to only those explicitly meant for anonymous access (e.g. `legal.pdf`, `privacy policy.pdf`). Internal documents should be stored outside the web root or behind an authenticated file-serving endpoint.

4. **Audit the `/docs/` directory contents** and remove or relocate any files that should not be publicly accessible.

5. **Suppress the `Server: Kestrel` header** to reduce technology fingerprinting (see Issue #01 for implementation details).