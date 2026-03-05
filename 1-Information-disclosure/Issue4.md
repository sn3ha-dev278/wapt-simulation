# Issue #04 — Unmanaged Errors Expose Backend Processing Details

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337`            |
| **Severity**  | Medium                                           |
| **CVSS v3.1** | 5.3                                              |
| **Vector**    | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N             |
| **Category**  | Information Disclosure / Improper Error Handling |

---

## Summary

The application fails to handle errors gracefully in multiple endpoints, returning internal error details directly to the client. Unlike Issue #03 where full stack traces were exposed, these responses reveal information about backend processing behaviour — specifically, error messages that confirm the presence of SQL query construction and JSON deserialization logic. Both vectors provide an attacker and is a common indicator of SQL injection vulnerabilities, and the other confirms that untrusted user input is being passed directly into a deserializer, a class of vulnerability commonly associated with remote code execution.

Two triggerable vectors were identified:

- **Vector A** — injecting a single quote into the transaction search parameter
- **Vector B** — sending malformed JSON to the admin store upload endpoint

---

## Steps to Reproduce

### Vector A — Transaction Search (`/api/Transaction/GetTransactions`)

1. Log in to the application and navigate to the **Transactions** page.
2. Locate the search/filter input field within the transactions table.
3. Enter a single quote character (`'`) into the search field and submit.
4. Observe that the application renders an error page instead of returning filtered results.

Alternatively, send the request directly:

```bash
curl -s "http://localhost:1337/api/Transaction/GetTransactions?start=0&length=10&search%5Bvalue%5D=%27&search%5Bregex%5D=false" \
  -H "Cookie: SessionId=[REDACTED]"
```

### Vector B — Admin Store Upload (`/api/AdminStore/UploadStoreItems`)

1. Log in as an admin user and intercept traffic using a proxy (e.g. Burp Suite).
2. Send a `POST` request to `/api/AdminStore/UploadStoreItems` with `Content-Type: application/json` and a malformed JSON body (e.g. `a"`).
3. Observe that the server responds with **HTTP 400** and a verbose error message that discloses the internal deserialization mechanism.

```bash
curl -s -X POST "http://localhost:1337/api/AdminStore/UploadStoreItems" \
  -H "Content-Type: application/json" \
  -H "Cookie: SessionId=[REDACTED]" \
  -d 'a"'
```

---

## Proof of Concept

### Vector A — Transaction Search

**Request:**

```http
GET /api/Transaction/GetTransactions?start=0&length=10&search%5Bvalue%5D=%27&search%5Bregex%5D=false&_=1751733102637 HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

The payload injected via the `search[value]` parameter:

```
'
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Sat, 05 Jul 2025 16:39:40 GMT
Server: Kestrel
Content-Length: 4042

<!DOCTYPE html>
<html>
<head>
...
  <h3>Error</h3>
  ...
```

The server returns **HTTP 200** with an HTML error page — a notable anomaly in itself, as an error condition should not yield a 200 status code. The error is triggered by a single unescaped quote, which is a classical indicator that user input is being interpolated directly into a SQL query without parameterisation, making this endpoint a strong candidate for SQL injection (to be confirmed in a dedicated finding).

---

### Vector B — Admin Store Upload

**Request:**

```http
POST /api/AdminStore/UploadStoreItems HTTP/1.1
Host: localhost:1337
Content-Type: application/json
Content-Length: 2
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Referer: http://localhost:1337/Transaction
Cookie: SessionId=[REDACTED]

a"
```

**Response:**

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Date: Sat, 19 Jul 2025 14:14:18 GMT
Server: Kestrel
Content-Length: 111

"Deserialization failed: Unexpected character encountered while parsing value: a. Path '', line 0, position 0."
```

The error message confirms that the endpoint attempts to deserialize the raw request body and surfaces the internal exception message verbatim. The string `Deserialization failed:` followed by the parser's exact output reveals that untrusted input reaches a JSON deserializer with no prior validation — confirms that untrusted user input is passed directly to a JSON deserialization routine without prior validation..

---

## Impact

- **SQL injection signal** — the single-quote error in Vector A is a well-established indicator that input is being concatenated into a SQL query. While full exploitability is subject to further testing, the unhandled error confirms the absence of input sanitisation and parameterised queries at minimum.
- **Insecure deserialization signal** — the verbose deserializer error in Vector B confirms that raw client input is passed into a deserialization routine. Depending on the deserializer and the object types in scope, this may be escalatable to remote code execution.
- **Error-based reconnaissance** — even without full exploitation, error messages of this kind allow an attacker to probe the application's internal behaviour systematically — confirming vulnerable code paths, inferring data types, and mapping injection points before launching a targeted attack.
- **Incorrect HTTP status code** — Vector A returning `HTTP 200` on an error condition suggests the error handling logic is entirely absent at the controller level, indicating broader systemic issues with input validation across the application.

---

## Recommended Mitigations

1. **Use parameterised queries or an ORM** for all database interactions. User input must never be concatenated into SQL strings:

   ```csharp
   // Vulnerable pattern
   var query = $"SELECT * FROM Transactions WHERE Description LIKE '%{searchValue}%'";

   // Safe pattern
   var query = "SELECT * FROM Transactions WHERE Description LIKE @search";
   command.Parameters.AddWithValue("@search", $"%{searchValue}%");
   ```

2. **Validate and strongly type all input** before it reaches deserialization. Reject requests with unexpected `Content-Type` values or malformed bodies at the middleware level, before any parsing occurs:

   ```csharp
   if (!ModelState.IsValid)
       return BadRequest(new { error = "Invalid request format." });
   ```

3. **Suppress internal exception messages** in API error responses. Return generic, structured error objects rather than raw exception strings:

   ```csharp
   // Avoid exposing exception.Message directly
   return BadRequest(new { error = "The request could not be processed." });
   ```

4. **Return correct HTTP status codes** for error conditions. An unhandled exception should never result in a `200 OK` response. Implement a global exception handler (see Issue #03) to enforce consistent, semantically correct error responses across all endpoints.

5. **Restrict the `/api/AdminStore/UploadStoreItems` endpoint** to verified admin roles and apply strict schema validation on the expected JSON structure before any deserialization occurs.