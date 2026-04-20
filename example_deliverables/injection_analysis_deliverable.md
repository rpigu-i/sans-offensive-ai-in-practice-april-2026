# Injection Analysis Report (SQLi, NoSQL, Command Injection, SSTI, LFI, SSRF, XXE)

## 1. Executive Summary

- **Analysis Status:** Complete
- **Sources Analyzed:** 16 distinct injection sources across SQL, NoSQL, SSTI/eval, LFI, SSRF, and XXE categories
- **Key Outcome:** 11 high-confidence externally-exploitable vulnerabilities confirmed. Two critical unauthenticated SQL injection endpoints provide direct database access; multiple RCE vectors (eval, Pug SSTI, notevil sandbox) exist for authenticated users; an unauthenticated XXE enables local file disclosure. All findings have been passed to the exploitation phase.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and environmental intelligence necessary to effectively exploit the vulnerabilities listed in the exploitation queue. It is intended to be read alongside the structured JSON output.

---

## 2. Dominant Vulnerability Patterns

### Pattern A — Raw SQL Template-Literal Interpolation
- **Description:** The application uses Sequelize's `.query()` method with ES6 template literals to construct SQL strings. User input is interpolated directly without parameterized bindings or escaping.
- **Implication:** Classic UNION-based and boolean/time-based SQL injection is directly achievable. The database is SQLite, confirmed by `sqlite_master` references in search.ts.
- **Representative:** INJ-VULN-01, INJ-VULN-02

### Pattern B — MongoDB `$where` JavaScript Expression Injection
- **Description:** Two endpoints construct the `$where` operator string by concatenating/interpolating user-controlled route parameters. The `$where` clause executes as server-side JavaScript in MongoDB.
- **Implication:** Attackers can inject arbitrary JavaScript into MongoDB queries, enabling data exfiltration, Boolean-blind extraction, and time-based DoS via the intentionally exposed global `sleep()` function.
- **Representative:** INJ-VULN-03, INJ-VULN-04

### Pattern C — Direct `eval()` and Template-Engine Code Execution
- **Description:** User-supplied data (username stored in SQLite, B2B order body) flows into `eval()`, `vm.runInContext()`, and `pug.compile()` without meaningful sandboxing.
- **Implication:** Full server-side RCE is achievable for any authenticated user who can control their username or submit a B2B order. The `notevil`/vm sandbox in the B2B path is documented as escapable.
- **Representative:** INJ-VULN-07, INJ-VULN-08, INJ-VULN-06

### Pattern D — Blacklist / Incomplete Validation at File-Access Sinks
- **Description:** File-serving routes and the data-erasure layout parameter rely on keyword blacklists or forward-slash-only checks rather than path canonicalization + boundary enforcement.
- **Implication:** Arbitrary file reads are possible for the data-erasure endpoint (LFI via layout), and the FTP server is vulnerable to null-byte extension bypass.
- **Representative:** INJ-VULN-10, INJ-VULN-11

---

## 3. Strategic Intelligence for Exploitation

### Defensive Evasion (WAF Analysis)
- No WAF or rate-limiting middleware was observed on the critical injection endpoints (`/rest/user/login`, `/rest/products/search`, `/rest/track-order/:id`, `/rest/products/:id/reviews`).
- No input sanitization middleware (e.g., express-validator, helmet SQL escaping) is applied globally.
- **Recommendation:** Payloads can be sent raw without bypass techniques.

### Error-Based Injection Potential
- The product search endpoint (`/rest/products/search`) propagates raw SQLite error objects to the client via Express's default error handler (search.ts:69–71: `next(error)`).
- **Recommendation:** Error-based extraction is viable for INJ-VULN-02. Malformed UNION probes will leak table/column names in the HTTP 500 response body.

### Confirmed Database Technology
- **SQLite** (not PostgreSQL/MySQL) — confirmed via `sqlite_master` query at search.ts:47 and Sequelize dialect in config.
- All SQL payloads must be SQLite-compatible (no `SLEEP()`, use `randomblob()`/heavy reads for time-based; `--` comment style).

### Authentication Bypass
- The hardcoded RSA private key at `lib/insecurity.ts:23` allows forging arbitrary valid JWTs. All "requires auth" vulnerabilities can therefore be accessed by an unauthenticated external attacker who forges a JWT.
- INJ-VULN-01 (login SQLi) itself provides direct auth bypass without needing a JWT.

### NoSQL Challenge-State Dependency
- Sources 3 and 4 (NoSQL $where injection) are gated by challenge flags (`noSqlCommandChallenge`, `reflectedXssChallenge`). When these challenges are **enabled** (default in a fresh Juice Shop instance), the `$where` string interpolation path is active. When disabled, numeric casting / regex filtering mitigates the injection.
- **Recommendation:** Confirm challenge state is enabled before testing INJ-VULN-03/04. A fresh instance will have challenges enabled.

---

## 4. Vulnerability Findings (Exploitation Queue)

### INJ-VULN-01 — Login Authentication SQL Injection

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-01 |
| **Vulnerability Type** | SQLi |
| **Externally Exploitable** | true |
| **Source** | `req.body.email` — POST /rest/user/login JSON body; routes/login.ts:34 |
| **Combined Sources** | `req.body.email` (unsanitized), `req.body.password` (MD5-hashed but irrelevant to email injection) |
| **Path** | Express POST handler → `models.sequelize.query()` raw SQL — routes/login.ts:34 |
| **Sink Call** | `models.sequelize.query(...)` — routes/login.ts:34 |
| **Slot Type** | SQL-val (email value in WHERE clause) |
| **Sanitization Observed** | NONE for email parameter. `security.hash(req.body.password)` (lib/insecurity.ts:43) only hashes the password field — does not touch email. |
| **Concat Occurrences** | routes/login.ts:34 — template literal: `` `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND ...` `` — occurs BEFORE any sanitization (none exists) |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `req.body.email` is directly interpolated into a raw SQL string via template literal. No parameterized binding, no escaping. The email value slot receives unsanitized string content, enabling full SQL injection. |
| **Witness Payload** | `' OR 1=1--` (in email field) — closes the string literal, short-circuits WHERE clause, authenticates as first user (admin). Or `bender@juice-sh.op'--` to target a specific account. |
| **Confidence** | high |
| **Notes** | No auth required. No rate limiting observed. The password field is hashed but the email field is the full injection point. SQLite dialect confirmed. |

---

### INJ-VULN-02 — Product Search SQL Injection (UNION-based Data Exfiltration)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-02 |
| **Vulnerability Type** | SQLi |
| **Externally Exploitable** | true |
| **Source** | `req.query.q` — GET /rest/products/search?q=; routes/search.ts:21 |
| **Combined Sources** | Single source: `req.query.q` |
| **Path** | Express GET handler → `criteria` variable → `models.sequelize.query()` — routes/search.ts:21–23 |
| **Sink Call** | `models.sequelize.query(...)` — routes/search.ts:23 |
| **Slot Type** | SQL-like (LIKE clause value) |
| **Sanitization Observed** | routes/search.ts:22 — length truncation to 200 characters (`criteria.substring(0, 200)`) — NOT a security control; only limits payload length |
| **Concat Occurrences** | routes/search.ts:23 — template literal: `` `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name` `` — `criteria` appears twice; no sanitization before this concat |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `criteria` (derived from `req.query.q`) is directly interpolated into a raw LIKE clause via template literal. The 200-character length limit is not a security control and does not prevent injection. Full UNION-based and error-based extraction is possible within 200 chars. |
| **Witness Payload** | `%' UNION SELECT id,email,password,'4','5','6','7','8' FROM Users--` — extracts all users' emails and hashed passwords |
| **Confidence** | high |
| **Notes** | No auth required. Verbose SQLite errors returned to client via Express error handler (next(error) at line 70). Column count for Products table is 8. Challenge detection code at lines 26–63 confirms that full user table extraction and sqlite_master schema extraction are the intended exploit outcomes. |

---

### INJ-VULN-03 — Product Reviews NoSQL Injection ($where JS Execution)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-03 |
| **Vulnerability Type** | SQLi (NoSQL variant — MongoDB $where injection) |
| **Externally Exploitable** | true |
| **Source** | `req.params.id` — GET /rest/products/:id/reviews; routes/showProductReviews.ts:31 |
| **Combined Sources** | Single source: `req.params.id` |
| **Path** | Express GET handler → `id = utils.trunc(req.params.id, 40)` → `db.reviewsCollection.find({ $where: 'this.product == ' + id })` — routes/showProductReviews.ts:31,36 |
| **Sink Call** | `db.reviewsCollection.find({ $where: 'this.product == ' + id })` — routes/showProductReviews.ts:36 |
| **Slot Type** | SQL-val (MongoDB $where JS expression operand) |
| **Sanitization Observed** | routes/showProductReviews.ts:31 — conditional: if `noSqlCommandChallenge` DISABLED → `Number(req.params.id)` (numeric cast, safe); if ENABLED → `utils.trunc(req.params.id, 40)` (40-char truncation + newline strip only — NOT safe) |
| **Concat Occurrences** | routes/showProductReviews.ts:36 — string concatenation: `'this.product == ' + id` — tainted when challenge is enabled |
| **Verdict** | **vulnerable** (when `noSqlCommandChallenge` is enabled — default state) |
| **Mismatch Reason** | When the challenge flag is active, `id` is only truncated to 40 characters and newlines stripped. The result is directly concatenated into a MongoDB `$where` JavaScript expression, allowing arbitrary JS code execution within MongoDB. The global `sleep()` function is exposed for time-based attacks. |
| **Witness Payload** | `1;sleep(2000);return true;/*` (as :id) — injects sleep call, confirms injection via response delay |
| **Confidence** | high |
| **Notes** | No auth required. The `sleep()` function is globally registered at lines 17–26 (max 2000ms enforced). Challenge state must be enabled (default). Attacker can enumerate all reviews using `return true` as condition. |

---

### INJ-VULN-04 — Order Tracking NoSQL Injection ($where JS Execution)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-04 |
| **Vulnerability Type** | SQLi (NoSQL variant — MongoDB $where injection) |
| **Externally Exploitable** | true |
| **Source** | `req.params.id` — GET /rest/track-order/:id; routes/trackOrder.ts:15 |
| **Combined Sources** | Single source: `req.params.id` |
| **Path** | Express GET handler → `id = utils.trunc(req.params.id, 60)` → `db.ordersCollection.find({ $where: \`this.orderId === '${id}'\` })` — routes/trackOrder.ts:15,18 |
| **Sink Call** | `db.ordersCollection.find({ $where: \`this.orderId === '${id}'\` })` — routes/trackOrder.ts:18 |
| **Slot Type** | SQL-val (MongoDB $where JS expression string literal) |
| **Sanitization Observed** | routes/trackOrder.ts:15 — conditional: if `reflectedXssChallenge` DISABLED → `String(req.params.id).replace(/[^\w-]+/g, '')` (alphanumeric+hyphen whitelist, safe); if ENABLED → `utils.trunc(req.params.id, 60)` (60-char truncation + newline strip — NOT safe) |
| **Concat Occurrences** | routes/trackOrder.ts:18 — template literal: `` `this.orderId === '${id}'` `` — tainted when challenge is enabled |
| **Verdict** | **vulnerable** (when `reflectedXssChallenge` is enabled — default state) |
| **Mismatch Reason** | When the challenge flag is active, `id` is truncated to 60 characters and interpolated into a MongoDB `$where` JS template string. Injecting a single quote closes the string literal and appends arbitrary JS, allowing Boolean-based extraction of all orders. |
| **Witness Payload** | `' || true || '` (as :id) — breaks out of string literal, OR-condition returns all orders; or `123'; return true; //` |
| **Confidence** | high |
| **Notes** | No auth required. Challenge state must be enabled (default). Returns raw order data including orderId values. The result at line 19 is returned directly to the client as JSON. |

---

### INJ-VULN-05 — Product Reviews NoSQL Operator Injection (Mass Update)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-05 |
| **Vulnerability Type** | SQLi (NoSQL operator injection) |
| **Externally Exploitable** | true |
| **Source** | `req.body.id` — PATCH /rest/products/reviews JSON body; routes/updateProductReviews.ts:18 |
| **Combined Sources** | `req.body.id` (filter), `req.body.message` (update payload) |
| **Path** | Express PATCH handler → `db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })` — routes/updateProductReviews.ts:17–20 |
| **Sink Call** | `db.reviewsCollection.update(...)` — routes/updateProductReviews.ts:17 |
| **Slot Type** | SQL-val (MongoDB filter document field value) |
| **Sanitization Observed** | NONE — `req.body.id` and `req.body.message` are passed directly to the MongoDB driver without any validation or sanitization |
| **Concat Occurrences** | No string concatenation; MongoDB object notation used directly. However, `req.body.id` is used as a MongoDB query object which accepts operators. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `req.body.id` is used as the MongoDB filter `_id` value without validation. When JSON body contains operator expressions (e.g., `{"$ne": null}`), MongoDB treats them as query operators rather than literal values. With `multi: true`, ALL matching documents are updated. |
| **Witness Payload** | `{"id": {"$ne": null}, "message": "hacked"}` — matches all review documents and overwrites all messages |
| **Confidence** | high |
| **Notes** | Auth required (isAuthorized middleware). JWT can be forged using hardcoded RSA private key (lib/insecurity.ts:23). The `multi: true` flag amplifies impact — all matching documents are modified. |

---

### INJ-VULN-06 — B2B Order notevil Sandbox RCE (vm.runInContext + safeEval)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-06 |
| **Vulnerability Type** | SSTI (JavaScript sandbox escape → RCE) |
| **Externally Exploitable** | true |
| **Source** | `req.body.orderLinesData` — POST /b2b/v2/orders JSON body; routes/b2bOrder.ts:19 |
| **Combined Sources** | Single source: `body.orderLinesData` |
| **Path** | Express POST handler → `orderLinesData = body.orderLinesData` → placed in vm sandbox → `vm.runInContext('safeEval(orderLinesData)', sandbox)` — routes/b2bOrder.ts:19–23 |
| **Sink Call** | `vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })` — routes/b2bOrder.ts:23 |
| **Slot Type** | TEMPLATE-expression (JavaScript expression evaluated via notevil + vm) |
| **Sanitization Observed** | routes/b2bOrder.ts:19 — `|| ''` default only. routes/b2bOrder.ts:22–23 — `vm.createContext(sandbox)` + `vm.runInContext()` provide Node.js VM context isolation (not process isolation). `notevil@1.3.3` (`safeEval`) provides loop detection only ("Infinite loop detected — reached max iterations") — documented as escapable. |
| **Concat Occurrences** | None — `orderLinesData` passed as variable reference into sandbox, evaluated by safeEval |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `notevil` provides loop detection but no cryptographic sandboxing. The Node.js `vm` module provides context isolation but not process isolation. Known escape vectors include Function constructor access: `Function('return process.mainModule.require("child_process").execSync("id").toString()')()`. The recon deliverable explicitly documents notevil as "escapable". |
| **Witness Payload** | `(function(){while(true){}})()` — triggers "Infinite loop detected" error (confirms eval path active); or `Function('return process')()` for sandbox escape |
| **Confidence** | med |
| **Notes** | Auth required (isAuthorized on /b2b/v2 routes). JWT forgeable via hardcoded RSA key. The vulnerability is conditionally active only when `rceChallenge` or `rceOccupyChallenge` is enabled (lines 18–37); otherwise the branch at line 35 returns success without evaluating. Confidence is medium due to sandbox escape requiring known notevil bypass techniques. |

---

### INJ-VULN-07 — User Profile eval() RCE (Stored username → eval)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-07 |
| **Vulnerability Type** | SSTI (JavaScript eval() RCE) |
| **Externally Exploitable** | true |
| **Source** | `user.username` — stored in SQLite Users table, set via PUT /api/Users/:id or POST /profile; routes/userProfile.ts:53 |
| **Combined Sources** | `user.username` from DB (tainted from any username-setting endpoint) |
| **Path** | GET /profile → `UserModel.findByPk()` → `username = user.username` → regex match `#{...}` → `code = username.substring(2, len-1)` → `eval(code)` — routes/userProfile.ts:35–62 |
| **Sink Call** | `eval(code)` — routes/userProfile.ts:62 |
| **Slot Type** | TEMPLATE-expression (raw JavaScript eval) |
| **Sanitization Observed** | routes/userProfile.ts:55 — `username.match(/#{(.*)}/)` pattern check (only executes if `#{...}` pattern present AND `usernameXssChallenge` enabled). routes/userProfile.ts:57 — `username.substring(2, username.length - 1)` extracts code between `#{` and `}`. NO sanitization of the code string itself. |
| **Concat Occurrences** | routes/userProfile.ts:57 — `username.substring()` extracts raw code. routes/userProfile.ts:62 — `eval(code)` executes it. No sanitization between extraction and execution. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `eval()` executes the username content directly with full Node.js process access — no sandbox, no restrictions. The only "guard" is a regex pattern match that ENABLES execution when `#{...}` is present. Attacker stores malicious payload in username then triggers it via GET /profile. |
| **Witness Payload** | Username: `#{process.mainModule.require('child_process').execSync('id').toString()}` — executes OS command on profile page load |
| **Confidence** | high |
| **Notes** | Auth required (valid JWT cookie). Attack is two-step: (1) set username via PUT /api/Users/:id or POST /profile, (2) trigger GET /profile. JWT forgeable via hardcoded RSA key. The `usernameXssChallenge` challenge flag must be enabled (default). The `// eslint-disable-line no-eval` comment confirms intentional use. |

---

### INJ-VULN-08 — User Profile Pug SSTI (Stored username → pug.compile)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-08 |
| **Vulnerability Type** | SSTI (Pug template compilation with user content) |
| **Externally Exploitable** | true |
| **Source** | `user.username` — stored in SQLite Users table, set via PUT /api/Users/:id or POST /profile; routes/userProfile.ts:53 |
| **Combined Sources** | `user.username` from DB (same as INJ-VULN-07) |
| **Path** | GET /profile → `UserModel.findByPk()` → `username` → `template.replace(/_username_/g, username)` → `pug.compile(template)` — routes/userProfile.ts:53,74,86 |
| **Sink Call** | `pug.compile(template)` — routes/userProfile.ts:86; `fn(user)` — routes/userProfile.ts:97 |
| **Slot Type** | TEMPLATE-expression (Pug template compilation with injected user data) |
| **Sanitization Observed** | routes/userProfile.ts:74 — `template.replace(/_username_/g, username)` performs direct string replacement with NO HTML/Pug escaping. `html-entities` (Entities class) is imported but NOT applied to username replacement (only to application name at line 77). |
| **Concat Occurrences** | routes/userProfile.ts:74 — post-processing concat: `template.replace(/_username_/g, username)` substitutes raw username into Pug template. routes/userProfile.ts:86 — `pug.compile(template)` compiles modified template as executable Pug code. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | Username is substituted into the Pug template string via simple string replacement without escaping. Pug directives injected into the template are compiled and executed. If `#{...}` eval (INJ-VULN-07) runs first, the eval result may itself contain Pug directives. Additionally, raw usernames containing Pug code (e.g., `- var x = process.mainModule`) are directly compiled. |
| **Witness Payload** | Username: `- var x = process.mainModule.require('child_process').execSync('whoami').toString()` — Pug executes the JavaScript statement during compilation |
| **Confidence** | high |
| **Notes** | Auth required (same as INJ-VULN-07). This is an independent SSTI path from INJ-VULN-07 — even if the eval branch is bypassed (e.g., `usernameXssChallenge` disabled), the Pug compilation path at line 86 still receives the raw username. The `html-entities` library is present but not applied to the username substitution. |

---

### INJ-VULN-09 — Data Erasure LFI via Layout Parameter

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-09 |
| **Vulnerability Type** | LFI (Local File Inclusion via Express layout parameter) |
| **Externally Exploitable** | true |
| **Source** | `req.body.layout` — POST /rest/data-erase JSON/form body; routes/dataErasure.ts:68 |
| **Combined Sources** | Single source: `req.body.layout` |
| **Path** | Express POST handler → `path.resolve(req.body.layout).toLowerCase()` → blacklist check → `res.render('dataErasureResult', { ...req.body })` — routes/dataErasure.ts:68–80 |
| **Sink Call** | `res.render('dataErasureResult', { ...req.body }, callback)` — routes/dataErasure.ts:72; the `layout` key in `req.body` controls the template layout path used by the Express view engine |
| **Slot Type** | FILE-path (Express view engine layout path) |
| **Sanitization Observed** | routes/dataErasure.ts:69 — `path.resolve(req.body.layout).toLowerCase()` — resolves and lowercases path. routes/dataErasure.ts:70 — blacklist check: `filePath.includes('ftp') \|\| filePath.includes('ctf.key') \|\| filePath.includes('encryptionkeys')` — incomplete blacklist |
| **Concat Occurrences** | routes/dataErasure.ts:69 — `path.resolve(req.body.layout)` — resolves user-supplied path to absolute. routes/dataErasure.ts:72 — `{ ...req.body }` spreads entire body (including layout) into render options. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | The blacklist only filters three specific path fragments ('ftp', 'ctf.key', 'encryptionkeys'). Any other filesystem path (e.g., `/etc/passwd`, `../node_modules/...`, application source files) passes validation and is used as a template layout, allowing arbitrary file read as a template. |
| **Witness Payload** | `{"layout": "../../../../etc/passwd"}` in POST body — reads /etc/passwd as a template layout; first 100 chars returned in response (line 77) |
| **Confidence** | high |
| **Notes** | Auth required (valid JWT cookie). JWT forgeable. Response is truncated to 100 chars (line 77: `html.slice(0, 100) + '......'`). The LFI challenge is explicitly tracked at line 79 (`lfrChallenge`). Path traversal from app root to system files is the primary attack vector. |

---

### INJ-VULN-10 — Profile Image URL SSRF

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-10 |
| **Vulnerability Type** | LFI (SSRF — Server-Side Request Forgery) |
| **Externally Exploitable** | true |
| **Source** | `req.body.imageUrl` — POST /profile/image/url JSON body; routes/profileImageUrlUpload.ts:19 |
| **Combined Sources** | Single source: `req.body.imageUrl` |
| **Path** | Express POST handler → `url = req.body.imageUrl` → `fetch(url)` — routes/profileImageUrlUpload.ts:19,24 |
| **Sink Call** | `fetch(url)` — routes/profileImageUrlUpload.ts:24 |
| **Slot Type** | FILE-path (URL passed to fetch()) |
| **Sanitization Observed** | routes/profileImageUrlUpload.ts:20 — regex check `/(.)*solve\/challenges\/server-side(.)*/` — DETECTION ONLY (sets `abused_ssrf_bug` flag), does NOT prevent execution. No URL scheme validation, no hostname whitelist, no blocklist. |
| **Concat Occurrences** | routes/profileImageUrlUpload.ts:19 — `const url = req.body.imageUrl` — direct assignment, no transformation. routes/profileImageUrlUpload.ts:24 — `fetch(url)` — direct use. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `req.body.imageUrl` is passed directly to `fetch()` with no URL validation. Any URL scheme and hostname accepted. The regex pattern at line 20 is a challenge-detection hook, not a security control. Cloud metadata endpoints (`http://169.254.169.254/`), internal services, and arbitrary HTTP hosts are all reachable. |
| **Witness Payload** | `{"imageUrl": "http://169.254.169.254/latest/meta-data/"}` — cloud metadata SSRF; or `{"imageUrl": "http://localhost:3000/api/Users/"}` for internal API access |
| **Confidence** | high |
| **Notes** | Auth required (valid JWT cookie). JWT forgeable. The catch block at lines 33–37 stores the raw URL in the DB if fetch fails — enabling blind SSRF even when target returns errors. |

---

### INJ-VULN-11 — XML File Upload XXE (Entity Expansion)

| Field | Value |
|-------|-------|
| **ID** | INJ-VULN-11 |
| **Vulnerability Type** | LFI (XXE — XML External Entity Injection) |
| **Externally Exploitable** | true |
| **Source** | Multipart file upload body — POST /file-upload (XML file); routes/fileUpload.ts:77 |
| **Combined Sources** | Single source: `file.buffer` (uploaded XML file content) |
| **Path** | Express POST handler → `data = file.buffer.toString()` → placed in vm sandbox → `libxml.parseXml(data, { noent: true })` — routes/fileUpload.ts:77–81 |
| **Sink Call** | `vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })` — routes/fileUpload.ts:81 |
| **Slot Type** | DESERIALIZE-object (XML parsed with external entity expansion enabled) |
| **Sanitization Observed** | routes/fileUpload.ts:75 — `.xml` extension check (filename must end with .xml). routes/fileUpload.ts:76–81 — challenge flag check (`deprecatedInterfaceChallenge` must be enabled). NO DTD stripping, NO entity resolution restrictions. `noent: true` **explicitly enables** external entity expansion. |
| **Concat Occurrences** | routes/fileUpload.ts:77 — `file.buffer.toString()` converts binary to string. routes/fileUpload.ts:81 — `libxml.parseXml(data, ...)` parses XML with entities expanded. No concat; direct parse. |
| **Verdict** | **vulnerable** |
| **Mismatch Reason** | `libxml.parseXml()` is called with `noent: true`, which explicitly instructs the parser to expand external entities (XXE). No DTD filtering or entity resolver restrictions are applied. The uploaded XML content is fully controlled by the attacker. |
| **Witness Payload** | XML file with external entity declaration: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` — reads /etc/passwd via XXE |
| **Confidence** | high |
| **Notes** | No auth required for file upload endpoint. Challenge flag `deprecatedInterfaceChallenge` must be enabled (default). The parsed XML string is returned in the HTTP 410 error response at line 85, truncated to 400 chars — enabling direct file content exfiltration via the error message. |

---

## 5. Vectors Analyzed and Confirmed Secure

These input vectors were traced and confirmed to have robust, context-appropriate defenses or are not externally exploitable via the attack scope. They are **low-priority** for further testing.

| **Source (Parameter/Key)** | **Endpoint/File Location** | **Defense Mechanism Implemented** | **Verdict** |
|-----------------------------|---------------------------|-----------------------------------|-------------|
| `req.params.file` (FTP server) | `GET /ftp/:file` — routes/fileServer.ts:16 | Extension whitelist (.md, .pdf only), forward-slash check, null-byte filter (`security.cutOffPoisonNullByte`) — strong validation preventing path traversal outside ftp/ directory | SAFE |
| `req.params.file` (Log server) | `GET /support/logs/:file` — routes/logfileServer.ts:11 | Forward-slash check; on Linux (Juice Shop target OS) `/` is the sole path separator, sufficient to block traversal above `logs/` | SAFE (Linux only) |
| `req.params.file` (Encryption key server) | `GET /encryptionkeys/:file` — routes/keyServer.ts:11 | Forward-slash check; same reasoning as log server — effective on Linux target | SAFE (Linux only) |
| Video subtitle content | `GET /promotion` — routes/videoHandler.ts:55,70 | Subtitle content comes from server-side config file (`config.get('application.promotion.subtitles')`), not from any HTTP request parameter. External attackers cannot control the subtitle file path via HTTP. | NOT externally exploitable |
| `file.buffer` (YAML upload) | `POST /file-upload` — routes/fileUpload.ts:111,116 | `js-yaml@4.1.0` `yaml.load()` does not execute code in v4. Risk is DoS via YAML bomb only — no code execution path. | SAFE for RCE/deserialization injection |

---

## 6. Analysis Constraints and Blind Spots

- **Challenge-State Dependency (Sources 3, 4, 6):** The MongoDB `$where` injection paths (INJ-VULN-03, INJ-VULN-04) and B2B eval path (INJ-VULN-06) are conditionally active based on Juice Shop challenge flags. On a default fresh instance all challenges are enabled. If challenges were manually disabled, the safer code paths would activate and mitigate these vulnerabilities.

- **Two-Step Exploit for eval/SSTI (Sources 7, 8):** INJ-VULN-07 and INJ-VULN-08 require a setup step (setting the malicious username via PUT /api/Users/:id) before triggering via GET /profile. The exploitation phase should verify the username-setting endpoint is accessible with a standard user JWT.

- **SQLite Dialect:** The database is SQLite (confirmed via `sqlite_master` reference in search.ts:47). SQLite does not support stacked queries, `SLEEP()`, or OUT-OF-BAND techniques. Time-based blind injection must use CPU-intensive operations (`randomblob()`). UNION-based extraction is the primary recommended technique for INJ-VULN-01/02.

- **JWT Forgery as Auth Bypass:** All "auth required" vulnerabilities assume JWT forgery is viable via the hardcoded RSA private key. This was confirmed in the recon phase. The exploitation phase should verify the JWT signing key before relying on this bypass.

- **notevil Sandbox Escape Confidence:** INJ-VULN-06 is rated medium confidence because the actual escape technique depends on notevil v1.3.3 specifics. The recon document explicitly marks it as escapable but specific bypass vectors were not validated via live testing in this phase.

---

*Report generated: 2026-04-20 | Analyst: Injection Analysis Specialist*
