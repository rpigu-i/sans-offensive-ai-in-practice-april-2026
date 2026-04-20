# Authentication Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** 14 exploitable authentication vulnerabilities identified across all methodology checks. The application's authentication model is comprehensively broken: the JWT private key is hardcoded in source, login lacks any rate limiting, passwords are stored as unsalted MD5 with hashes embedded in every JWT, the sole session store has no invalidation mechanism, cookies lack all security flags, and a critical SQL injection enables complete authentication bypass.
- **Purpose of this Document:** This report provides the strategic context, code-backed root-cause analysis, and precise exploitation hypotheses for the Exploitation phase. Every finding is tied to specific file:line locations in the source code, live-confirmed where applicable, and ranked by exploitability.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Token Trust Failure (JWT Forgery + Algorithm Confusion)
- **Description:** The RSA private key used to sign all JWTs is hardcoded in `lib/insecurity.ts` line 23 and the corresponding public key is served unauthenticated at `/encryptionkeys/jwt.pub`. Additionally, `express-jwt@0.1.3` is initialized with no `algorithms` restriction, enabling RS256→HS256 key-confusion and `alg:none` attacks.
- **Implication:** Any attacker can forge a JWT claiming any role (admin, accounting) for any user without needing valid credentials.
- **Representative Findings:** `AUTH-VULN-05`, `AUTH-VULN-06`.

### Pattern 2: No Authentication Brute-Force Defenses
- **Description:** Neither the login endpoint (`POST /rest/user/login`) nor the registration endpoint (`POST /api/Users`) have any rate limiting, CAPTCHA, or account lockout. The only rate-limited auth endpoint is password reset (out of scope).
- **Implication:** Attackers can brute-force any account password or conduct credential stuffing campaigns indefinitely without throttling.
- **Representative Findings:** `AUTH-VULN-01`, `AUTH-VULN-02`.

### Pattern 3: Weak Session Lifecycle (Cookie Flags + No Invalidation)
- **Description:** The token cookie is set without `HttpOnly`, `Secure`, or `SameSite` flags. There is no logout endpoint and no server-side invalidation mechanism — the in-memory `tokenMap` has no delete operation.
- **Implication:** Session tokens can be stolen via XSS, intercepted over HTTP, and replayed indefinitely within the 6-hour window with no revocation path.
- **Representative Findings:** `AUTH-VULN-03`, `AUTH-VULN-04`.

### Pattern 4: MD5 Credential Exposure
- **Description:** All user passwords are hashed with unsalted MD5 (`crypto.createHash('md5')` at `lib/insecurity.ts` line 43). Worse, the full MD5 hash is embedded in the JWT payload (confirmed live in decoded token), so any intercepted token directly exposes the crackable hash.
- **Implication:** Any user whose JWT is intercepted has their password trivially crackable offline via rainbow tables; no database access required.
- **Representative Findings:** `AUTH-VULN-07`, `AUTH-VULN-13`.

### Pattern 5: Direct Privilege Escalation Paths
- **Description:** Two independent, trivially exploitable paths to admin exist: (1) SQL injection in the login `email` field bypasses authentication entirely; (2) the `role` field is writable at registration (`POST /api/Users`) with no server-side restriction — live-confirmed: `role:"admin"` accepted.
- **Implication:** An anonymous attacker can achieve admin-level access in a single unauthenticated request.
- **Representative Findings:** `AUTH-VULN-09`, `AUTH-VULN-10`.

---

## 3. Strategic Intelligence for Exploitation

- **Authentication Method:** Custom JWT-based authentication. Token signed with RS256 (hardcoded private key). Token returned in JSON body of `POST /rest/user/login` response; frontend stores in `token` cookie via JavaScript and injects via HTTP interceptor for all subsequent requests.
- **Token Delivery:** `{"authentication":{"token":"<JWT>","bid":<basket_id>,"umail":"<email>"}}` — token only in JSON body, NOT in `Set-Cookie`. Cookie is set server-side by `updateAuthenticatedUsers()` middleware (`lib/insecurity.ts` line 195) on first authenticated request, without any security flags.
- **Token Storage on Server:** In-memory `authenticatedUsers.tokenMap` in `lib/insecurity.ts` lines 72-93. Map entries are never deleted. Token TTL is 6 hours per JWT `exp` claim.
- **JWT Library:** `jsonwebtoken@0.4.0` (severely outdated; current is 9.x). `express-jwt@0.1.3` (deprecated; no `algorithms` enforcement).
- **JWT Payload Contents (Live-Confirmed):** Full user DB row included: `id`, `email`, `password` (MD5 hash), `role`, `lastLoginIp`, `totpSecret`, `isActive`, `createdAt`, `updatedAt`. Example decoded: `{"data":{"id":1,"email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500","role":"admin",...},"iat":1776713039}`.
- **Public Key:** Exposed at `http://juice-shop:3000/encryptionkeys/jwt.pub` (unauthenticated, confirmed live). Required for RS256→HS256 key-confusion attack.
- **Password Policy:** No server-side enforcement. MD5 without salt (`lib/insecurity.ts` line 43). Default admin credentials `admin@juice-sh.op:admin123` ship with the application (live-confirmed).
- **Transport:** HTTP only on port 3000. No HTTPS, no HSTS, no redirect. No `Cache-Control: no-store` on auth responses.
- **Live-Confirmed Header Absence on Login:** No `Strict-Transport-Security`, no `Set-Cookie` with flags, no `Cache-Control: no-store` in `POST /rest/user/login` response.
- **User Enumeration:** Login endpoint is NOT enumerable (generic error). Registration IS enumerable (live-confirmed: `{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}`).

---

## 4. Vulnerability Findings

### AUTH-VULN-01: No Rate Limiting on POST /rest/user/login
- **Type:** Abuse_Defenses_Missing
- **Code Location:** `server.ts` lines 341-348 — rate limiting explicitly configured ONLY for `/rest/user/reset-password`; no rate limit on `/rest/user/login`
- **Missing Defense:** No per-IP or per-account rate limit, CAPTCHA, or lockout on the primary login endpoint
- **Live Evidence:** 20 consecutive failed login attempts all returned HTTP 401 with no throttling, no 429, no lockout

### AUTH-VULN-02: No Rate Limiting on POST /api/Users (Registration)
- **Type:** Abuse_Defenses_Missing
- **Code Location:** `server.ts` lines 341-348 — no rate limit on `/api/Users`
- **Missing Defense:** No rate limiting on account registration; error message on duplicate email reveals whether account exists
- **Live Evidence:** Registration returns `{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}` for existing emails — enables email enumeration

### AUTH-VULN-03: Token Cookie Lacks Security Flags (HttpOnly, Secure, SameSite)
- **Type:** Session_Management_Flaw
- **Code Location:** `lib/insecurity.ts` line 195: `res.cookie('token', token)` — no options object
- **Missing Defense:** No `HttpOnly` flag (XSS steals token), no `Secure` flag (plaintext HTTP transmission), no `SameSite` flag (CSRF possible)
- **Live Evidence:** Login response headers confirm no `Set-Cookie` with security flags; `Access-Control-Allow-Origin: *` CORS makes cross-origin theft viable

### AUTH-VULN-04: No Server-Side Session Invalidation / No Logout Endpoint
- **Type:** Session_Management_Flaw
- **Code Location:** `lib/insecurity.ts` lines 72-93 — `authenticatedUsers` object has `put`, `get`, `tokenOf`, `from`, `updateFrom` methods but NO `delete`/`remove` method; no `logout.ts` route file exists; no logout route in `server.ts`
- **Missing Defense:** No logout mechanism; once a token is issued it cannot be server-side invalidated before 6-hour JWT expiry

### AUTH-VULN-05: JWT RSA Private Key Hardcoded in Source Code
- **Type:** Token_Management_Issue
- **Code Location:** `lib/insecurity.ts` line 23 — full 1024-bit RSA private key embedded as string literal; `lib/insecurity.ts` line 56: `jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`
- **Missing Defense:** Key not externalized to secrets management; public key also served unauthenticated at `/encryptionkeys/jwt.pub`
- **Live Evidence:** Public key confirmed at `http://juice-shop:3000/encryptionkeys/jwt.pub`

### AUTH-VULN-06: JWT Algorithm Confusion — No Algorithm Enforcement in express-jwt
- **Type:** Token_Management_Issue
- **Code Location:** `lib/insecurity.ts` line 54: `expressJwt(({ secret: publicKey }) as any)` — no `algorithms` field specified; `jsonwebtoken@0.4.0` (pre-CVE-2015-9235 fix)
- **Missing Defense:** Old `express-jwt@0.1.3` with `jsonwebtoken@0.4.0` does not enforce algorithm; RS256→HS256 key-confusion attack (using public key as HMAC secret) and `alg:none` bypass are plausible

### AUTH-VULN-07: MD5 Password Hashing Without Salt
- **Type:** Weak_Credentials
- **Code Location:** `lib/insecurity.ts` line 43: `crypto.createHash('md5').update(data).digest('hex')`; `models/user.ts` line 77: `this.setDataValue('password', security.hash(clearTextPassword))`
- **Missing Defense:** MD5 is cryptographically broken; no salt; entire rainbow table coverage available

### AUTH-VULN-08: Default Admin Credentials
- **Type:** Weak_Credentials
- **Code Location:** `data/static/users.yml` — `email: admin@juice-sh.op`, `password: admin123`, `role: admin`
- **Missing Defense:** Hardcoded default admin credentials not forced to change on deployment
- **Live Evidence:** Login with `admin@juice-sh.op:admin123` returns HTTP 200 with valid admin JWT

### AUTH-VULN-09: Mass Assignment — Role Field Writable at Registration
- **Type:** Authentication_Bypass
- **Code Location:** `models/user.ts` lines 80-99 — `role` field has no write protection; `server.ts` lines 407-421 — finale-rest auto-generates CRUD with no field allowlist
- **Missing Defense:** `role` field not excluded from writeable attributes; no server-side validation that `role` must be `customer` at registration
- **Live Evidence:** `POST /api/Users` with `"role":"admin"` returns HTTP 201 with `"role":"admin"` in response body

### AUTH-VULN-10: SQL Injection Authentication Bypass
- **Type:** Authentication_Bypass
- **Code Location:** `routes/login.ts` line 34: `` `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL` `` — raw string interpolation, no parameterization
- **Missing Defense:** No prepared statements/parameterized queries; raw SQL string concatenation of user input

### AUTH-VULN-11: No HTTPS / No HSTS
- **Type:** Transport_Exposure
- **Code Location:** `server.ts` lines 185-187 — only `helmet.noSniff()` and `helmet.frameguard()` configured; `helmet.hsts()` absent; no HTTPS middleware
- **Missing Defense:** No TLS, no HTTPS redirect, no `Strict-Transport-Security` header
- **Live Evidence:** Server responds on `http://juice-shop:3000` with no HTTPS redirect; no `Strict-Transport-Security` header in any response

### AUTH-VULN-12: No Cache-Control: no-store on Auth Responses
- **Type:** Transport_Exposure
- **Code Location:** No `Cache-Control: no-store` set in any auth route handler or middleware
- **Missing Defense:** Auth responses (including JWT-containing login response) lack `Cache-Control: no-store` / `Pragma: no-cache`
- **Live Evidence:** `POST /rest/user/login` response includes `ETag` header with no `Cache-Control` restriction

### AUTH-VULN-13: MD5 Password Hash Embedded in JWT Payload
- **Type:** Token_Management_Issue
- **Code Location:** `routes/login.ts` lines 19-26 — full `user.data` object (including `password` MD5 hash field) passed to `security.authorize(user)` without field stripping
- **Missing Defense:** Sensitive fields not excluded from JWT payload; password hash embedded in every issued token
- **Live Evidence:** Decoded JWT payload contains `"password":"0192023a7bbd73250516f069df18b500"` (MD5 of `admin123`) — crackable in seconds

### AUTH-VULN-14: User Enumeration via Registration Endpoint
- **Type:** Login_Flow_Logic
- **Code Location:** `models/user.ts` — Sequelize unique constraint on `email`; error propagated to client without sanitization
- **Missing Defense:** Duplicate email error reveals whether an email address is registered
- **Live Evidence:** `POST /api/Users` with `admin@juice-sh.op` returns `{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}` confirming account existence

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have adequate defenses. They are low-priority for further testing.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Login Error Messages (User Enumeration) | `routes/login.ts` line 49 | Generic `"Invalid email or password."` for both unknown email and wrong password | SAFE |
| JWT Token Expiration | `lib/insecurity.ts` line 56 | `expiresIn: '6h'` enforced via RS256-signed JWT | SAFE (TTL present) |
| Password Reset Error Messages | `routes/resetPassword.ts` line 47 | Same `"Wrong answer to security question."` for non-existent user and wrong answer | SAFE |
| Session Fixation | N/A — JWT-based auth | Each login generates a fresh JWT via `security.authorize(user)` — no pre-login session ID to fix | NOT APPLICABLE |
| TOTP Second Factor Endpoint | `POST /rest/2fa/verify` | Out of scope per engagement rules; rate-limited per `server.ts` | OUT OF SCOPE |
| OAuth/SSO | `frontend/src/app/oauth/` | Out of scope per engagement rules | OUT OF SCOPE |
