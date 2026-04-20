# Reconnaissance Deliverable: OWASP Juice Shop

## 0) HOW TO READ THIS

This reconnaissance report provides a comprehensive map of the application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint — focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls — understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping — use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing (per engagement scope):**
1. `POST /rest/user/login` — SQL injection authentication bypass (primary demo target)
2. `POST /api/Users` — Mass assignment privilege escalation (admin role via registration)
3. `GET /rest/basket/:id` — IDOR basket access (horizontal privilege escalation)
4. `POST /b2b/v2/orders` — SSTI/RCE via `vm.runInContext(safeEval(orderLinesData))` (code execution target)

---

## 1. Executive Summary

OWASP Juice Shop is a deliberately vulnerable e-commerce web application built with an **Express.js 4.22.1 / Node.js 20-24 / TypeScript** backend and an **Angular 20** single-page-application frontend. Both the API and the pre-built Angular SPA are served from the same process on **port 3000** of a single host (`juice-shop`). The application serves as a security training platform and intentionally contains multiple classes of exploitable vulnerabilities.

The attack surface consists of **167+ network-accessible entry points**: 89 explicit REST routes, 28 auto-generated CRUD endpoints (via `finale-rest`), WebSocket events (Socket.IO), and four directory-listing endpoints. Authentication relies on JWT tokens signed with a hardcoded RSA private key using the obsolete `jsonwebtoken@0.4.0` library. All user passwords are hashed with unsalted MD5, making them trivially rainbow-tableable.

**Priority attack surfaces per engagement scope:**
1. **Login SQLi** (`POST /rest/user/login`) — raw SQL string interpolation of `req.body.email` with no parameterization
2. **Registration mass assignment** (`POST /api/Users`) — the `role` field is writable at registration, allowing direct admin account creation (live-confirmed: `role:"admin"` accepted)
3. **Basket IDOR** (`GET /rest/basket/:id`) — authenticated endpoint with zero ownership check on the `:id` path parameter (live-confirmed: admin token retrieved basket owned by user 2)
4. **B2B SSTI/RCE** (`POST /b2b/v2/orders`) — `orderLinesData` passed through `vm.runInContext(safeEval(...))` enabling sandbox escape/DoS

---

## 2. Technology & Service Map

- **Frontend:** Angular 20 (pre-built SPA served as static files from `frontend/dist/frontend/`); uses Angular `DomSanitizer.bypassSecurityTrustHtml()` extensively, creating XSS sink surfaces. HTTP interceptor at `frontend/src/app/Services/request.interceptor.ts` injects JWT into every request.
- **Backend:** Node.js 20-24 / TypeScript ~5.3.3 / Express.js 4.22.1. Route handlers in `routes/` (63 files). ORM: Sequelize 6.37.3 (SQLite). Secondary DB: MarsDB (MongoDB-compatible in-memory). Template engine: Pug 3.0.3. XML parser: libxmljs2 0.35.0.
- **Authentication Libraries:** `jsonwebtoken@0.4.0` (CRITICAL: severely outdated, current 9.x); `express-jwt@0.1.3` (deprecated, unmaintained)
- **Other Key Dependencies:** `finale-rest@1.1.1` (auto-generates CRUD routes), `sanitize-html@1.4.2` (outdated, bypass-prone), `safe-eval` / `notevil` (sandboxed eval, escapable), `helmet@4.6.0` (XSS filter explicitly disabled), `socket.io@4.8.1`
- **Infrastructure:** Single Docker container running as non-root UID 65532 (`gcr.io/distroless/nodejs24-debian13`); no HTTPS; no external infrastructure
- **Database:** SQLite (ephemeral — recreated on restart via `sequelize.sync({ force: true })`). MarsDB in-memory for reviews/orders.
- **Identified Subdomains:** None (single host `juice-shop`, no subdomain enumeration results from pre-recon)
- **Open Ports & Services:**
  - `tcp/3000` — Express.js HTTP server (primary attack surface; Angular SPA + REST API + Socket.IO + static files)
  - No other open ports identified externally

---

## 3. Authentication & Session Management Flow

### Entry Points
- `POST /rest/user/login` — primary credential-based login
- `POST /api/Users` — user registration (creates account; no email verification)
- `POST /rest/2fa/verify` — TOTP second factor (out of scope per rules)

### Mechanism (Step-by-Step)
1. **Credential Submission:** Client POSTs `{ email, password }` JSON to `POST /rest/user/login`
2. **SQL Query (VULNERABLE):** `routes/login.ts` line 34 executes: `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${MD5(req.body.password)}' AND deletedAt IS NULL` — raw string interpolation, no parameterization
3. **Token Generation:** On success, `security.authorize(user)` at `lib/insecurity.ts` line 56 signs a JWT with the hardcoded RSA private key using RS256 algorithm; token expires in 6 hours
4. **Response:** Returns `{ authentication: { token, bid, umail } }` — token is the JWT, `bid` is the basket ID for this user
5. **Token Storage (Client):** Frontend stores token in cookie (`token`) AND injects it into every request via the HTTP interceptor
6. **Cookie Configuration:** Cookie set WITHOUT `HttpOnly`, `Secure`, or `SameSite` flags — fully accessible via JavaScript (`lib/insecurity.ts` ~line 195)
7. **Session Map:** Tokens are also stored server-side in `security.authenticatedUsers.tokenMap` — required by some inline auth checks (e.g., `routes/orderHistory.ts`, `routes/updateUserProfile.ts`)

### Code Pointers
- `routes/login.ts` — Login handler, SQL injection at line 34
- `lib/insecurity.ts` — All crypto: JWT signing (line 56), MD5 hash (line 43), public key load (line 22), private key hardcoded (line 23)
- `lib/utils.ts` lines 130–143 — Token extraction from `Authorization: Bearer` header or `req.cookies.token`

### 3.1 Role Assignment Process
- **Role Determination:** Role is stored as a field in the `Users` SQLite table. On registration, defaults to `'customer'`. JWT payload includes `data.role` claim which is read from the database record at login time.
- **Default Role:** `'customer'` (defined as `defaultValue: 'customer'` in `models/user.ts` line 82)
- **Role Upgrade Path:**
  - **Mass assignment (CRITICAL):** `POST /api/Users` accepts `role` field in POST body — no server-side restriction on the value. Live-confirmed: posting `{ "role": "admin" }` creates an admin account. See `models/user.ts` and `server.ts` lines 407–421.
  - **Deluxe upgrade:** `POST /rest/deluxe-membership` — upgrades customer to deluxe; payment bypass possible (see Section 8.3)
  - **No admin → customer downgrade path** exists in the application
- **Code Implementation:** `models/user.ts` lines 80–99 (role field definition); `server.ts` lines 407–421 (registration pre-hooks); `data/static/users.yml` (seeded default users)

### 3.2 Privilege Storage & Validation
- **Storage Location:** Role stored in SQLite `Users` table. Embedded in JWT `data.role` claim after login. JWT is the primary session token — no server-side session store for role validation (except the token map used by some routes).
- **Validation Points:**
  - **Middleware:** `security.isAuthorized()` (validates JWT signature only, not role); `security.isAccounting()` (validates JWT + checks `role === 'accounting'`); `security.denyAll()` (blocks all with random secret)
  - **Inline:** `security.isDeluxe(req)` and `security.isCustomer(req)` are called inside route handlers (not middleware) — see `routes/b2bOrder.ts`, `routes/order.ts`, `routes/deluxe.ts`
- **Cache/Session Persistence:** JWT lives 6 hours. No refresh mechanism. `authenticatedUsers.tokenMap` persists until server restart (in-memory).
- **Code Pointers:** `lib/insecurity.ts` lines 54–55 (middleware factories), 156–175 (role check functions), 177–186 (`appendUserId`)

### 3.3 Role Switching & Impersonation
- **Impersonation Features:** None built into the application.
- **Role Switching:** No legitimate "sudo mode." However, the hardcoded RSA private key allows forging JWTs with any role — functional impersonation without application support.
- **Audit Trail:** No role-change logging. Morgan logs HTTP requests but no role-specific audit trail.
- **Code Implementation:** JWT forgery via hardcoded private key at `lib/insecurity.ts` line 23. Public key accessible at `/encryptionkeys/jwt.pub`.

---

## 4. API Endpoint Inventory

**Network Surface Focus:** Only network-accessible endpoints reachable via HTTP requests to `http://juice-shop:3000`.

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|---|---|---|---|---|---|
| POST | `/rest/user/login` | anon | None | None | Credential login; SQL injection in `email` field. `routes/login.ts:34` |
| POST | `/api/Users` | anon | None | None (POST only allowed) | User registration; mass assignment — `role` field writable. `models/user.ts:82`, `server.ts:407` |
| GET | `/rest/user/whoami` | anon | None | `updateAuthenticatedUsers()` (non-blocking) | Returns current user from token map; empty `{}` if unauthenticated. `routes/currentUser.ts` |
| GET | `/rest/user/authentication-details` | user | None | `isAuthorized()` | Returns authenticated user details. `routes/authenticatedUsers.ts`, `server.ts:397` |
| GET | `/rest/user/change-password` | anon | None | None (token read from Authorization header) | Changes password; no current-password required when token present. `routes/changePassword.ts` |
| GET | `/rest/user/security-question` | anon | None | None | Returns security question for email. `routes/securityQuestion.ts` |
| POST | `/rest/user/reset-password` | anon | None | Rate-limited (100/5min, X-Forwarded-For spoofable) | Password reset via security answer HMAC. `routes/resetPassword.ts` |
| GET | `/rest/products/search` | anon | None | None | Product search; SQL injection in `q` query param. `routes/search.ts:23` |
| GET | `/rest/basket/:id` | user | `id` (basket ID) | `isAuthorized()` + `appendUserId()` — NO ownership check | IDOR confirmed — any basket accessible by ID. `routes/basket.ts:19` |
| POST | `/rest/basket/:id/checkout` | user | `id` (basket ID) | `isAuthorized()` + `appendUserId()` | Checkout basket; creates PDF order receipt. `routes/order.ts`, `server.ts:399` |
| PUT | `/rest/basket/:id/coupon/:coupon` | user | `id` (basket ID) | `isAuthorized()` | Apply coupon to basket. `server.ts:398` |
| POST | `/api/BasketItems` | user | `BasketId` | `isAuthorized()` + `appendUserId()` + ownership check bypassable via HTTP param pollution | Add item to basket; IDOR via duplicate JSON key. `routes/basketItems.ts:37` |
| PUT | `/api/BasketItems/:id` | user | `id` (BasketItem ID) | `appendUserId()` — NO ownership check on item ID | Update basket item; no ownership verification. `routes/basketItems.ts:65` |
| DELETE | `/api/BasketItems/:id` | user | `id` | `isAuthorized()` | Delete basket item. `server.ts:357` |
| POST | `/b2b/v2/orders` | user | None | `isAuthorized()` (blanket `/b2b/v2`) | B2B order; RCE via `vm.runInContext(safeEval(orderLinesData))`. `routes/b2bOrder.ts:23`, `server.ts:423` |
| GET | `/rest/order-history` | user | None | Inline token-map check (no Express middleware) | Own order history; auth checked inline, error on failure. `routes/orderHistory.ts:11` |
| GET | `/rest/order-history/orders` | accounting | None | `isAccounting()` | All orders (admin view). `server.ts:622` |
| PUT | `/rest/order-history/:id/delivery-status` | accounting | `id` (order ID) | `isAccounting()` | Toggle delivery status. `server.ts:623` |
| GET | `/api/Users` | user | None | `isAuthorized()` | List all users (no admin check); exposes emails, roles, MD5 password hashes in some configs. `server.ts:362` |
| GET | `/api/Users/:id` | user | `id` (user ID) | `isAuthorized()` — NO ownership check | Get any user by ID; any authenticated user can fetch any user record. `server.ts:364` |
| POST | `/api/Cards` | user | None | `appendUserId()` | Add payment card; UserId injected from JWT. `server.ts:437` |
| GET | `/api/Cards` | user | None | `appendUserId()` | List own payment cards. `routes/payment.ts:21` |
| GET | `/api/Cards/:id` | user | `id` (card ID) | `appendUserId()` + ownership in handler | Get card by ID with UserId filter. `routes/payment.ts:41` |
| DELETE | `/api/Cards/:id` | user | `id` | `appendUserId()` + ownership in handler | Delete card. `routes/payment.ts:70` |
| GET | `/api/Addresss` | user | None | `appendUserId()` | List own addresses. `server.ts:448` |
| POST | `/api/Addresss` | user | None | `appendUserId()` | Add address. `server.ts:447` |
| PUT | `/api/Addresss/:id` | user | `id` | `appendUserId()` | Update address. `server.ts:449` |
| DELETE | `/api/Addresss/:id` | user | `id` | `appendUserId()` | Delete address. `server.ts:450` |
| GET | `/api/Addresss/:id` | user | `id` | `appendUserId()` | Get address. `server.ts:451` |
| POST | `/api/PrivacyRequests` | user | None | `isAuthorized()` | Submit GDPR privacy request. `server.ts:434` |
| POST | `/rest/user/data-export` | user | None | `appendUserId()` | Export user PII. `routes/dataExport.ts`, `server.ts:618` |
| POST | `/rest/data-erase` | user | None | Cookie/Bearer auth | Data erasure; LFI via `req.body.layout`. `routes/dataErasure.ts:69` |
| GET | `/rest/wallet/balance` | user | None | `appendUserId()` | Get wallet balance. `routes/wallet.ts:12` |
| PUT | `/rest/wallet/balance` | user | None | `appendUserId()` | Add wallet balance. `routes/wallet.ts:22` |
| GET | `/rest/deluxe-membership` | user | None | Inline `isCustomer()`/`isDeluxe()` | Deluxe status/pricing. `routes/deluxe.ts:60` |
| POST | `/rest/deluxe-membership` | user (customer) | None | `appendUserId()` + inline role check | Upgrade to deluxe; payment bypass possible. `routes/deluxe.ts:19` |
| GET | `/profile` | user (cookie auth) | None | Inline cookie `token` check (no Express middleware) | Profile page; eval() on username `#{...}` pattern. `routes/userProfile.ts:55-62` |
| POST | `/profile` | user (cookie auth) | None | Inline cookie `token` check — CSRF vulnerable | Update profile username. `routes/updateUserProfile.ts:16` |
| POST | `/profile/image/url` | user | None | Cookie/Bearer auth | Set profile image via URL — **PRIMARY SSRF VECTOR**. `routes/profileImageUrlUpload.ts:24` |
| POST | `/profile/image/file` | user | None | Cookie/Bearer auth | Upload profile image file. `routes/profileImageFileUpload.ts` |
| POST | `/file-upload` | anon | None | None | File upload; XXE via XML (`noent:true`). `routes/fileUpload.ts:83` |
| GET | `/rest/track-order/:id` | anon | `id` (order ID string) | None | Track order; NoSQL injection in `$where`. `routes/trackOrder.ts:18` |
| GET | `/rest/products/:id/reviews` | anon | `id` (product ID) | None | Product reviews; NoSQL injection in `$where`. `routes/showProductReviews.ts:36` |
| PUT | `/rest/products/:id/reviews` | anon | `id` | None | Create review (unauthenticated). `routes/createProductReviews.ts` |
| PATCH | `/rest/products/reviews` | user | None | `isAuthorized()` | Update review; `multi:true` allows mass update. `routes/updateProductReviews.ts:18` |
| GET | `/rest/memories` | anon | None | None | List photo memories. `server.ts:628` |
| POST | `/rest/memories` | user | None | `appendUserId()` | Upload photo memory. `server.ts:312` |
| GET | `/rest/admin/application-version` | anon | None | None | App version disclosure (public). `routes/appVersion.ts` |
| GET | `/rest/admin/application-configuration` | anon | None | None | **Full app config disclosure** (public despite admin path). `routes/appConfiguration.ts` |
| GET | `/rest/chatbot/status` | anon | None | None | Chatbot status. |
| POST | `/rest/chatbot/respond` | anon | None | None | Chatbot interaction. |
| GET | `/rest/country-mapping` | anon | None | None | Country mapping. |
| GET | `/rest/saveLoginIp` | anon | None | None | Save login IP. |
| GET | `/api/Feedbacks` | anon | None | None | List all feedback (public). |
| POST | `/api/Feedbacks` | anon | None | None | Submit feedback (stored XSS vector via `comment` field). |
| DELETE | `/api/Feedbacks/:id` | user | `id` | `isAuthorized()` | Delete feedback. |
| GET | `/api/Products` | anon | None | None | List all products. |
| PUT | `/api/Products/:id` | anon | `id` | None (auth commented out) | Update product — **UNAUTHENTICATED**. `server.ts:369` |
| GET | `/api/Quantitys` | anon | None | None | List product quantities. |
| GET | `/ftp` | anon | None | None | FTP directory listing (serve-index). |
| GET | `/ftp/:file` | anon | `file` | None | FTP file download; path traversal potential. `routes/fileServer.ts:33` |
| GET | `/encryptionkeys` | anon | None | None | **Encryption keys directory** (exposes JWT public key). |
| GET | `/encryptionkeys/:file` | anon | `file` | None | Serve encryption key file; path traversal. `routes/keyServer.ts:14` |
| GET | `/support/logs` | anon | None | None | Access log directory listing. |
| GET | `/support/logs/:file` | anon | `file` | None | Serve log file. `routes/logfileServer.ts:14` |
| GET | `/metrics` | anon | None | None | Prometheus metrics (unauthenticated). |
| GET | `/redirect` | anon | None | None | Open redirect; allowlist uses `.includes()` — bypassable. `routes/redirect.ts:13` |
| GET | `/api/Deliverys` | anon | None | None | List delivery methods. |
| GET | `/api/SecurityQuestions` | anon | None | None | List security questions. |
| GET | `/rest/2fa/status` | user | None | `isAuthorized()` | Check 2FA enrollment. |
| POST | `/rest/2fa/verify` | anon | None | Rate-limited | TOTP verification. |

---

## 5. Potential Input Vectors for Vulnerability Analysis

**Network Surface Focus:** Only inputs accessible via the deployed web application's HTTP interface.

### URL Parameters (Query String)
- `GET /rest/products/search?q=` — `routes/search.ts:21` — SQL injection sink at line 23; truncated to 200 chars but not escaped
- `GET /redirect?to=` — `routes/redirect.ts:13` — open redirect; validated via `.includes()` (bypassable)
- `GET /rest/user/security-question?email=` — `routes/securityQuestion.ts` — returns security question for email
- `GET /rest/track-order/:id` — URL path param `id` — NoSQL injection, `routes/trackOrder.ts:18`
- `GET /rest/products/:id/reviews` — URL path param `id` — NoSQL injection, `routes/showProductReviews.ts:36`
- `GET /ftp/:file` — URL path param `file` — path traversal potential, `routes/fileServer.ts:33`
- `GET /encryptionkeys/:file` — URL path param `file` — path traversal, `routes/keyServer.ts:14`
- `GET /support/logs/:file` — URL path param `file` — path traversal, `routes/logfileServer.ts:14`
- `GET /rest/basket/:id` — URL path param `id` (basket ID) — IDOR, `routes/basket.ts:19`
- `GET /api/Users/:id` — URL path param `id` (user ID) — IDOR, `server.ts:364`
- `PUT /api/Products/:id` — URL path param `id` — unauthenticated product update, `server.ts:369`

### POST Body Fields (JSON/Form)

**Authentication:**
- `POST /rest/user/login` body: `email` (SQL injection, `routes/login.ts:34`), `password` (MD5-hashed before use)
- `POST /api/Users` body: `email`, `password`, `passwordRepeat`, **`role`** (mass assignment — accepts `admin`), `username`, `deluxeToken`, `profileImage` — `models/user.ts`, `server.ts:407`

**Basket / Orders:**
- `POST /api/BasketItems` body: `ProductId`, `BasketId` (IDOR via HTTP param pollution — `routes/basketItems.ts:37`), `quantity`
- `PUT /api/BasketItems/:id` body: `BasketId`, `quantity` — no ownership check — `routes/basketItems.ts:65`
- `POST /b2b/v2/orders` body: **`orderLinesData`** (RCE/SSTI — `routes/b2bOrder.ts:19-23`), `cid` (reflected in response)
- `POST /rest/basket/:id/checkout` body: `couponData`, `orderDetails`

**Profile / Image:**
- `POST /profile` form body: `username` — stored in DB, later used in eval (`routes/userProfile.ts:62`) and Pug SSTI (`routes/userProfile.ts:87`)
- `POST /profile/image/url` body: **`imageUrl`** — SSRF vector — `routes/profileImageUrlUpload.ts:24`

**Data / Privacy:**
- `POST /rest/data-erase` body: **`layout`** — LFI via `path.resolve(req.body.layout)` used in `res.render()` — `routes/dataErasure.ts:69`
- `POST /rest/user/data-export` body: `format` (export format selector)
- `PATCH /rest/products/reviews` body: `id` (review ID — mass update when `multi:true`), `message` — `routes/updateProductReviews.ts:18`
- `PUT /rest/products/:id/reviews` body: `author`, `message` — unauthenticated stored content, `routes/createProductReviews.ts`

**Payments:**
- `POST /api/Cards` body: `fullName`, `cardNum`, `expMonth`, `expYear`, `UserId` (injected by middleware — but if middleware bypassed, attacker-controlled)
- `PUT /rest/wallet/balance` body: `balance`, `UserId` (from JWT via appendUserId), `paymentId`
- `POST /rest/deluxe-membership` body: `paymentMode` — if not `wallet` or `card`, skips payment (freeDeluxe bypass)

**File Upload:**
- `POST /file-upload` multipart: file content — XML triggers XXE (`routes/fileUpload.ts:83`), YAML triggers YAML bomb/deserialization (`routes/fileUpload.ts:117`)

**Feedback / Complaints:**
- `POST /api/Feedbacks` body: `comment` (stored XSS — rendered in admin panel via `bypassSecurityTrustHtml`), `rating`, `UserId`, `captchaId`, `captcha`
- `POST /api/Complaints` body: `message`, `file` (file upload field)

### HTTP Headers
- `Authorization: Bearer <token>` — JWT token accepted on all authenticated routes; forging via hardcoded private key enables role escalation
- `Cookie: token=<jwt>` — alternative to Authorization header; required for `/profile` and `/profile/image/url` endpoints
- `X-Forwarded-For` — used as key for rate limiter on `/rest/user/reset-password` and 2FA endpoints; trivially spoofable to bypass rate limits

### Cookie Values
- `token` — JWT session cookie; no HttpOnly/Secure/SameSite flags; used for profile and image upload endpoints; manipulable via XSS

---

## 6. Network & Interaction Map

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|---|---|---|---|---|---|
| User Browser | Identity | Internet | Browser/Angular 20 | Tokens | Attacker-controlled client; Angular SPA entry point |
| JuiceShop-Express | Service | App | Node.js/Express 4.22.1 / TypeScript | PII, Tokens, Payments | Main application backend; serves SPA + REST API + static files on :3000 |
| SQLite-DB | DataStore | Data | SQLite (via Sequelize 6.37.3) | PII, Tokens, Payments | Ephemeral; recreated on restart; stores users (MD5 passwords), cards, baskets, orders, addresses |
| MarsDB-InMemory | DataStore | Data | MarsDB (MongoDB-compatible, in-memory) | Public | Stores product reviews and order data; NoSQL injection surface |
| JWT-KeyStore | ExternAsset | App | RSA 1024-bit keypair (hardcoded) | Secrets | Private key hardcoded in `lib/insecurity.ts:23`; public key in `encryptionkeys/jwt.pub` (public) |
| FTP-Directory | ExternAsset | App | serve-index (static) | Public | `/ftp` — publicly browsable directory of downloadable files |
| EncryptionKeys-Directory | ExternAsset | App | serve-index (static) | Secrets | `/encryptionkeys` — publicly exposes JWT public key and premium key |
| AccessLogs-Directory | ExternAsset | App | serve-index (static) | PII | `/support/logs` — publicly browsable Morgan access logs; may contain PII in URLs |
| PrometheusMetrics | ExternAsset | App | prom-client | Public | `/metrics` — unauthenticated; exposes request counts, latency, challenge completion stats |
| SocketIO-Server | Service | App | Socket.IO 4.8.1 | Public | WebSocket events for challenge verification; co-hosted on port 3000 |

### 6.2 Entity Metadata

| Title | Metadata Key: Value |
|---|---|
| JuiceShop-Express | Hosts: `http://juice-shop:3000`; Endpoints: `/rest/*`, `/api/*`, `/b2b/v2/*`, `/profile`, `/file-upload`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/metrics`, `/redirect`; Auth: JWT Bearer + Cookie; Dependencies: SQLite-DB, MarsDB-InMemory, JWT-KeyStore |
| SQLite-DB | Engine: `SQLite` (Sequelize 6.37.3); Exposure: Internal only; Consumers: `JuiceShop-Express`; Init: `sequelize.sync({ force: true })` — ephemeral; Raw query at `routes/login.ts:34`, `routes/search.ts:23` |
| MarsDB-InMemory | Engine: MarsDB (MongoDB-compatible); Exposure: Internal only; Consumers: `JuiceShop-Express`; Collections: `reviewsCollection`, `ordersCollection`; NoSQL injection at `routes/showProductReviews.ts:36`, `routes/trackOrder.ts:18`, `routes/updateProductReviews.ts:18` |
| JWT-KeyStore | Algorithm: RS256; Private Key: Hardcoded string in `lib/insecurity.ts:23` (1024-bit RSA); Public Key: `encryptionkeys/jwt.pub` (publicly accessible via HTTP); Token Lifetime: 6 hours; Library: `jsonwebtoken@0.4.0` (CRITICAL: outdated) |
| FTP-Directory | Path: `ftp/` on filesystem; URL: `/ftp`; Auth: None; File types: `.md`, `.pdf`, `.kdbx`; Path traversal checked by extension only in `routes/fileServer.ts:33` |
| EncryptionKeys-Directory | Path: `encryptionkeys/` on filesystem; URL: `/encryptionkeys`; Auth: None; Contains: `jwt.pub` (JWT public key), `premium.key` (premium feature key) |
| PrometheusMetrics | URL: `/metrics`; Auth: None; Data: HTTP request counts, response times, challenge completion stats; Route: `routes/metrics.ts` |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|---|---|---|---|---|
| User Browser → JuiceShop-Express | HTTP | `:3000 /rest/user/login` | None | Tokens, PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 POST /api/Users` | None | PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /rest/products/search` | None | Public |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /rest/basket/:id` | auth:user | PII, Payments |
| User Browser → JuiceShop-Express | HTTP | `:3000 POST /api/BasketItems` | auth:user, ownership:basket (bypassable) | Payments |
| User Browser → JuiceShop-Express | HTTP | `:3000 POST /b2b/v2/orders` | auth:user | Payments |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET/POST /profile` | auth:cookie (inline, no middleware) | PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 POST /profile/image/url` | auth:cookie+bearer | PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 POST /file-upload` | None | Public |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /ftp/:file` | None | Public |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /encryptionkeys/:file` | None | Secrets |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /support/logs/:file` | None | PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /metrics` | None | Public |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /api/Users` | auth:user | PII |
| User Browser → JuiceShop-Express | HTTP | `:3000 GET /rest/order-history/orders` | auth:accounting | Payments, PII |
| JuiceShop-Express → SQLite-DB | In-process | Sequelize ORM | None (same process) | PII, Tokens, Payments |
| JuiceShop-Express → MarsDB-InMemory | In-process | MarsDB API | None (same process) | Public |
| JuiceShop-Express → External-HTTP | HTTP/HTTPS | Variable (fetch) | None (SSRF!) | Variable |
| JuiceShop-Express → JWT-KeyStore | File read | Filesystem | None | Secrets |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|---|---|---|
| auth:user | Auth | Requires a valid JWT in `Authorization: Bearer` header or `token` cookie, verified against RSA public key via `express-jwt`. Implemented by `security.isAuthorized()` in `lib/insecurity.ts:54`. |
| auth:cookie | Auth | Requires a valid JWT in the `token` cookie specifically. Used by `POST /profile` and `GET /profile` via inline check `security.authenticatedUsers.get(req.cookies.token)`. Not an Express middleware guard. |
| auth:accounting | Authorization | Requires `auth:user` PLUS JWT claim `data.role === 'accounting'`. Implemented by `security.isAccounting()` in `lib/insecurity.ts:156`. Returns HTTP 403 on failure. |
| auth:deluxe | Authorization | Requires `data.role === 'deluxe'` AND valid HMAC `deluxeToken` matching `HMAC-SHA256(email + "deluxe")`. Implemented inline via `security.isDeluxe(req)` in `lib/insecurity.ts:167`. NOT Express middleware. |
| auth:customer | Authorization | Requires `data.role === 'customer'` in JWT. Implemented inline via `security.isCustomer(req)` in `lib/insecurity.ts:172`. NOT Express middleware. |
| ownership:basket | ObjectOwnership | Checks that `user.bid` (from JWT) matches the basket `id` in the URL. Implemented in `routes/basket.ts:22` ONLY as challenge detection — **does NOT block unauthorized access**. IDOR present. |
| ownership:basketitem | ObjectOwnership | Checks `BasketId[0]` (first parsed value) matches `user.bid`. Bypassable via duplicate JSON key HTTP parameter pollution — `routes/basketItems.ts:37`. |
| ownership:card | ObjectOwnership | Checks `WHERE { id: req.params.id, UserId: req.body.UserId }` in Sequelize query. Relies on `appendUserId()` correctly setting `UserId` from JWT — `routes/payment.ts:41`. |
| appendUserId | Auth | Middleware that extracts user ID from JWT token map and injects into `req.body.UserId`. Provides user identity binding. If JWT forged, UserId is attacker-controlled — `lib/insecurity.ts:177`. |
| denyAll | Auth | Blocks all requests using a random HMAC secret. Permanently disabled routes. `lib/insecurity.ts:55`. |
| ratelimit:xff | RateLimit | Rate limiting using `X-Forwarded-For` header as client identifier. Applied to password reset and 2FA endpoints. Trivially bypassable by spoofing the `X-Forwarded-For` header. |
| cors:open | Protocol | CORS configured to `Access-Control-Allow-Origin: *` — accepts requests from any origin. No credential isolation. Confirmed in response headers. |
| ip:accounting | Network | IP filter `123.456.789` applied to `/api/Quantitys/:id` alongside `isAccounting()`. This is an intentionally invalid IP — the endpoint is unreachable via normal means. `server.ts:430`. |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| anon | 0 | Global | No authentication required; open endpoints accessible without any token |
| customer | 1 | Global | Default role assigned on registration (`defaultValue: 'customer'`, `models/user.ts:82`); JWT claim `data.role === 'customer'` |
| deluxe | 2 | Global | Upgraded from customer via `POST /rest/deluxe-membership`; JWT claim `data.role === 'deluxe'` + HMAC `deluxeToken` validated inline by `security.isDeluxe()` at `lib/insecurity.ts:167` |
| accounting | 3 | Global | Assigned via DB seeding or JWT forgery; JWT claim `data.role === 'accounting'`; validated by `security.isAccounting()` middleware at `lib/insecurity.ts:156` |
| admin | 5 | Global | Assigned at registration via mass assignment (`role: "admin"` in POST body) or via JWT forgery; JWT claim `data.role === 'admin'`; no dedicated admin middleware found — admin endpoints rely on `isAuthorized()` only |

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
anon → customer → deluxe → accounting → admin

Special Notes:
- customer → deluxe: self-service upgrade via POST /rest/deluxe-membership
- anon → admin: direct via POST /api/Users mass assignment (role:"admin" in body) — CONFIRMED LIVE
- any → admin: JWT forgery via hardcoded private key in lib/insecurity.ts:23
- accounting || deluxe: parallel isolation (both > customer, but isolated from each other's permissions)

admin has NO dedicated middleware guard — admin endpoints use isAuthorized() only.
No server-side validation that the JWT role claim corresponds to a DB record.
```

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|---|---|---|---|
| anon | `/` (Angular SPA) | `/`, `/rest/products/search`, `/api/Feedbacks`, `/rest/track-order/:id`, `/ftp/*`, `/encryptionkeys/*`, `/support/logs/*`, `/metrics`, `/rest/admin/application-*` | None |
| customer | `/` (post-login) | All anon routes + `/rest/basket/:id`, `/api/BasketItems`, `/b2b/v2/orders`, `/profile`, `/api/Cards`, `/api/Addresss`, `/rest/wallet/*`, `/rest/order-history`, `/rest/memories`, `/rest/user/authentication-details` | JWT Bearer + Cookie |
| deluxe | Same as customer | All customer routes + quantity limit bypass on basket items; discounted prices on orders | JWT Bearer (with `deluxeToken` HMAC claim) |
| accounting | Same as customer | All customer routes + `/rest/order-history/orders`, `/rest/order-history/:id/delivery-status` | JWT Bearer (with `role: accounting` claim) |
| admin | Same as customer | All customer routes + `/api/Users` (GET all, no extra check), `/api/Products` (POST), `/api/Feedbacks/:id` (DELETE) — no exclusive admin routes found in code | JWT Bearer (with `role: admin` claim; no dedicated admin middleware) |

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|---|---|---|---|
| anon | None | No token required | N/A |
| customer | `isAuthorized()` (JWT signature validation) | `security.isCustomer(req)` inline for deluxe upgrade gate | JWT claims + SQLite `Users.role` |
| deluxe | `isAuthorized()` + inline `isDeluxe(req)` | `data.role === 'deluxe'` AND `data.deluxeToken === HMAC(email + 'deluxe')` | JWT claims + `Users.deluxeToken` field |
| accounting | `isAccounting()` middleware | `data.role === 'accounting'` | JWT claims + SQLite `Users.role` |
| admin | `isAuthorized()` only | `data.role === 'admin'` (implied by model-level `isIn` validator) | JWT claims + SQLite `Users.role` |

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity |
|---|---|---|---|---|
| **High** | `GET /rest/basket/:id` | `id` (basket ID) | Payments, PII | Any authenticated user can read any other user's basket; ownership check only logs the violation — CONFIRMED LIVE (admin token retrieved basket 2 owned by user 2) |
| **High** | `GET /api/Users/:id` | `id` (user ID) | PII | Any authenticated user can fetch any user record including email, role, profileImage, lastLoginIp |
| **High** | `POST /api/BasketItems` (HTTP param pollution) | `BasketId` (second occurrence) | Payments | Duplicate-key bypass: first BasketId passes ownership check, second BasketId (victim's) is used for insertion |
| **High** | `PUT /api/BasketItems/:id` | `id` (BasketItem record ID) | Payments | No ownership check on the BasketItem record ID — any user can update any basket item quantity |
| **Medium** | `GET /api/Users` | None | PII | Lists ALL users with emails, roles — no admin restriction, any authenticated user |
| **Medium** | `POST /rest/basket/:id/checkout` | `id` (basket ID) | Payments | If basket IDOR allows reading, checkout may allow placing orders against another user's basket |
| **Low** | `GET /rest/order-history` | None | Payments | Only returns own orders (inline auth check) but error handling leaks IP address on failure |

### 8.2 Vertical Privilege Escalation Candidates

| Target Role | Endpoint Pattern | Functionality | Risk Level |
|---|---|---|---|
| admin | `POST /api/Users` with `{"role":"admin"}` | **Direct admin account creation** — mass assignment CONFIRMED LIVE | **CRITICAL** |
| admin | JWT forgery via `lib/insecurity.ts:23` hardcoded private key | Forge any JWT with `role: "admin"` | **CRITICAL** |
| accounting | JWT forgery via hardcoded private key | Forge JWT with `role: "accounting"` to access order management | High |
| accounting | `GET /rest/order-history/orders` | Access all user orders | High |
| accounting | `PUT /rest/order-history/:id/delivery-status` | Modify order delivery status | High |
| deluxe | `POST /rest/deluxe-membership` with `paymentMode` bypass | Free deluxe upgrade (skip payment) | Medium |
| any | `PUT /api/Products/:id` (unauthenticated) | Modify product data without authentication | Medium |

### 8.3 Context-Based Authorization Candidates

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|---|---|---|---|
| Basket checkout | `POST /rest/basket/:id/checkout` | User must own basket | IDOR bypass from basket access — checkout another user's basket |
| Deluxe upgrade | `POST /rest/deluxe-membership` | `paymentMode` should be `wallet` or `card` | Send alternative `paymentMode` value to skip payment entirely (`freeDeluxeChallenge`) |
| Profile image set | `POST /profile/image/url` | URL should point to valid image | No validation — full SSRF to any URL/protocol |
| Data erasure | `POST /rest/data-erase` | `layout` param should be a valid template name | LFI — `path.resolve(req.body.layout)` — include arbitrary filesystem paths |
| BasketItem add | `POST /api/BasketItems` | `BasketId` must match user's basket | HTTP parameter pollution — send two `BasketId` values |
| Password change | `GET /rest/user/change-password` | Should require current password | No current password check when `Authorization: Bearer <token>` present |

---

## 9. Injection Sources

**Network Surface Focus:** All sources reachable via HTTP requests to `http://juice-shop:3000`. Local-only scripts and build tools excluded.

### SQL Injection Sources

**Source 1 — Login Authentication Bypass (CRITICAL)**
- **File:** `routes/login.ts`
- **Line:** 34
- **HTTP Method/Path:** `POST /rest/user/login`
- **Auth Required:** None
- **Input:** `req.body.email` (POST JSON body field)
- **Sink:** `models.sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL\`, { model: UserModel, plain: true })`
- **Data Flow:** `req.body.email` → zero validation/sanitization → raw string interpolation → `sequelize.query()` raw SQL
- **Exploit Payload:** `' OR 1=1--` in email field bypasses authentication entirely; `bender@juice-sh.op'--` logs in as specific user

**Source 2 — Product Search Data Exfiltration**
- **File:** `routes/search.ts`
- **Line:** 23
- **HTTP Method/Path:** `GET /rest/products/search?q=<payload>`
- **Auth Required:** None
- **Input:** `req.query.q` (URL query parameter)
- **Validation:** Truncated to 200 characters (line 22) — NOT a security control
- **Sink:** `models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name\`)`
- **Data Flow:** `req.query.q` → 200-char truncation only → raw string interpolation → `sequelize.query()` raw SQL
- **Exploit Payload:** `%' UNION SELECT id, email, password, '4', '5', '6', '7' FROM Users--` (UNION-based data exfiltration)

### NoSQL Injection Sources

**Source 3 — Product Reviews NoSQL Injection**
- **File:** `routes/showProductReviews.ts`
- **Line:** 36
- **HTTP Method/Path:** `GET /rest/products/:id/reviews`
- **Auth Required:** None
- **Input:** `req.params.id` (URL path parameter)
- **Sink:** `db.reviewsCollection.find({ $where: 'this.product == ' + id })`
- **Data Flow:** `req.params.id` → direct string concatenation → MongoDB `$where` JavaScript evaluation

**Source 4 — Order Tracking NoSQL Injection**
- **File:** `routes/trackOrder.ts`
- **Line:** 18
- **HTTP Method/Path:** `GET /rest/track-order/:id`
- **Auth Required:** None
- **Input:** `req.params.id` (URL path parameter)
- **Sink:** `db.ordersCollection.find({ $where: \`this.orderId === '${id}'\` })`
- **Data Flow:** `req.params.id` → string interpolation into template literal → MongoDB `$where` JavaScript evaluation

**Source 5 — Product Reviews Mass Update**
- **File:** `routes/updateProductReviews.ts`
- **Lines:** 18–20
- **HTTP Method/Path:** `PATCH /rest/products/reviews`
- **Auth Required:** Yes (`isAuthorized()`)
- **Input:** `req.body.id` (POST JSON body)
- **Sink:** `db.reviewsCollection.update({ _id: req.body.id }, ..., { multi: true })` — `multi: true` means if `_id` matches multiple documents, all are updated

### SSTI / Code Execution Sources

**Source 6 — B2B Order SSTI/RCE (CRITICAL)**
- **File:** `routes/b2bOrder.ts`
- **Lines:** 19–23
- **HTTP Method/Path:** `POST /b2b/v2/orders`
- **Auth Required:** Yes (`isAuthorized()`)
- **Input:** `req.body.orderLinesData` (POST JSON body)
- **Sink:**
  ```javascript
  const orderLinesData = body.orderLinesData || ''
  const sandbox = { safeEval, orderLinesData }
  vm.createContext(sandbox)
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
  ```
- **Data Flow:** `body.orderLinesData` → placed in vm sandbox as `orderLinesData` → passed to `safeEval()` (notevil) inside `vm.runInContext()`
- **Attack Path 1 (DoS):** Infinite loop payload causes "Infinite loop detected" error from notevil
- **Attack Path 2 (Timeout):** CPU-intensive expression triggers the 2000ms timeout
- **Payload Format:** String expression, e.g., `"while(true){}"` or arithmetic expression `"1+1"`

**Source 7 — User Profile eval() RCE (CRITICAL)**
- **File:** `routes/userProfile.ts`
- **Lines:** 55–62
- **HTTP Method/Path:** `GET /profile` (triggered on profile page load)
- **Auth Required:** Yes (cookie `token`)
- **Input:** `user.username` — stored in SQLite, set via `POST /profile` form or `PUT /api/Users/:id`
- **Trigger Pattern:** Username matching `/#{(.*)}/` regex
- **Sink:** `username = eval(code)` where `code = username.substring(2, username.length - 1)` (content between `#{` and `}`)
- **Data Flow:** Username set via profile update → stored in DB → on profile load, username matches regex → `eval()` executes the content
- **Exploit:** Set username to `#{process.mainModule.require('child_process').execSync('id').toString()}` → executes OS command server-side

**Source 8 — Pug SSTI via Username (follows eval)**
- **File:** `routes/userProfile.ts`
- **Lines:** 74, 87–98
- **HTTP Method/Path:** `GET /profile`
- **Auth Required:** Yes (cookie `token`)
- **Input:** `user.username` (from DB, same as Source 7)
- **Sink:** `pug.compile(template)` where `template` has username substituted at line 74 via `template.replace(/_username_/g, username)`
- **Data Flow:** Username (post-eval if `#{...}` present, else raw) → substituted into Pug template string → `pug.compile(template)` executes template
- **Note:** If eval() returns a string containing Pug template directives (e.g., `- var x = process.mainModule`), SSTI occurs via Pug

**Source 9 — Video Subtitle Pug SSTI**
- **File:** `routes/videoHandler.ts`
- **Line:** 69
- **HTTP Method/Path:** Video/promotion endpoint
- **Input:** Video subtitle file content (configuration-driven)
- **Sink:** `pug.compile(template)` with subtitle injection

### LFI / Path Traversal Sources

**Source 10 — Data Erasure LFI (CRITICAL)**
- **File:** `routes/dataErasure.ts`
- **Lines:** 69–72
- **HTTP Method/Path:** `POST /rest/data-erase`
- **Auth Required:** Yes (token)
- **Input:** `req.body.layout` (POST JSON/form body)
- **Sink:** `path.resolve(req.body.layout)` used as layout argument to `res.render()` — reads arbitrary filesystem paths as template
- **Data Flow:** `req.body.layout` → `path.resolve()` → `res.render(view, { layout: resolvedPath })` — includes arbitrary files as Express views

**Source 11 — FTP File Server Path Traversal**
- **File:** `routes/fileServer.ts`
- **Line:** 33
- **HTTP Method/Path:** `GET /ftp/:file`
- **Auth Required:** None
- **Input:** `req.params.file` (URL path parameter)
- **Validation:** Extension check only (allows `.md`, `.pdf`, `.kdbx`); only forward slash checked
- **Sink:** `res.sendFile(path.resolve('ftp/', file))`
- **Attack:** Null byte injection (`file.md%2500.js`) or encoded traversal sequences to bypass extension check

**Source 12 — Log File Server Path Traversal**
- **File:** `routes/logfileServer.ts`
- **Line:** 14
- **HTTP Method/Path:** `GET /support/logs/:file`
- **Auth Required:** None
- **Input:** `req.params.file` (URL path parameter)
- **Validation:** Only checks for forward slash character
- **Sink:** `res.sendFile(path.resolve('logs/', file))`

**Source 13 — Encryption Key Server Path Traversal**
- **File:** `routes/keyServer.ts`
- **Line:** 14
- **HTTP Method/Path:** `GET /encryptionkeys/:file`
- **Auth Required:** None
- **Input:** `req.params.file` (URL path parameter)
- **Validation:** Only checks for forward slash character
- **Sink:** `res.sendFile(path.resolve('encryptionkeys/', file))`

### SSRF Sources

**Source 14 — Profile Image URL SSRF (CRITICAL)**
- **File:** `routes/profileImageUrlUpload.ts`
- **Line:** 24
- **HTTP Method/Path:** `POST /profile/image/url`
- **Auth Required:** Yes (cookie/Bearer)
- **Input:** `req.body.imageUrl` (POST JSON body)
- **Validation:** NONE — only challenge-specific pattern matching
- **Sink:** `const response = await fetch(url)` where `url = req.body.imageUrl`
- **Data Flow:** `body.imageUrl` → direct to `fetch()` — any URL, any scheme
- **Impact:** Cloud metadata endpoint access (`http://169.254.169.254/`), internal network scanning, SSRF to internal services

### Deserialization / XML / YAML Sources

**Source 15 — XML File Upload XXE**
- **File:** `routes/fileUpload.ts`
- **Line:** 83
- **HTTP Method/Path:** `POST /file-upload`
- **Auth Required:** None
- **Input:** Multipart file upload (XML file)
- **Sink:** `vm.runInContext('libxml.parseXml(data, { noent: true })', sandbox)` — `noent: true` enables entity expansion
- **Impact:** XML External Entity injection — can read local files or trigger SSRF

**Source 16 — YAML File Upload Bomb/Deserialization**
- **File:** `routes/fileUpload.ts`
- **Line:** 117
- **HTTP Method/Path:** `POST /file-upload`
- **Auth Required:** None
- **Input:** Multipart file upload (YAML file)
- **Sink:** `vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)` — `js-yaml@4.1.0` `load()` does not execute code but can cause DoS via YAML bomb

