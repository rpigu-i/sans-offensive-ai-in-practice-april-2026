# Penetration Test Scope & Boundaries

**Primary Directive:** This analysis is strictly limited to the **network-accessible attack surface** of the OWASP Juice Shop application. All findings have been verified against the scope criteria below.

### In-Scope: Network-Reachable Components
A component is considered **in-scope** if its execution can be initiated, directly or indirectly, by a network request that the deployed application server is capable of receiving. This includes:
- Publicly exposed web pages and API endpoints (89+ explicit REST endpoints, 28 auto-generated CRUD endpoints)
- Endpoints requiring authentication via JWT tokens obtained through the application's login mechanism
- Exposed developer utilities and debug surfaces (Swagger UI at `/api-docs`, Prometheus metrics at `/metrics`)
- WebSocket events handled by Socket.IO on the main HTTP server
- Static file serving routes including directory listing endpoints (`/ftp`, `/support/logs`, `/encryptionkeys`)

### Out-of-Scope: Locally Executable Only
The following components are **out-of-scope** as they cannot be invoked through the running application's network interface:
- **CI/CD Pipelines:** `.github/workflows/ci.yml`, `zap_scan.yml`, `codeql-analysis.yml` — GitHub Actions workflows
- **Build Tools:** Grunt tasks (`Gruntfile.js`), TypeScript compilation (`tsc`), Angular CLI builds
- **Test Suites:** `test/api/`, `test/server/`, `test/cypress/` — Mocha, Jest, Cypress test runners
- **Database Migrations:** `data/datacreator.ts` — runs at application startup only (not network-triggered after init)
- **CLI Utilities:** npm scripts (`package.json` scripts section), SBOM generation (`cyclonedx-npm`)
- **Documentation:** `SECURITY.md`, `SOLUTIONS.md`, `REFERENCES.md` — static documentation files

---

## 1. Executive Summary

OWASP Juice Shop is a deliberately vulnerable monolithic web application built with an Express.js (Node.js) backend and Angular 20 frontend, serving as a security training platform. The application exposes **167+ network-accessible entry points** across REST APIs, auto-generated CRUD endpoints, WebSocket events, file serving routes, and an Angular SPA. The security posture is intentionally weak, featuring multiple classes of exploitable vulnerabilities including SQL injection, NoSQL injection, remote code execution via `eval()`, XML External Entity (XXE) attacks, and Server-Side Request Forgery (SSRF).

The most critical architectural security decisions center around the authentication subsystem: JWT tokens are signed with an RSA private key that is **hardcoded directly in source code** (`lib/insecurity.ts`), passwords are hashed with unsalted MD5, and the cookie parser uses a trivially guessable secret (`'kekse'`). The application deliberately disables the XSS filter (`helmet.xssFilter()`), configures CORS to accept all origins, and uses severely outdated security libraries including `jsonwebtoken@0.4.0` (current: v9.x) and `express-jwt@0.1.3` (deprecated). These decisions create a cascading trust failure where token forgery enables privilege escalation across all authenticated endpoints.

From an external attacker perspective, the highest-value attack surfaces are: (1) the login endpoint vulnerable to SQL injection for authentication bypass, (2) the product search endpoint for data exfiltration, (3) the profile image URL upload for SSRF against internal infrastructure, (4) the user profile endpoint for server-side code execution via `eval()`, and (5) multiple file serving endpoints with path traversal potential. The application also exposes sensitive operational data through publicly accessible Prometheus metrics, access logs, and encryption key directories without authentication.

## 2. Architecture & Technology Stack

- **Framework & Language:** The application is built on **Express.js 4.22.1** running on **Node.js 20-24** with **TypeScript ~5.3.3** (backend) and **~5.8.2** (frontend). Express is configured with a deep middleware stack of 19+ layers including compression, CORS, Helmet (partial), body parsers, cookie parser, JWT validation, rate limiting, and custom anti-cheat middleware. The security implications are significant: the middleware ordering places CORS before authentication, meaning cross-origin requests are accepted before any token validation occurs. The body parser accepts URL-encoded (`extended: true`), text, and JSON content types, expanding the attack surface for content-type confusion attacks. File uploads are handled by multer with a 200KB memory storage limit.

- **Architectural Pattern:** This is a **monolithic SPA+REST API** architecture where the Angular 20 frontend and Express.js backend are served from the same process on port 3000. The frontend is pre-built and served as static files from `frontend/dist/frontend/`. The backend uses **Sequelize v6.37.3** ORM with **SQLite** for relational data and **MarsDB** (MongoDB-compatible in-memory database) for document storage (product reviews, orders). The trust boundary between frontend and backend relies entirely on JWT tokens passed via `Authorization: Bearer` headers or cookies. A critical architectural decision is the use of **finale-rest** to auto-generate CRUD endpoints for 14 Sequelize models, creating 28 additional API endpoints with varying authorization controls. This auto-generation pattern means authorization must be bolted on after endpoint creation, increasing the risk of missed access controls.

- **Critical Security Components:** The core security module is `lib/insecurity.ts`, which centralizes JWT signing/verification, password hashing (MD5), HMAC operations, input sanitization, redirect allowlisting, and role-based access control functions. This single-file security architecture means a vulnerability in this module compromises the entire application's security posture. The application uses `helmet@4.6.0` for security headers but intentionally disables `xssFilter()`. Rate limiting via `express-rate-limit` is applied only to password reset and 2FA endpoints, leaving the login endpoint unprotected against brute force. The IP-based rate limiting uses `X-Forwarded-For` header as the key generator, which is trivially spoofable.

## 3. Authentication & Authorization Deep Dive

### Authentication Mechanisms

The application implements a custom JWT-based authentication system centered in `lib/insecurity.ts`. Tokens are signed using RS256 (RSA) with a **hardcoded private key** embedded directly in the source code (line 23). The public key is loaded from `encryptionkeys/jwt.pub`, which is also publicly accessible via the `/encryptionkeys/:file` route. Tokens expire after 6 hours with no refresh token mechanism. The JWT library used is `jsonwebtoken@0.4.0`, which is **severely outdated** (current version is 9.x) and contains known vulnerabilities including algorithm confusion attacks.

Password hashing uses **MD5 without salt** (`crypto.createHash('md5')` at `lib/insecurity.ts` line 43), making all passwords vulnerable to rainbow table attacks. The application ships with default credentials including `admin@juice-sh.op:admin123`. Security answers for password recovery are hashed using HMAC-SHA256, but the HMAC key (`'pa4qacea4VK9t9nGv7yZtwmj'`) is hardcoded in source code at `lib/insecurity.ts` line 44, allowing precomputation of security answer hashes.

**Exhaustive Authentication Endpoint List:**

| Method | Endpoint | Handler File | Auth Required | Notes |
|--------|----------|-------------|---------------|-------|
| POST | `/rest/user/login` | `routes/login.ts` | No | SQL injection vulnerable (line 34) |
| GET | `/rest/user/change-password` | `routes/changePassword.ts` | No | Token from `Authorization: Bearer=<token>` header |
| POST | `/rest/user/reset-password` | `routes/resetPassword.ts` | No | Rate-limited (100 req/5min), X-Forwarded-For spoofable |
| GET | `/rest/user/security-question` | `routes/securityQuestion.ts` | No | Returns security question for email |
| GET | `/rest/user/whoami` | `routes/currentUser.ts` | Yes | Returns current user info, potential password hash leak |
| GET | `/rest/user/authentication-details` | `routes/authenticatedUsers.ts` | Yes | Returns authenticated user details |
| POST | `/api/Users` | Auto-generated (finale-rest) | No | User registration |
| POST | `/rest/2fa/verify` | `routes/2fa.ts` | No | TOTP verification, rate-limited |
| GET | `/rest/2fa/status` | `routes/2fa.ts` | Yes | Check 2FA enrollment status |
| POST | `/rest/2fa/setup` | `routes/2fa.ts` | Yes | Enable 2FA with TOTP secret generation |
| POST | `/rest/2fa/disable` | `routes/2fa.ts` | Yes | Disable 2FA, rate-limited |

### Session Management & Token Security

Token cookies are set at `lib/insecurity.ts` (approximately line 195) with:
```typescript
res.cookie('token', token)
```

**Critical finding:** The token cookie is set **without HttpOnly, Secure, or SameSite flags**. This means:
- JavaScript can read the token (XSS → session hijack)
- Token is transmitted over HTTP in development (no Secure flag)
- No CSRF protection from SameSite attribute

The cookie parser at `server.ts` line 289 uses secret `'kekse'` (German for "cookies"), a trivially guessable value. Token extraction logic in `lib/utils.ts` lines 130-143 accepts tokens from both the `Authorization: Bearer <token>` header and `req.cookies.token`, creating dual authentication paths.

### Authorization Model & Bypass Scenarios

The application implements role-based access control with four roles: `customer` (default), `deluxe`, `accounting`, and `admin`. Authorization functions in `lib/insecurity.ts`:

- **`isAuthorized()`** (line 54): Uses `express-jwt` with the public key — validates JWT signature
- **`denyAll()`** (line 55): Uses a random secret to block all access — effectively disables endpoint
- **`isAccounting()`** (lines 156-165): Checks JWT claim `data.role === 'accounting'`
- **`isDeluxe()`** (lines 167-170): Validates deluxe membership via HMAC token derived from email
- **`appendUserId()`**: Extracts user ID from JWT and appends to request — trusts JWT claims without server-side validation

**Bypass scenarios:**
1. Since the JWT private key is hardcoded, an attacker can forge tokens with any role (admin, accounting)
2. The `appendUserId` middleware trusts JWT claims, enabling horizontal privilege escalation by modifying the `bid` (basket ID) claim
3. Multiple endpoints lack authorization entirely (e.g., `POST /profile`, `GET /rest/order-history`)
4. The commented-out `PUT /api/Products/:id` authorization (server.ts line 369) leaves product modification unprotected

### SSO/OAuth Flows

The Angular frontend includes an OAuth component (`frontend/src/app/oauth/oauth.component.ts`) with a route matcher for `#access_token=...` fragments. Google OAuth is configured with a client ID in `config/default.yml` line 59. The OAuth callback handles token extraction from URL fragments client-side. **No server-side `state` or `nonce` parameter validation was identified**, making the OAuth flow potentially vulnerable to CSRF attacks on the authorization callback.

## 4. Data Security & Storage

### Database Security

The application uses **SQLite** via Sequelize ORM (`models/index.ts`) with credentials `database/username/password` (all plaintext defaults). The database file `data/juiceshop.sqlite` is recreated on every startup with `sequelize.sync({ force: true })`, meaning all data is ephemeral. A secondary **MarsDB** (MongoDB-compatible in-memory) database handles product reviews and orders, stored via `data/mongodb.ts`.

**Critical SQL injection points** exist in two high-traffic endpoints:
1. **Login** (`routes/login.ts` line 34): `SELECT * FROM Users WHERE email = '${req.body.email}'` — authentication bypass
2. **Search** (`routes/search.ts` line 23): `SELECT * FROM Products WHERE name LIKE '%${criteria}%'` — data exfiltration, schema disclosure

**NoSQL injection** is present in three endpoints using MongoDB `$where` operator with string concatenation:
- `routes/showProductReviews.ts` line 36: `{ $where: 'this.product == ' + id }`
- `routes/trackOrder.ts` line 18: `{ $where: \`this.orderId === '${id}'\` }`
- `routes/updateProductReviews.ts` lines 18-20: `multi: true` flag allows mass updates

### Data Flow Security

**Payment data (credit cards)** is stored as unencrypted integers in the `Card` model (`models/card.ts` line 22). Card numbers are only masked on display (`routes/payment.ts` lines 28-33), not at the storage layer. The `dataExport` endpoint (`routes/dataExport.ts`) exports user PII including email, order history, reviews, and memory uploads in plaintext JSON. An email "anonymization" function replaces vowels with asterisks (line 22) but then exports the full email elsewhere (line 104).

**Sensitive data in JWT tokens**: The JWT payload includes user email, role, and `lastLoginIp`. The `lastLoginIp` field is rendered via `bypassSecurityTrustHtml` in the frontend (`frontend/src/app/last-login-ip/last-login-ip.component.ts` line 39), creating an XSS vector through JWT payload manipulation.

### Multi-tenant Data Isolation

There is no multi-tenancy implementation. All users share a single SQLite database. Horizontal privilege escalation is possible through multiple IDOR vulnerabilities:
- Basket access: `routes/basket.ts` allows accessing other users' baskets by changing the ID parameter
- Payment methods: `routes/payment.ts` accepts `UserId` from request body without server-side validation
- User profiles: `routes/updateUserProfile.ts` uses cookie token without verifying the target user matches

## 5. Attack Surface Analysis

### External Entry Points

The application exposes **167+ network-accessible entry points** categorized as follows:

**REST API Endpoints (89 explicit routes in `server.ts`):**

| Category | Count | Auth Required | Key Routes |
|----------|-------|---------------|------------|
| User/Auth | 11 | Mixed | `/rest/user/login`, `/rest/user/reset-password`, `/api/Users` |
| Products/Search | 8 | No | `/rest/products/search`, `/rest/products/:id/reviews` |
| Basket/Orders | 7 | Yes | `/rest/basket/:id`, `/rest/basket/:id/checkout` |
| File Upload | 4 | No | `/file-upload`, `/profile/image/file`, `/profile/image/url` |
| Admin | 2 | No (!) | `/rest/admin/application-version`, `/rest/admin/application-configuration` |
| 2FA | 4 | Mixed | `/rest/2fa/verify`, `/rest/2fa/setup`, `/rest/2fa/status`, `/rest/2fa/disable` |
| Web3/NFT | 5 | No | `/rest/web3/submitKey`, `/rest/web3/nftMintListen` |
| Chatbot | 2 | No | `/rest/chatbot/status`, `/rest/chatbot/respond` |
| Wallet | 2 | Yes | `/rest/wallet/balance` (GET/PUT) |
| Misc | 44 | Mixed | Redirect, memories, promotions, code snippets, etc. |

**Auto-Generated CRUD Endpoints (28 endpoints via finale-rest):**
Models: User, Product, Feedback, BasketItem, Challenge, Complaint, Recycle, SecurityQuestion, SecurityAnswer, Address, PrivacyRequest, Card, Quantity, Hint — each with `/api/<Model>` and `/api/<Model>/:id` patterns.

**Directory Listing Endpoints (4 paths, all unauthenticated):**
- `/ftp` — serves files from `ftp/` directory with `serve-index`
- `/support/logs` — serves access logs from `logs/` directory
- `/encryptionkeys` — serves encryption keys from `encryptionkeys/` directory
- `/.well-known` — serves well-known directory

**API Documentation:**
- `/api-docs` — Swagger UI serving `swagger.yml` (B2B v2 API docs), unauthenticated

**WebSocket Events (Socket.IO):**
- `verifyLocalXssChallenge`, `verifySvgInjectionChallenge`, `verifyCloseNotificationsChallenge` — challenge verification events
- `notification received` — client acknowledgment

### Internal Service Communication

The application is monolithic with no inter-service communication. The frontend communicates with the backend exclusively via HTTP REST calls and WebSocket events. The only trust boundary is between the client and server, mediated by JWT tokens. The auto-generated finale-rest endpoints trust Sequelize model hooks and middleware for authorization, creating implicit trust relationships between the route layer and ORM layer.

### Input Validation Patterns

Input validation is minimal and inconsistent across the codebase:
- **Search** (`routes/search.ts`): Input trimmed to 200 characters (line 22) but no sanitization before SQL interpolation
- **File uploads** (`routes/fileUpload.ts`): 200KB size limit via multer, file type checked by extension for ZIP/XML/YAML
- **Sanitization** (`lib/insecurity.ts`): `sanitizeHtml` library (v1.4.2, outdated) used for some inputs with allowlist bypasses
- **Null byte handling** (`lib/insecurity.ts` lines 46-52): Only URL-encoded null bytes (`%00`) are handled; actual null bytes pass through
- **File path validation**: `routes/fileServer.ts` checks file extensions (.md, .pdf, .kdbx); `routes/logfileServer.ts` and `routes/keyServer.ts` only check for forward slash character

### Background Processing

The application uses no background job queues. All processing is synchronous within the request-response cycle. The only asynchronous behavior is:
- Socket.IO event emission for challenge notifications (triggered by HTTP requests)
- Webhook notifications via `lib/webhook.ts` when challenges are solved (sends to `SOLUTIONS_WEBHOOK` env var)
- File downloads during startup for configuration customization (`lib/startup/customizeApplication.ts`)

## 6. Infrastructure & Operational Security

### Secrets Management

All secrets are hardcoded in source code with no external secret management:

| Secret | Location | Value |
|--------|----------|-------|
| RSA Private Key | `lib/insecurity.ts` line 23 | Full 1024-bit RSA key in source |
| HMAC Key | `lib/insecurity.ts` line 44 | `'pa4qacea4VK9t9nGv7yZtwmj'` |
| Cookie Secret | `server.ts` line 289 | `'kekse'` |
| Google OAuth Client ID | `config/default.yml` line 59 | Public in config |
| Default Admin Password | `data/static/users.yml` | `admin123` |

No environment variable-based secret management is used for core security functions. The `SOLUTIONS_WEBHOOK` environment variable is the only externally configurable secret.

### Configuration Security

The application uses YAML configuration files in the `config/` directory with `default.yml` as the primary configuration. Configuration includes `unsafe.yml` which contains intentionally insecure settings. There is **no HTTPS enforcement** — the default `baseUrl` is `http://localhost:3000`. No infrastructure-level security headers (HSTS, Cache-Control for sensitive responses) were found in Nginx, Kubernetes, or CDN configurations — the application is designed to run standalone.

The Dockerfile (`Dockerfile`) uses a multi-stage build with `gcr.io/distroless/nodejs24-debian13` base image, running as UID 65532 (non-root). This is the only deployment-hardening measure identified. The `docker-compose.test.yml` is for testing only.

### External Dependencies

Key external dependencies with security implications:
- `jsonwebtoken@0.4.0` — **CRITICAL**: Severely outdated, known vulnerabilities
- `express-jwt@0.1.3` — **HIGH**: Deprecated, unmaintained
- `sanitize-html@1.4.2` — **HIGH**: Outdated, potential XSS bypass
- `helmet@4.6.0` — **MEDIUM**: Outdated, missing newer security headers
- `finale-rest@1.1.1` — Auto-generates CRUD endpoints with security implications
- `socket.io@4.8.1` — WebSocket server
- `sequelize@6.37.3` — ORM (current version)
- `pug@3.0.3` — Template engine used in user profile rendering
- `libxmljs2@0.35.0` — XML parsing (used in XXE-vulnerable file upload)
- `js-yaml@4.1.0` — YAML parsing (used in YAML bomb-vulnerable file upload)
- `download@8.0.0` — HTTP file download (used in SSRF-vulnerable startup functions)

### Monitoring & Logging

- **Access Logging**: Morgan middleware logs HTTP requests in `combined` format to `logs/access.log.%DATE%` with daily rotation and 2-day retention
- **Application Logging**: Winston logger (`lib/logger.ts`) outputs to console at `info` level (or `error` in test mode)
- **Metrics**: Prometheus metrics exposed at `/metrics` endpoint **without authentication** — leaks application internals including request counts, response times, and custom challenge metrics
- **Log Exposure**: Access logs are publicly browsable at `/support/logs` via `serve-index` middleware
- **No sensitive data masking**: Logs do not mask PII, tokens, or sensitive parameters

## 7. Overall Codebase Indexing

The Juice Shop codebase follows a flat monolithic structure rooted in the repository directory. The backend TypeScript source files are organized into `routes/` (63 route handler files, one per endpoint or feature), `models/` (22 Sequelize model definitions), `lib/` (core utilities including the critical `insecurity.ts` security module, `utils.ts`, `logger.ts`, and a `startup/` subdirectory with 10 initialization modules), `data/` (database seeding via `datacreator.ts`, static data in YAML files, MongoDB initialization, and chatbot training data), and `views/` (Pug/Handlebars templates for server-rendered pages). The frontend is a complete Angular 20 application in `frontend/` with 74+ components organized by feature (e.g., `login/`, `search-result/`, `administration/`), services for API communication, guards for route protection, and interceptors for HTTP request modification. Configuration is managed through YAML files in `config/` with a schema validator (`config.schema.yml`). Encryption keys are stored in `encryptionkeys/` (tracked in git), FTP-served files in `ftp/`, user uploads in `uploads/`, and test suites in `test/` (API tests via Frisby/Mocha, server tests via Jest, E2E tests via Cypress). Build orchestration uses npm scripts with TypeScript compilation (`tsc`) for the backend and Angular CLI for the frontend. The codebase uses `vuln-code-snippet` comments to mark intentional vulnerabilities, which aids in identifying security-relevant code. The flat route structure (one file per endpoint) makes attack surface enumeration straightforward but also means security controls are distributed across 63+ files rather than centralized in middleware.

## 8. Critical File Paths

### Configuration
- `server.ts` — Main server file, middleware stack, route registration (761 lines)
- `app.ts` — Entry point bootstrap
- `config/default.yml` — Primary YAML configuration (23KB)
- `config/unsafe.yml` — Intentionally unsafe configuration
- `config.schema.yml` — Configuration validation schema
- `Dockerfile` — Multi-stage Docker build (distroless base)
- `docker-compose.test.yml` — Testing Docker Compose
- `.npmrc` — NPM configuration

### Authentication & Authorization
- `lib/insecurity.ts` — **CRITICAL**: JWT signing/verification, password hashing (MD5), HMAC, role checks, redirect allowlist, sanitization — the entire security architecture
- `routes/login.ts` — Login endpoint with SQL injection (line 34)
- `routes/changePassword.ts` — Password change handler
- `routes/resetPassword.ts` — Password reset with HMAC verification
- `routes/2fa.ts` — Two-factor authentication (TOTP) setup/verify/disable
- `routes/currentUser.ts` — Current user info, potential password hash leak
- `routes/authenticatedUsers.ts` — Authenticated user details
- `encryptionkeys/jwt.pub` — JWT public key (publicly accessible)
- `encryptionkeys/premium.key` — Premium feature key

### API & Routing
- `server.ts` (lines 355-591) — Route registration and authorization middleware
- `routes/search.ts` — Product search with SQL injection (line 23)
- `routes/basket.ts` — Basket access with IDOR vulnerability
- `routes/basketItems.ts` — Basket item management with auth bypass
- `routes/b2bOrder.ts` — B2B order with vm.runInContext code execution (line 23)
- `routes/redirect.ts` — Open redirect with allowlist bypass
- `routes/fileUpload.ts` — File upload handling (XXE, YAML bomb)
- `routes/profileImageUrlUpload.ts` — SSRF via URL-based image upload (line 24)
- `routes/profileImageFileUpload.ts` — File-based image upload
- `routes/userProfile.ts` — User profile with eval() RCE (line 62) and Pug SSTI (line 87)
- `routes/dataErasure.ts` — Data erasure with LFI via layout parameter (line 69)
- `routes/dataExport.ts` — Data export with PII leakage
- `routes/chatbot.ts` — Chatbot with training data download (SSRF via config)
- `routes/payment.ts` — Payment processing with IDOR
- `routes/order.ts` — Order placement
- `routes/trackOrder.ts` — Order tracking with NoSQL injection (line 18)
- `routes/showProductReviews.ts` — Product reviews with NoSQL injection (line 36)
- `routes/updateProductReviews.ts` — Review updates with multi-document NoSQL injection
- `routes/createProductReviews.ts` — Review creation
- `routes/likeProductReviews.ts` — Review likes
- `routes/videoHandler.ts` — Video/promotion handler with Pug SSTI
- `routes/fileServer.ts` — FTP file serving with path traversal potential (line 33)
- `routes/logfileServer.ts` — Log file serving (line 14)
- `routes/keyServer.ts` — Encryption key serving (line 14)
- `routes/quarantineServer.ts` — Quarantine file serving (line 14)
- `routes/web3Wallet.ts` — Web3 wallet endpoints
- `routes/nftMint.ts` — NFT minting endpoints
- `routes/checkKeys.ts` — Web3 key verification
- `routes/deluxe.ts` — Deluxe membership
- `routes/wallet.ts` — Wallet balance management
- `routes/memory.ts` — Photo memory upload/retrieval
- `routes/updateUserProfile.ts` — Profile update with CSRF detection
- `routes/captcha.ts` — CAPTCHA generation
- `routes/imageCaptcha.ts` — Image CAPTCHA generation
- `routes/countryMapping.ts` — Country data
- `routes/saveLoginIp.ts` — Login IP storage
- `routes/securityQuestion.ts` — Security question retrieval
- `routes/appVersion.ts` — Application version disclosure
- `routes/appConfiguration.ts` — Application configuration disclosure
- `routes/continueCode.ts` — Progress continue codes
- `routes/restoreProgress.ts` — Progress restoration
- `routes/orderHistory.ts` — Order history with accounting role check
- `routes/easterEgg.ts` — Hidden Easter egg page
- `routes/premiumReward.ts` — Premium reward page
- `routes/privacyPolicyProof.ts` — Privacy policy proof
- `routes/verify.ts` — Challenge verification middleware
- `swagger.yml` — OpenAPI 3.0 specification for B2B API
- `frontend/src/app/app.routing.ts` — Angular frontend route definitions

### Data Models & DB Interaction
- `models/index.ts` — Sequelize initialization (SQLite, force sync)
- `models/user.ts` — User model with MD5 password hashing (line 77)
- `models/product.ts` — Product model
- `models/basket.ts` — Shopping basket model
- `models/basketitem.ts` — Basket item model
- `models/feedback.ts` — Feedback model
- `models/card.ts` — Payment card model (unencrypted card numbers, line 22)
- `models/address.ts` — Address model (plaintext PII)
- `models/complaint.ts` — Complaint model
- `models/securityAnswer.ts` — Security answer model (HMAC-SHA256 hashing)
- `models/securityQuestion.ts` — Security question model
- `models/challenge.ts` — Challenge tracking model
- `models/privacyRequest.ts` — GDPR privacy request model
- `models/imageCaptcha.ts` — Image CAPTCHA model
- `models/memory.ts` — User memory model
- `models/wallet.ts` — Wallet model
- `models/delivery.ts` — Delivery method model
- `models/quantity.ts` — Product quantity model
- `models/recycle.ts` — Recycling model
- `data/datacreator.ts` — Database seeding with default credentials
- `data/static/users.yml` — Default user accounts and passwords
- `data/mongodb.ts` — MarsDB (MongoDB-compatible) initialization

### Dependency Manifests
- `package.json` — Root dependencies (284 lines) including vulnerable packages
- `frontend/package.json` — Frontend Angular dependencies

### Sensitive Data & Secrets Handling
- `lib/insecurity.ts` — All crypto functions, hardcoded keys
- `encryptionkeys/jwt.pub` — JWT public key
- `encryptionkeys/premium.key` — Premium feature key
- `ctf.key` — CTF mode key file
- `data/static/users.yml` — Default passwords and credentials

### Middleware & Input Validation
- `lib/insecurity.ts` — `sanitizeHtml`, `sanitizeSecure`, `cutOffPoisonNullByte`, `isRedirectAllowed`
- `routes/verify.ts` — Challenge verification and access control middleware
- `lib/antiCheat.ts` — Anti-cheat validation middleware
- `server.ts` (lines 181-289) — Middleware stack configuration (Helmet, CORS, rate limiting, body parsers)

### Logging & Monitoring
- `lib/logger.ts` — Winston logger configuration
- `server.ts` (lines 330-338) — Morgan access log configuration
- `routes/metrics.ts` — Prometheus metrics endpoint (unauthenticated)

### Infrastructure & Deployment
- `Dockerfile` — Multi-stage build with distroless base
- `docker-compose.test.yml` — Test environment Docker Compose
- `.github/workflows/ci.yml` — Main CI pipeline
- `.github/workflows/codeql-analysis.yml` — CodeQL security scanning
- `.github/workflows/zap_scan.yml` — OWASP ZAP scanning

### Frontend Security-Relevant Components
- `frontend/src/app/search-result/search-result.component.ts` — bypassSecurityTrustHtml (lines 132, 170)
- `frontend/src/app/search-result/search-result.component.html` — innerHTML binding (line 13)
- `frontend/src/app/product-details/product-details.component.html` — innerHTML binding (line 16)
- `frontend/src/app/administration/administration.component.ts` — bypassSecurityTrustHtml (lines 60, 78)
- `frontend/src/app/administration/administration.component.html` — innerHTML bindings (lines 26, 60, 105)
- `frontend/src/app/last-login-ip/last-login-ip.component.ts` — bypassSecurityTrustHtml (line 39)
- `frontend/src/app/last-login-ip/last-login-ip.component.html` — innerHTML binding (line 10)
- `frontend/src/app/data-export/data-export.component.ts` — document.write (line 71), bypassSecurityTrustHtml (line 57)
- `frontend/src/app/about/about.component.ts` — bypassSecurityTrustHtml (lines 119-121)
- `frontend/src/app/about/about.component.html` — innerHTML binding (line 51)
- `frontend/src/app/track-result/track-result.component.ts` — bypassSecurityTrustHtml (line 48)
- `frontend/src/app/feedback-details/feedback-details.component.html` — innerHTML binding (line 18)
- `frontend/src/app/score-board/score-board.component.ts` — bypassSecurityTrustHtml (line 86)
- `frontend/src/app/oauth/oauth.component.ts` — OAuth callback handler
- `frontend/src/app/Services/request.interceptor.ts` — HTTP request interceptor
- `frontend/src/hacking-instructor/index.ts` — innerHTML assignment (line 126)
- `frontend/src/environments/environment.ts` — Development environment config
- `frontend/src/environments/environment.prod.ts` — Production environment config

### API Schema Files
- `swagger.yml` — OpenAPI 3.0 specification (copied to `.shannon/deliverables/schemas/swagger-b2b-api.yml`)

## 9. XSS Sinks and Render Contexts

**Network Surface Focus:** All sinks listed below are on web application pages served by the Express.js server and rendered in user browsers via the Angular SPA. Local-only scripts, build tools, and non-network components have been excluded.

### HTML Body Context — `[innerHTML]` Bindings (Angular Templates)

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `frontend/src/app/search-result/search-result.component.html` | 13 | `<span id="searchValue" [innerHTML]="searchValue"></span>` | URL query parameter `q` via `bypassSecurityTrustHtml` | **Reflected XSS** — search query rendered unsanitized |
| 2 | `frontend/src/app/product-details/product-details.component.html` | 16 | `<div [innerHTML]="data.productData.description"></div>` | Product API response | **Stored XSS** — product descriptions from database |
| 3 | `frontend/src/app/data-export/data-export.component.html` | 29 | `<div class="captcha-image" [innerHTML]="captcha"></div>` | ImageCaptcha API via `bypassSecurityTrustHtml` | XSS via crafted captcha image data |
| 4 | `frontend/src/app/administration/administration.component.html` | 26 | `<mat-cell [innerHTML]="user.email"></mat-cell>` | User email from API via `bypassSecurityTrustHtml` | **Stored XSS** — admin panel renders all user emails |
| 5 | `frontend/src/app/administration/administration.component.html` | 60 | `<p [innerHTML]="feedback.comment"></p>` | Feedback comments via `bypassSecurityTrustHtml` | **Stored XSS** — feedback rendered in admin panel |
| 6 | `frontend/src/app/last-login-ip/last-login-ip.component.html` | 10 | `<dd [innerHTML]="lastLoginIp"></dd>` | JWT `lastLoginIp` claim via `bypassSecurityTrustHtml` | **Stored XSS** — IP field from JWT token |
| 7 | `frontend/src/app/feedback-details/feedback-details.component.html` | 18 | `<cite [innerHTML]="feedback"></cite>` | Feedback dialog data | **Stored XSS** — feedback detail popup |
| 8 | `frontend/src/app/about/about.component.html` | 51 | `<figure class="feedback" [innerHTML]="item?.args"></figure>` | Feedback args via `bypassSecurityTrustHtml` | **Stored XSS** — about page gallery |
| 9 | `frontend/src/app/score-board/components/challenges-unavailable-warning/challenges-unavailable-warning.component.html` | 11 | `<span [innerHTML]="'INFO_DISABLED_CHALLENGES' \| translate: ..."></span>` | Translation parameters | Low risk — depends on translation content |
| 10 | `frontend/src/app/nft-unlock/nft-unlock.component.html` | 38 | `<p [innerHTML]="'NFT_SBT_BOX_TEXT' \| translate: i18nParams"></p>` | Translation with i18nParams | Low risk — depends on translation content |

### HTML Body Context — `bypassSecurityTrustHtml()` (Angular DomSanitizer Bypass)

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `frontend/src/app/search-result/search-result.component.ts` | 170 | `this.sanitizer.bypassSecurityTrustHtml(queryParam)` | URL query parameter `q` | **Reflected XSS** — bypasses Angular sanitizer for search query |
| 2 | `frontend/src/app/search-result/search-result.component.ts` | 132 | `this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)` | Product descriptions from API | **Stored XSS** — product description bypass |
| 3 | `frontend/src/app/last-login-ip/last-login-ip.component.ts` | 39 | `this.sanitizer.bypassSecurityTrustHtml(\`<small>${payload.data.lastLoginIp}</small>\`)` | JWT payload `lastLoginIp` | **Stored XSS** via JWT manipulation |
| 4 | `frontend/src/app/track-result/track-result.component.ts` | 48 | `this.sanitizer.bypassSecurityTrustHtml(\`<code>${results.data[0].orderId}</code>\`)` | Order data from API | **Stored XSS** via order ID injection |
| 5 | `frontend/src/app/data-export/data-export.component.ts` | 57 | `this.sanitizer.bypassSecurityTrustHtml(data.image)` | Captcha API response | XSS via captcha image data |
| 6 | `frontend/src/app/administration/administration.component.ts` | 60 | `this.sanitizer.bypassSecurityTrustHtml(...)` on user emails | User data from API | **Stored XSS** — admin panel email rendering |
| 7 | `frontend/src/app/administration/administration.component.ts` | 78 | `this.sanitizer.bypassSecurityTrustHtml(feedback.comment)` | Feedback comments | **Stored XSS** — admin panel feedback rendering |
| 8 | `frontend/src/app/about/about.component.ts` | 119-121 | `this.sanitizer.bypassSecurityTrustHtml(feedbacks[i].comment)` | Feedback data | **Stored XSS** — about page gallery |
| 9 | `frontend/src/app/score-board/score-board.component.ts` | 86 | `this.sanitizer.bypassSecurityTrustHtml(challenge.description)` | Challenge descriptions | Stored XSS if challenge data is manipulated |

### JavaScript Context — `document.write()`

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `frontend/src/app/data-export/data-export.component.ts` | 71 | `window.open('', '_blank', 'width=500')?.document.write(this.userData)` | Backend API response (user data export) | **Stored XSS** — writes unescaped API response to new window |

### JavaScript Context — `innerHTML` Direct Assignment

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `frontend/src/hacking-instructor/index.ts` | 126 | `textBox.innerHTML = snarkdown(hint.text)` | Hint text from challenge instructions | XSS if hint text contains script tags (snarkdown processes markdown) |

### JavaScript Context — `eval()` (Server-Side RCE)

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/userProfile.ts` | 62 | `username = eval(code)` | Username field matching `#{(.*)}` pattern | **Remote Code Execution** — server-side eval of user input |

### JavaScript Context — `vm.runInContext()` (Server-Side Sandbox Escape)

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/b2bOrder.ts` | 23 | `vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })` | `orderLinesData` from POST body | **RCE** — safe-eval sandbox may be escapable |
| 2 | `routes/fileUpload.ts` | 83 | `vm.runInContext('libxml.parseXml(data, { noent: true })', sandbox)` | XML file upload content | **XXE** — XML entity expansion enabled |
| 3 | `routes/fileUpload.ts` | 117 | `vm.runInContext('JSON.stringify(yaml.load(data))', sandbox)` | YAML file upload content | **YAML deserialization / DoS** — YAML bomb |

### Template Injection — Pug SSTI (Server-Side)

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/userProfile.ts` | 87 | `pug.compile(template)` with username substitution at line 74 | Username from database (post-eval) | **SSTI** — Pug template injection via crafted username |
| 2 | `routes/videoHandler.ts` | 69 | `pug.compile(template)` with subtitles injection | Video subtitle file content | **SSTI** — template injection via subtitle data |
| 3 | `routes/dataErasure.ts` | 69-72 | `res.render('dataErasureResult', { ...req.body })` with `layout` from POST body | `req.body.layout` parameter | **LFI/SSTI** — layout path traversal to include arbitrary templates |

### SQL Injection Sinks

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/login.ts` | 34 | `sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email}'\`)` | POST body `email` field | **Authentication bypass** — SQL injection in login |
| 2 | `routes/search.ts` | 23 | `sequelize.query(\`SELECT * FROM Products WHERE name LIKE '%${criteria}%'\`)` | Query parameter `q` | **Data exfiltration** — UNION-based SQL injection |

### NoSQL Injection Sinks

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/showProductReviews.ts` | 36 | `db.reviewsCollection.find({ $where: 'this.product == ' + id })` | URL parameter `id` | **NoSQL injection** — JavaScript eval in $where |
| 2 | `routes/trackOrder.ts` | 18 | `db.ordersCollection.find({ $where: \`this.orderId === '${id}'\` })` | URL parameter `id` | **NoSQL injection** — JavaScript eval in $where |
| 3 | `routes/updateProductReviews.ts` | 18-20 | `db.reviewsCollection.update({ _id: req.body.id }, ..., { multi: true })` | POST body `id` field | **Mass update** — multi flag allows all-document updates |

### Path Traversal / File Inclusion Sinks

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/fileServer.ts` | 33 | `res.sendFile(path.resolve('ftp/', file))` | URL parameter `:file` | **Path traversal** — extension filter bypass potential |
| 2 | `routes/logfileServer.ts` | 14 | `res.sendFile(path.resolve('logs/', file))` | URL parameter `:file` | **Path traversal** — only forward slash check |
| 3 | `routes/keyServer.ts` | 14 | `res.sendFile(path.resolve('encryptionkeys/', file))` | URL parameter `:file` | **Path traversal** — only forward slash check |
| 4 | `routes/quarantineServer.ts` | 14 | `res.sendFile(path.resolve('ftp/quarantine/', file))` | URL parameter `:file` | **Path traversal** — only forward slash check |
| 5 | `routes/dataErasure.ts` | 69 | `path.resolve(req.body.layout)` used in `res.render()` | POST body `layout` | **LFI** — blacklist bypass possible |

### CSP Header Injection

| # | File | Line | Code | Data Source | Impact |
|---|------|------|------|-------------|--------|
| 1 | `routes/userProfile.ts` | 88 | `` `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'` `` | User `profileImage` from database | **CSP bypass** — inject arbitrary CSP directives via profile image URL |

## 10. SSRF Sinks

**Network Surface Focus:** All SSRF sinks listed below are in server-side code that processes network requests initiated by the Express.js application. Local-only utilities and build scripts have been excluded.

### HTTP(S) Clients — Direct SSRF via User Input

#### 1. Profile Image URL Upload — CRITICAL
- **File:** `routes/profileImageUrlUpload.ts`
- **Line:** 24
- **Code:** `const response = await fetch(url)` where `url = req.body.imageUrl`
- **User-Controllable Components:** Full URL (scheme, host, path, query)
- **Validation:** **NONE** — only checks for challenge-specific pattern matching
- **HTTP Client:** Native `fetch()` API
- **Impact:** Full SSRF — access cloud metadata (169.254.169.254), scan internal networks, reach internal services, exfiltrate data via DNS/HTTP. This is the primary SSRF attack vector in the application.

### HTTP(S) Clients — Configuration-Driven SSRF

#### 2. Webhook Notification
- **File:** `lib/webhook.ts`
- **Line:** 18
- **Code:** `const res = await fetch(webhook, { method: 'POST', ... })` where `webhook = process.env.SOLUTIONS_WEBHOOK`
- **User-Controllable:** Via environment variable injection
- **Validation:** **NONE**
- **HTTP Client:** Native `fetch()` API
- **Impact:** SSRF if environment variable can be controlled; exfiltrates challenge solution data

#### 3. Chatbot Training Data Download
- **File:** `routes/chatbot.ts`
- **Lines:** 34-36
- **Code:** `const data = await download(trainingFile)` where `trainingFile` from configuration `application.chatBot.trainingData`
- **User-Controllable:** Via YAML configuration
- **Validation:** Only `utils.isUrl()` (checks if string starts with "http")
- **HTTP Client:** NPM `download` package (v8.0.0)
- **Impact:** SSRF during application initialization; downloads arbitrary content from attacker-controlled servers

#### 4. Application Customization — Logo Download
- **File:** `lib/startup/customizeApplication.ts`
- **Line:** 41
- **Code:** `await utils.downloadToFile(filePath, destinationFolder + '/' + file)` for `application.logo` config
- **User-Controllable:** Via YAML configuration
- **Validation:** Only `utils.isUrl()`
- **HTTP Client:** NPM `download` package via `utils.downloadToFile()` (`lib/utils.ts` lines 121-128)
- **Impact:** Download arbitrary files from internal/external servers at startup

#### 5. Application Customization — Favicon Download
- **File:** `lib/startup/customizeApplication.ts`
- **Line:** 55
- **Code:** Same pattern as Logo for `application.favicon` config
- **Impact:** Same as above

#### 6. Application Customization — Promotion Video Download
- **File:** `lib/startup/customizeApplication.ts`
- **Line:** 66
- **Code:** Same pattern for `application.promotion.video` config
- **Impact:** Same as above

#### 7. Application Customization — Subtitles Download
- **File:** `lib/startup/customizeApplication.ts`
- **Line:** 70
- **Code:** Same pattern for `application.promotion.subtitles` config
- **Impact:** Same as above

#### 8. Easter Egg Overlay Download
- **File:** `lib/startup/customizeEasterEgg.ts`
- **Lines:** 14-17
- **Code:** `await utils.downloadToFile(overlayPath, ...)` for `application.easterEggPlanet.overlayMap` config
- **Validation:** Only `utils.isUrl()`
- **HTTP Client:** NPM `download` package
- **Impact:** Download arbitrary overlay images from internal networks at startup

### Importers & Data Loaders

#### 9. Product Image Download (Database Initialization)
- **File:** `data/datacreator.ts`
- **Lines:** 329-332
- **Code:** `void utils.downloadToFile(imageUrl, ...)` for `products[].image` config values
- **Validation:** Only `utils.isUrl()`
- **Impact:** SSRF during database initialization; fires `void` (no await) so errors are silenced

#### 10. Product Blueprint Download
- **File:** `data/datacreator.ts`
- **Lines:** 358-361
- **Code:** `await utils.downloadToFile(blueprintUrl, ...)` for `products[].fileForRetrieveBlueprintChallenge` config
- **Validation:** Only `utils.isUrl()`
- **Impact:** SSRF during database initialization

#### 11. Memory Image Download
- **File:** `data/datacreator.ts`
- **Lines:** 285-288
- **Code:** `void utils.downloadToFile(imageUrl, ...)` for `memories[].image` config values
- **Validation:** Only `utils.isUrl()`
- **Impact:** SSRF during database initialization

### Redirect & "Next URL" Handlers

#### 12. Open Redirect
- **File:** `routes/redirect.ts`
- **Lines:** 13-33
- **Code:** `res.redirect(toUrl)` where `toUrl = query.to`
- **Validation:** Flawed allowlist using `.includes()` instead of strict matching (`lib/insecurity.ts` lines 124-141)
- **Bypass:** `?to=https://evil.com?https://github.com/juice-shop/juice-shop` passes the check
- **Impact:** Open redirect to attacker-controlled domains; enables phishing, token theft via referrer

### Utility Functions (Shared SSRF Infrastructure)

#### Download Utility
- **File:** `lib/utils.ts`
- **Lines:** 121-128
- **Code:**
```typescript
export const downloadToFile = async (url: string, dest: string) => {
  const data = await download(url)
  fs.writeFileSync(dest, data)
}
```
- **No URL validation:** Accepts any URL including `file://`, internal IPs, cloud metadata
- **Used by:** Sinks #4-11 above
- **NPM Package:** `download@8.0.0` — supports HTTP/HTTPS, follows redirects

### Summary of SSRF Attack Surface

| Priority | Sink | User-Controllable | Validation | Runtime Context |
|----------|------|-------------------|------------|-----------------|
| **CRITICAL** | `routes/profileImageUrlUpload.ts:24` | Direct (POST body) | None | Any authenticated request |
| **HIGH** | `lib/webhook.ts:18` | Environment variable | None | Challenge solve events |
| **HIGH** | `routes/redirect.ts:19` | Direct (query param) | Flawed allowlist | Any request |
| **MEDIUM** | `routes/chatbot.ts:34-36` | Configuration file | isUrl() only | App initialization |
| **MEDIUM** | `lib/startup/customizeApplication.ts:41-70` | Configuration file | isUrl() only | App startup |
| **MEDIUM** | `lib/startup/customizeEasterEgg.ts:14-17` | Configuration file | isUrl() only | App startup |
| **LOW** | `data/datacreator.ts:285-361` | Configuration file | isUrl() only | Database initialization |


