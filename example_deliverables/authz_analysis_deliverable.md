# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** 11 high-confidence authorization vulnerabilities identified across horizontal, vertical, and context/workflow categories. Every endpoint from recon Section 8 has been traced to a verdict. All findings are passed to the exploitation phase via the machine-readable exploitation queue.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue. It is intended to be read alongside the JSON deliverable.

**Findings at a Glance:**

| ID | Type | Endpoint | Confidence |
|----|------|----------|------------|
| AUTHZ-VULN-01 | Horizontal | GET /rest/basket/:id | High |
| AUTHZ-VULN-02 | Horizontal | GET /api/Users/:id | High |
| AUTHZ-VULN-03 | Horizontal | GET /api/Users | High |
| AUTHZ-VULN-04 | Horizontal | POST /api/BasketItems | High |
| AUTHZ-VULN-05 | Horizontal | PUT /api/BasketItems/:id | High |
| AUTHZ-VULN-06 | Horizontal | POST /rest/basket/:id/checkout | High |
| AUTHZ-VULN-07 | Vertical | POST /api/Users | High |
| AUTHZ-VULN-08 | Vertical | JWT forgery (lib/insecurity.ts) | High |
| AUTHZ-VULN-09 | Vertical | PUT /api/Products/:id | High |
| AUTHZ-VULN-10 | Vertical | POST /rest/deluxe-membership | High |
| AUTHZ-VULN-11 | Context_Workflow | PATCH /rest/products/reviews | High |

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Missing Ownership Validation (Horizontal)
- **Description:** Multiple endpoints accept resource IDs (basket ID, user ID, basket item ID) without verifying the requesting user owns or has access to that resource. The JWT is validated (user is authenticated) but the resource is returned or mutated without binding the ID to the current user's identity.
- **Root Cause:** Route handlers call `BasketModel.findOne({ where: { id } })` or `BasketItemModel.findOne({ where: { id: req.params.id } })` without appending `UserId` or `BasketId` from the JWT. `security.isAuthorized()` on these routes only validates JWT cryptographic signature — it performs zero resource-scoping.
- **Implication:** Any authenticated attacker can read or mutate any user's basket, basket items, and user profile data by enumerating small integer IDs.
- **Representative:** AUTHZ-VULN-01, AUTHZ-VULN-02, AUTHZ-VULN-05, AUTHZ-VULN-06

### Pattern 2: Challenge-Detection-Only Guards (Horizontal)
- **Description:** Several "ownership checks" exist in the code but only trigger a challenge flag — they never block the request. The code calls `challengeUtils.solveIf(...)` to record that a vulnerability was exploited, then continues execution without returning an error.
- **Root Cause:** `challengeUtils.solveIf()` is a side-effect-free logging call. It does not interrupt the request/response cycle. The actual guard logic (returning 401/403, calling `return`) is absent.
- **Implication:** The security check provides the visual appearance of protection in a code review but provides zero runtime enforcement.
- **Representative:** AUTHZ-VULN-01 (`routes/basket.ts:21-24` — check calls `solveIf` then falls through to `res.json(basket)`), AUTHZ-VULN-05 (`routes/basketItems.ts:70` — same pattern)

### Pattern 3: Client-Controlled Role/Privilege Fields (Vertical)
- **Description:** The application allows client-supplied values to directly set privileged fields (`role`, `paymentMode`) without server-side validation or sanitization.
- **Root Cause:** The Sequelize `User` model defines `role` with an `isIn` validator that accepts `'admin'` as valid input. No pre-hook strips or rejects the `role` field on registration. The `registerAdminChallenge` middleware detects the attack but calls `next()` unconditionally.
- **Implication:** Any unauthenticated user can self-register as `admin` in a single HTTP request, granting full application privileges immediately.
- **Representative:** AUTHZ-VULN-07, AUTHZ-VULN-10

### Pattern 4: Hardcoded Cryptographic Secret (Vertical)
- **Description:** The RSA private key used to sign all JWTs is hardcoded in plaintext inside the application source code. The corresponding public key is served via an unauthenticated endpoint.
- **Root Cause:** `lib/insecurity.ts` line 23 contains the full `-----BEGIN RSA PRIVATE KEY-----` block. No runtime secret injection, no key rotation, no environment variable.
- **Implication:** An attacker who can read the source code (via directory listing at `/ftp`, GitHub, etc.) can forge cryptographically valid JWTs with any claims: any user ID, any email, any role (`admin`, `accounting`, `deluxe`). All server-side role checks that rely on JWT claims are bypassed.
- **Representative:** AUTHZ-VULN-08

### Pattern 5: HTTP Parameter Pollution Ownership Bypass (Horizontal)
- **Description:** The basket item creation endpoint parses the raw body manually, collecting all values for each key into arrays. The ownership check uses `basketIds[0]` (first occurrence), but the item is actually inserted using `basketIds[basketIds.length - 1]` (last occurrence). Sending two `BasketId` values in the body splits the check from the insert.
- **Root Cause:** `routes/basketItems.ts` lines 37-44 — array indexing mismatch between security check and data usage.
- **Implication:** An authenticated attacker can add items to any other user's basket while the ownership check passes with the attacker's own basket ID.
- **Representative:** AUTHZ-VULN-04

### Pattern 6: Missing Authentication on Privileged Mutation Endpoint (Vertical)
- **Description:** The `isAuthorized()` middleware line for `PUT /api/Products/:id` was commented out in `server.ts`. The finale-rest module still auto-generates the PUT route handler, leaving it fully accessible without authentication.
- **Root Cause:** `server.ts` line ~369: `// app.put('/api/Products/:id', security.isAuthorized())` — middleware registration commented out, route handler still active.
- **Implication:** Any unauthenticated (anonymous) requester can modify any product's name, description, or price without any authentication token.
- **Representative:** AUTHZ-VULN-09

## 4. Vectors Analyzed and Confirmed Secure

These authorization checks were traced and confirmed to have robust, properly-placed guards. They are **low-priority** for further testing.

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|---|---|---|---|
| `GET /rest/order-history` | `routes/orderHistory.ts:13` | Inline token-map lookup: `security.authenticatedUsers.get(token)`. Filters results by authenticated user's obfuscated email (`{ email: updatedEmail }`). No other user's orders are returned unless email collision exists (theoretical only). | SAFE |
| `GET /rest/order-history/orders` | `server.ts:622`, `lib/insecurity.ts:156` | `security.isAccounting()` middleware runs before handler. Decodes JWT and checks `data.role === 'accounting'`. Returns HTTP 403 on failure. Guard dominates the sink (no path around it). Independently secure, though defeatable via JWT forgery (AUTHZ-VULN-08). | SAFE |
| `PUT /rest/order-history/:id/delivery-status` | `server.ts:623`, `lib/insecurity.ts:156` | Same `isAccounting()` middleware as above. Enforced before any database mutation. | SAFE |
| `POST /api/Users` (DELETE/PUT) | `server.ts:364` | `security.denyAll()` applied to PUT and DELETE on `/api/Users/:id` — uses a random HMAC secret that can never be satisfied. | SAFE |

---

## 5. Analysis Constraints and Blind Spots

- **Change Password Excluded by Scope Rules:** `GET /rest/user/change-password` was analyzed and found to lack a current-password requirement when the `current` query parameter is omitted. This finding was excluded per engagement rules ("Change password — overlaps with auth bypass demo").
- **Accounting Endpoints Conditional on JWT Forgery:** `GET /rest/order-history/orders` and `PUT /rest/order-history/:id/delivery-status` are correctly guarded by `isAccounting()`. They appear in the "Secure" table above but become exploitable once AUTHZ-VULN-08 (JWT forgery) is leveraged to obtain a token with `role: "accounting"`. The exploitation agent should chain AUTHZ-VULN-08 → accounting endpoint access as a secondary objective.
- **finale-rest CRUD Routes:** The auto-generated CRUD endpoints (`/api/Users/:id`, `/api/BasketItems/:id`, etc.) inherit only the middleware explicitly registered in `server.ts`. Routes where the `isAuthorized()` call was commented out or omitted leave the underlying CRUD handler unprotected.
- **In-Memory Token Map Dependency:** Several route handlers (order history, profile) use `security.authenticatedUsers.get(token)` instead of standard JWT middleware. This means forged tokens that were never added to the token map via a real login will fail these checks, even if the JWT signature is valid. Exploitation of JWT forgery (AUTHZ-VULN-08) works best against routes protected by `isAuthorized()` middleware, not token-map-dependent routes.

---

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture
- Sessions use JWT tokens signed with RS256 algorithm, stored in the `token` cookie (no `HttpOnly`, `Secure`, or `SameSite` flags) and injectable via `Authorization: Bearer` header.
- The JWT payload contains: `{ data: { id, email, role, deluxeToken, lastLoginIp, profileImage }, iat, exp }`.
- **Critical Finding:** The private key used to sign JWTs is hardcoded in `lib/insecurity.ts:23`. The corresponding public key is served at `GET /encryptionkeys/jwt.pub` (no auth required). An attacker can forge tokens with any claims using the key embedded in source code.
- Token lifetime: 6 hours. No refresh mechanism. No server-side revocation (except server restart clears `authenticatedUsers.tokenMap`).
- **Secondary auth path:** Some routes (e.g., `GET /rest/order-history`) bypass `isAuthorized()` middleware and instead perform inline lookup via `security.authenticatedUsers.get(token)` against the in-memory token map. These routes are only accessible to users whose tokens are actively tracked in the server's live token map (i.e., who actually logged in via the application).

### Role/Permission Model
- Five roles: `anon`, `customer` (default), `deluxe`, `accounting`, `admin`.
- Role is stored in the `Users` SQLite table AND embedded in the JWT `data.role` claim.
- **Critical Finding:** Role checks trust JWT claims directly with no database re-validation on each request. A forged JWT with `role: "admin"` is treated as a valid admin session.
- `admin` role has NO dedicated middleware guard — admin-accessible endpoints use `isAuthorized()` only, which only validates JWT signature.
- `accounting` role is guarded by `isAccounting()` middleware which does verify `data.role === 'accounting'` in the decoded token — BUT this check is defeated by JWT forgery (AUTHZ-VULN-08).
- `deluxe` role requires both `data.role === 'deluxe'` AND a valid HMAC `deluxeToken`. However, the HMAC is deterministic: `HMAC-SHA256(email + "deluxe")` with the key from `lib/insecurity.ts:48`. Both can be forged.

### Resource Access Patterns
- Most endpoints use small sequential integer IDs (SQLite auto-increment) for baskets (`bid`), users, and basket items — highly enumerable.
- All basket endpoints use `req.params.id` directly in database WHERE clauses with no user scoping.
- The `appendUserId()` middleware (`lib/insecurity.ts:177`) injects `req.body.UserId` from the JWT token map — this is a reliable user-binding mechanism but is only used on select routes (e.g., `/rest/basket`, `/rest/deluxe-membership`) and is absent on the auto-generated CRUD endpoints.

### Workflow Implementation
- Deluxe membership upgrade (`POST /rest/deluxe-membership`) performs payment validation inside `if (paymentMode === 'wallet')` and `if (paymentMode === 'card')` branches. There is no `else` or default rejection — any other `paymentMode` value skips both branches and executes the `user.update({ role: 'deluxe', ... })` call unconditionally.
- Basket checkout (`POST /rest/basket/:id/checkout`) fetches the basket by `:id` URL parameter without cross-referencing the authenticated user's `bid` JWT claim. The checkout creates a PDF order, decrements inventory, and records an order — all against the basket specified in the URL, not the user's own basket.
- Review updates (`PATCH /rest/products/reviews`) use `{ multi: true }` in the MarsDB update call. The `_id` field comes directly from `req.body.id` with no ownership check. Passing a MongoDB-style match-all query (e.g., `{}`) as the `id` will update every review in the database in a single request.

---
