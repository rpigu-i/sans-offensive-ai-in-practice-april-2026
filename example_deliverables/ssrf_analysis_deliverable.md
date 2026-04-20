# SSRF Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** One high-confidence, directly externally exploitable Server-Side Request Forgery vulnerability was identified with a clear, unobstructed source-to-sink data flow. Additional configuration-driven SSRF sinks exist but are not triggerable via external HTTP requests in a standard deployment.
- **Purpose of this Document:** This report provides strategic context on the application's outbound request mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

**Findings Summary:**

| ID | Endpoint | Vulnerability | External? | Confidence |
|----|----------|---------------|-----------|------------|
| SSRF-VULN-01 | `POST /profile/image/url` | URL_Manipulation — no validation on `imageUrl` before `fetch()` | Yes | High |

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Unrestricted URL Fetch from User-Supplied Input

- **Description:** The profile image URL upload endpoint accepts a user-supplied URL in the POST request body (`imageUrl`) and passes it directly to the Node.js native `fetch()` API with zero validation — no scheme restriction, no hostname allowlist, no private IP range check, no port restriction.
- **Implication:** An authenticated attacker can force the application server to make an outbound HTTP request to any destination, including `http://127.0.0.1`, `http://169.254.169.254` (cloud metadata), and arbitrary internal network services. The response body is streamed back (primary sink at line 24), making this non-blind SSRF with data exfiltration potential.
- **Representative Finding:** `SSRF-VULN-01`

### Pattern 2: Weak `isUrl()` Guard on Configuration-Driven Sinks

- **Description:** Multiple startup-time and initialization-time HTTP sinks (chatbot training data download, logo/favicon/video/subtitle downloads, database product image downloads) are gated only by `utils.isUrl()` — a trivial check that returns `true` if the string starts with `"http"`. This accepts `http://127.0.0.1`, `http://169.254.169.254`, and any other HTTP URL.
- **Implication:** If an attacker can influence the YAML configuration file or environment variables at deployment time, all these sinks become exploitable. In a standard deployment these are not reachable via external HTTP requests, so they are rated as not externally exploitable.
- **Representative Findings:** Sinks #3–#11 (all configuration/startup-time, see §4)

---

## 3. Strategic Intelligence for Exploitation

- **HTTP Client Library:** Native Node.js `fetch()` API (used by the primary SSRF sink) and the `download@8.0.0` npm package (used by configuration-driven sinks).
- **Request Architecture:** The primary sink at `routes/profileImageUrlUpload.ts:24` issues a raw `GET` request to the attacker-supplied URL. The response body is streamed directly to disk via `Readable.fromWeb(response.body).pipe(fileStream)`. If the fetch fails, the raw URL is persisted to the user's `profileImage` database column — a secondary stored-URL leak path.
- **Authentication Requirement:** A valid session cookie (`token`) must accompany requests to the primary SSRF endpoint. Authentication is checked inside the handler (not by middleware), so unauthenticated requests receive a 302 redirect to `/profile` rather than an error that would reveal the SSRF path exists. Any registered user account is sufficient; admin privileges are not required.
- **Response Exposure (Non-Blind):** The fetched response body is written to a publicly accessible file: `frontend/dist/frontend/assets/public/images/uploads/<userId>.<ext>`. After triggering the SSRF, the response content can be retrieved by fetching `/assets/public/images/uploads/<userId>.jpg` (or the appropriate extension). This makes SSRF-VULN-01 **non-blind with full response retrieval**.
- **Extension Inference:** The file extension is derived from the last `.`-delimited segment of the attacker-supplied URL. For URLs without a recognized image extension, it defaults to `.jpg`. This means even non-image responses (e.g., text from a metadata endpoint) will be saved and retrievable.
- **Internal Services:** The application runs on port 3000. Standard cloud metadata endpoint (`169.254.169.254`) and any services co-located on the container network are reachable.
- **Detection-Only Challenge Flag:** Line 20 of `profileImageUrlUpload.ts` sets `req.app.locals.abused_ssrf_bug = true` when the URL matches `/solve/challenges/server-side/`. This is a **monitoring flag only** — the request is never blocked and the SSRF proceeds regardless.

---

## 4. Secure by Design: Validated Components

These sinks were analyzed and found to be either safe or not externally triggerable.

| Component/Flow | File Location | Defense / Reason Not Exploitable | Verdict |
|---|---|---|---|
| **Webhook Notification** | `lib/webhook.ts:18` | URL sourced exclusively from `process.env.SOLUTIONS_WEBHOOK` environment variable. Not controllable via any HTTP request parameter. Requires deployment-level access to inject. | NOT EXTERNALLY EXPLOITABLE |
| **Chatbot Training Data Download** | `routes/chatbot.ts:34-36` | URL sourced from `application.chatBot.trainingData` YAML config. `initializeChatbot()` is called at module load time; no external HTTP request can alter the config value post-startup. Only `isUrl()` validation exists (insufficient), but not reachable externally. | NOT EXTERNALLY EXPLOITABLE |
| **Logo / Favicon / Promotion Video / Subtitles Download** | `lib/startup/customizeApplication.ts:41-70` | All URLs sourced from YAML `application.*` config values. Only runs at application startup (`server.ts:743`). No HTTP endpoint exposes these config values for user modification. `isUrl()` only check is insufficient, but externally inaccessible. | NOT EXTERNALLY EXPLOITABLE |
| **Easter Egg Overlay Download** | `lib/startup/customizeEasterEgg.ts:14-17` | URL sourced from `application.easterEggPlanet.overlayMap` config. Startup-only. Same `isUrl()` guard. Not reachable via HTTP. | NOT EXTERNALLY EXPLOITABLE |
| **Product Image / Blueprint / Memory Image Downloads** | `data/datacreator.ts:285-361` | URLs sourced from YAML `products[].image` / `products[].fileForRetrieveBlueprintChallenge` / `memories[].image` config values. Triggered only during database initialization at startup. Not externally triggerable. | NOT EXTERNALLY EXPLOITABLE |
| **Open Redirect** | `routes/redirect.ts:13-33` | The `GET /redirect?to=` endpoint issues a `res.redirect()` (browser-side redirect), not a server-side outbound HTTP request. It does not constitute SSRF. The flawed `.includes()` allowlist enables phishing redirect abuse but does not force the server to make outbound requests. | NOT SSRF (Open Redirect only) |

---

## 5. Exploitation Queue

### SSRF-VULN-01 — Profile Image URL Upload (URL_Manipulation)

**Source-to-Sink Trace:**

```
[SOURCE]   req.body.imageUrl                     (user POST body, no sanitization)
    ↓
[ASSIGN]   const url = req.body.imageUrl         (profileImageUrlUpload.ts:19)
    ↓
[CHECK]    url.match(/solve\/challenges\/server-side/) → sets flag only, no block
    ↓
[AUTH]     security.authenticatedUsers.get(req.cookies.token) → must be truthy
    ↓
[SINK]     const response = await fetch(url)     (profileImageUrlUpload.ts:24)
    ↓
[RESPONSE] Readable.fromWeb(response.body).pipe(fileStream) → written to public path
```

**Missing Defenses:**
- No scheme allowlist (accepts `file://`, `http://`, `https://`, etc.)
- No hostname allowlist or blocklist
- No private/reserved IP range check (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16)
- No port restriction
- No redirect-following control

**Witness Payload:**
```
POST /profile/image/url HTTP/1.1
Host: juice-shop:3000
Cookie: token=<valid_jwt>
Content-Type: application/x-www-form-urlencoded

imageUrl=http://169.254.169.254/latest/meta-data/
```

**Response Retrieval:**
```
GET /assets/public/images/uploads/<userId>.jpg HTTP/1.1
Host: juice-shop:3000
```

