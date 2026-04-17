"""
JWT DECODER AND VALIDATOR — Token Security Analyzer
Security Engineer Coding Practice Problem #18

=====================================================================
REFERENCE NOTES — JWT Structure, Base64url, Token Attacks, Sets
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - JWTs are everywhere: OAuth, OIDC, API authentication, session tokens
  - Misconfigured JWT validation is a common vulnerability
  - Security engineers need to decode and inspect tokens during
    pentests, incident response, and code review
  - Same decoding technique used in: analyzing OAuth flows,
    debugging authentication issues, forensic token analysis


JWT STRUCTURE:
----------------
  header.payload.signature

  Three base64url-encoded parts separated by dots.

  Header:  {"alg": "HS256", "typ": "JWT"}
  Payload: {"sub": "12345", "name": "User", "exp": 1893456000}
  Signature: HMAC-SHA256(header + "." + payload, secret_key)

  CRITICAL: Payload is NOT encrypted — only signed.
  Anyone with the token can decode and read the payload.
  The signature only proves it wasn't tampered with.


BASE64URL vs BASE64:
----------------------
  Standard base64: uses + / and = padding
  Base64url (JWT): uses - _ and strips padding

  To decode JWT parts:
    1. Replace - with + and _ with / (urlsafe_b64decode handles this)
    2. Add padding back: "=" * (4 - len % 4)
    3. Decode with base64.urlsafe_b64decode()

  Why padding matters:
    base64 requires input length to be a multiple of 4.
    JWT strips the = padding to save space in URLs.
    If you don't add it back, decoding fails.


COMMON JWT ATTACKS TO CHECK FOR:
-----------------------------------
  1. alg: none — token is unsigned, server accepts it as valid
     → Complete authentication bypass

  2. Empty signature — related to alg:none, token has no integrity check
     → Forged tokens accepted

  3. Expired token — exp claim is in the past
     → If accepted, enables replay attacks with stolen tokens

  4. No exp claim — token never expires
     → Stolen token valid forever

  5. Admin role in claims — may be legitimate or may be forged
     → Combined with alg:none = instant admin access


SET OPERATIONS — WHY {} NOT []:
---------------------------------
  Sets support mathematical operations that lists don't:

  a = {"sub", "iat", "iss", "exp"}
  b = {"sub", "exp", "name", "role"}

  a - b     → {"iat", "iss"}               difference (in a, not in b)
  a & b     → {"sub", "exp"}               intersection (in both)
  a | b     → {"sub","iat","iss","exp",...} union (everything)

  Lists can't do subtraction:
    ["sub", "iat"] - ["sub"]  → TypeError!

  Use sets when you need: membership checks, subtraction, intersection.
  Use lists when you need: order, duplicates, indexing.


ONE-LINE RECALLS:
------------------
  JWT decode:   "Split on dots, add base64 padding back, urlsafe_b64decode,
                 json.loads — payload is readable by anyone"
  Padding fix:  "'=' * (4 - len % 4) — JWT strips padding, add it back"
  Attacks:      "alg:none = unsigned, empty sig = forged, expired = replay,
                 no exp = forever valid"
  Sets:         "{} for set operations (subtraction, intersection),
                 [] for ordered data"

=====================================================================
"""

import base64
import json
import time


def decode_jwt_part(part):
    """
    Decode a base64url-encoded JWT part into a Python dict.

    JWT uses base64url encoding which differs from standard base64:
      - '+' replaced with '-'
      - '/' replaced with '_'
      - Padding '=' stripped

    We add padding back before decoding.
    """
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    decoded_bytes = base64.urlsafe_b64decode(part)
    return json.loads(decoded_bytes)


def analyze_jwt(token):
    """
    Decode and analyze a JWT for security issues.

    Checks for:
      - alg: none (unsigned token — authentication bypass)
      - Missing or empty signature
      - Expired token (replay attack risk)
      - No expiration claim (token valid forever)
      - Admin role in claims (privilege verification)
      - Missing recommended claims (sub, iat, iss, exp)

    Args:
        token: JWT string (header.payload.signature)

    Returns:
        Dict with decoded header, payload, and security alerts
    """
    parts = token.split(".")

    if len(parts) != 3:
        return {"error": f"Invalid JWT — expected 3 parts, got {len(parts)}"}

    header_b64, payload_b64, signature = parts

    try:
        header = decode_jwt_part(header_b64)
        payload = decode_jwt_part(payload_b64)
    except Exception as e:
        return {"error": f"Failed to decode: {e}"}

    alerts = []

    # Check 1: Algorithm set to "none" — unsigned token
    if header.get("alg", "").lower() == "none":
        alerts.append({
            "severity": "CRITICAL",
            "issue": "Algorithm set to 'none' — token is unsigned",
            "risk": "Complete authentication bypass — attacker can forge any identity",
        })

    # Check 2: Missing or empty signature
    if not signature:
        alerts.append({
            "severity": "CRITICAL",
            "issue": "Signature is empty",
            "risk": "Token integrity cannot be verified — may be forged",
        })

    # Check 3: Token expiration
    exp = payload.get("exp")
    if exp:
        if exp < time.time():
            expired_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp))
            alerts.append({
                "severity": "HIGH",
                "issue": f"Token expired at {expired_at}",
                "risk": "Expired tokens should be rejected — if accepted, replay attacks possible",
            })
    else:
        alerts.append({
            "severity": "MEDIUM",
            "issue": "No expiration claim (exp) — token never expires",
            "risk": "Stolen token is valid forever",
        })

    # Check 4: Admin role
    role = payload.get("role", "")
    if role == "admin":
        user = payload.get("name", payload.get("sub", "unknown"))
        alerts.append({
            "severity": "MEDIUM",
            "issue": f"Token has admin role for user '{user}'",
            "risk": "Verify this is legitimate — combined with alg:none this is account takeover",
        })

    # Check 5: Missing recommended claims
    recommended_claims = {"sub", "iat", "iss", "exp"}
    present_claims = set(payload.keys())
    missing = recommended_claims - present_claims
    if missing:
        alerts.append({
            "severity": "LOW",
            "issue": f"Missing recommended claims: {', '.join(sorted(missing))}",
            "risk": "Harder to validate token origin and freshness",
        })

    # Check 6: Weak algorithm
    alg = header.get("alg", "")
    weak_algorithms = {"HS256"}  # HS256 with weak secret is brute-forceable
    if alg in weak_algorithms:
        alerts.append({
            "severity": "LOW",
            "issue": f"Algorithm '{alg}' — ensure HMAC secret is at least 256 bits",
            "risk": "Weak secrets can be brute-forced offline with hashcat",
        })

    return {
        "header": header,
        "payload": payload,
        "has_signature": bool(signature),
        "alert_count": len(alerts),
        "alerts": alerts,
    }


def analyze_multiple_tokens(tokens):
    """Analyze a batch of JWTs and return summary."""
    results = []
    for token in tokens:
        result = analyze_jwt(token)
        results.append(result)

    critical = sum(1 for r in results for a in r.get("alerts", []) if a["severity"] == "CRITICAL")
    high = sum(1 for r in results for a in r.get("alerts", []) if a["severity"] == "HIGH")

    return {
        "total_tokens": len(results),
        "critical_alerts": critical,
        "high_alerts": high,
        "results": results,
    }


if __name__ == "__main__":
    tokens = [
        # Token 1: Normal valid token (expires in the future)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJTdWZ5YWFuIiwicm9sZSI6InVzZXIiLCJleHAiOjE4OTM0NTYwMDAsImlhdCI6MTcxMDAwMDAwMCwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSJ9.fake_signature",

        # Token 2: alg:none attack — unsigned token with admin role
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI5OTk5OSIsIm5hbWUiOiJBdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTg5MzQ1NjAwMH0.",

        # Token 3: Expired token
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1Njc4OSIsIm5hbWUiOiJFeHBpcmVkVXNlciIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNjAwMDAwMDAwLCJpYXQiOjE1OTkwMDAwMDB9.fake_signature",

        # Token 4: Valid token but with admin role — needs verification
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2Nzg5MCIsIm5hbWUiOiJTbmVha3lBZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTg5MzQ1NjAwMCwiaWF0IjoxNzEwMDAwMDAwfQ.fake_signature",
    ]

    descriptions = [
        "Normal valid token",
        "alg:none attack — unsigned with admin",
        "Expired token",
        "Admin role — needs verification",
    ]

    print("=== JWT Security Analyzer ===\n")

    for i, token in enumerate(tokens):
        result = analyze_jwt(token)
        print(f"--- Token {i+1}: {descriptions[i]} ---\n")

        if "error" in result:
            print(f"  ERROR: {result['error']}\n")
            continue

        print(f"  Header:    {result['header']}")
        print(f"  Algorithm: {result['header'].get('alg', 'N/A')}")
        print(f"  Subject:   {result['payload'].get('sub', 'N/A')}")
        print(f"  Name:      {result['payload'].get('name', 'N/A')}")
        print(f"  Role:      {result['payload'].get('role', 'N/A')}")
        print(f"  Signed:    {'Yes' if result['has_signature'] else 'NO — UNSIGNED'}")

        exp = result["payload"].get("exp")
        if exp:
            exp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp))
            status = "VALID" if exp > time.time() else "EXPIRED"
            print(f"  Expires:   {exp_str} [{status}]")
        else:
            print(f"  Expires:   NEVER (no exp claim)")

        if result["alerts"]:
            print(f"\n  Alerts ({result['alert_count']}):")
            for alert in result["alerts"]:
                print(f"    [{alert['severity']}] {alert['issue']}")
                print(f"      Risk: {alert['risk']}")
        else:
            print(f"\n  No security alerts.")

        print()

    # Summary
    summary = analyze_multiple_tokens(tokens)
    print("=== Summary ===")
    print(f"  Tokens analyzed: {summary['total_tokens']}")
    print(f"  Critical alerts: {summary['critical_alerts']}")
    print(f"  High alerts: {summary['high_alerts']}")

    # Expected:
    # Token 1: Low alerts only (missing iss claim, HS256 weak secret warning)
    # Token 2: CRITICAL — alg:none + empty signature + admin role
    # Token 3: HIGH — expired token
    # Token 4: MEDIUM — admin role needs verification