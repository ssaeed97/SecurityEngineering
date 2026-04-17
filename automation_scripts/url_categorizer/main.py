"""
URL CATEGORIZER - Web Traffic Analysis and Threat Detection


=====================================================================
REFERENCE NOTES - urlparse, parse_qs, Base64, Open Redirects, SSRF
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Analyzing web traffic logs requires breaking URLs into components
  - Detecting C2 (command and control) beacons, data exfiltration,
    SSRF attempts, and open redirects from URL patterns
  - Same techniques used in: WAF rule writing, proxy log analysis,
    threat hunting, phishing detection, IDS signatures


urlparse - BUILT-IN URL PARSER:
---------------------------------
  from urllib.parse import urlparse, parse_qs

  parsed = urlparse("https://api.example.com/v1/users?id=123&role=admin")
  parsed.scheme    → "https"
  parsed.netloc    → "api.example.com"     (the domain)
  parsed.path      → "/v1/users"
  parsed.query     → "id=123&role=admin"   (raw query string)

  parse_qs(parsed.query) → {"id": ["123"], "role": ["admin"]}
  Note: parse_qs returns LISTS because a key can appear multiple times
        e.g., ?tag=python&tag=security → {"tag": ["python", "security"]}

  URL structure:
    https://api.example.com/v1/users?id=123&role=admin
    │       │               │        │
    scheme  netloc (domain)  path    query parameters


BASE64 DETECTION - SPOTTING ENCODED DATA:
--------------------------------------------
  Base64 encodes binary data using only these characters:
    A-Z, a-z, 0-9, +, / and = for padding

  Properties of base64 strings:
    - Length is always a multiple of 4
    - Ends with 0, 1, or 2 equals signs for padding
    - Only contains the allowed character set

  Detection chain:
    1. Regex: r'^[A-Za-z0-9+/]+=*$' - only base64 characters
       ^              → start of string
       [A-Za-z0-9+/]  → any letter, digit, plus, or slash
       +              → one or more of above
       =*             → zero or more padding equals
       $              → end of string
    2. len(value) % 4 == 0 - length is multiple of 4
    3. len(value) >= 8 - ignore short strings that match accidentally
    4. base64.b64decode(value) - actually try to decode, confirm it works

  Example:
    "c2VjcmV0cw==" → regex match ✅, len=12, 12%4=0 ✅, >=8 ✅,
                      decodes to "secrets" ✅ → FLAGGED

    "admin" → regex match ✅, len=5, 5%4=1 ❌ → NOT base64

    "abc123" → regex match ✅, len=6, 6%4=2 ❌ → NOT base64


OPEN REDIRECT - HOW IT WORKS:
--------------------------------
  An open redirect lets attackers craft a link on a TRUSTED domain
  that sends the victim to a MALICIOUS site.

  SAFE (relative path, stays on same site):
    /login?redirect=/dashboard

  DANGEROUS (full URL, goes to attacker's site):
    /login?redirect=http://evil.com

  The victim sees "api.example.com" in the link and trusts it,
  but after login they're sent to evil.com.

  Detection:
    1. Check param names: redirect, url, next, return, goto
    2. Check param values: starts with http:// or https://
    3. If both match → open redirect attempt

  Common redirect parameter names:
    redirect, url, next, return, returnUrl, goto, destination, continue


SSRF via AWS METADATA:
------------------------
  169.254.169.254 is the AWS metadata endpoint. It returns IAM
  credentials, instance info, and network config.

  If a URL points to this IP, it means either:
    - Someone is testing for SSRF
    - An attacker is exploiting SSRF to steal IAM credentials

  This was the attack vector in the Capital One breach (2019).


ONE-LINE RECALLS:
------------------
  urlparse:      "scheme, netloc (domain), path, query - built-in URL parser"
  parse_qs:      "Turns query string into dict of lists"
  Base64 check:  "Regex for allowed chars + length multiple of 4 + try decode"
  Open redirect: "Redirect param with http:// value = phishing vector"
  SSRF:          "169.254.169.254 in URL = AWS metadata access attempt"

=====================================================================
"""

from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import re
import base64


def is_base64(value):
    """
    Check if a string looks like base64-encoded data.

    Uses a multi-step check:
      1. Regex: only valid base64 characters (A-Za-z0-9+/=)
      2. Length is a multiple of 4 (base64 property)
      3. At least 8 chars (avoid false positives on short strings)
      4. Actually decodes successfully
    """
    if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0 and len(value) >= 8:
        try:
            base64.b64decode(value)
            return True
        except Exception:
            return False
    return False


def analyze_urls(urls):
    """
    Parse, group, and flag suspicious URLs.

    Detections:
      - Known malicious domains (set lookup)
      - AWS metadata endpoint / SSRF (169.254.169.254)
      - Open redirect attempts (redirect param with external URL)
      - Base64-encoded parameters (possible data exfiltration)

    Args:
        urls: List of URL strings

    Returns:
        Tuple of (grouped_by_domain dict, alerts list)
    """
    malicious_domains = {"malware-c2.evil.com", "evil.com"}
    metadata_endpoints = {"169.254.169.254"}
    redirect_params = {"redirect", "url", "next", "return", "returnurl", "goto", "destination"}

    grouped = defaultdict(list)
    alerts = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        params = parse_qs(parsed.query)

        # Group by domain
        grouped[domain].append({
            "url": url,
            "path": path,
            "params": params,
        })

        # Check 1: Malicious domain
        if domain in malicious_domains:
            alerts.append({
                "url": url,
                "type": "MALICIOUS_DOMAIN",
                "severity": "HIGH",
                "reason": f"Known malicious domain: {domain}",
            })

        # Check 2: AWS metadata endpoint (SSRF)
        if domain in metadata_endpoints:
            alerts.append({
                "url": url,
                "type": "SSRF",
                "severity": "CRITICAL",
                "reason": "AWS metadata endpoint access - SSRF indicator",
            })

        # Check 3: Open redirect
        for key, values in params.items():
            if key.lower() in redirect_params:
                for val in values:
                    if val.startswith("http://") or val.startswith("https://"):
                        alerts.append({
                            "url": url,
                            "type": "OPEN_REDIRECT",
                            "severity": "MEDIUM",
                            "reason": f"Redirect to external URL via '{key}' param: {val}",
                        })

        # Check 4: Base64-encoded parameters (possible exfiltration)
        for key, values in params.items():
            for val in values:
                if is_base64(val):
                    decoded = base64.b64decode(val).decode("utf-8", errors="replace")
                    alerts.append({
                        "url": url,
                        "type": "BASE64_EXFIL",
                        "severity": "HIGH",
                        "reason": f"Base64 data in param '{key}' - decoded: '{decoded}'",
                    })

    return grouped, alerts


if __name__ == "__main__":
    urls = [
        # Normal API traffic
        "https://api.example.com/v1/users?id=123&role=admin",
        "https://api.example.com/v1/users?id=456&role=user",
        "https://cdn.legit-site.com/assets/logo.png",

        # Malicious domain - C2 beacons
        "http://malware-c2.evil.com/beacon?host=victim01&key=abc123",
        "http://malware-c2.evil.com/beacon?host=victim02&key=def456",

        # Malicious domain - data exfiltration with base64-encoded data
        "http://malware-c2.evil.com/exfil?data=c2VjcmV0cw==",

        # Open redirect attempt
        "https://api.example.com/v1/login?redirect=http://evil.com",

        # SSRF - AWS metadata endpoint
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",

        # Internal admin traffic - not malicious but worth grouping
        "https://internal.corp.net/admin/dashboard",
        "https://internal.corp.net/admin/users?action=delete&target=all",
    ]

    grouped, alerts = analyze_urls(urls)

    print("=== URLs Grouped by Domain ===\n")
    for domain, entries in sorted(grouped.items()):
        print(f"  {domain} ({len(entries)} requests)")
        for entry in entries:
            params_str = ""
            if entry["params"]:
                params_str = " | params: " + ", ".join(
                    f"{k}={v[0]}" for k, v in entry["params"].items()
                )
            print(f"    {entry['path']}{params_str}")
        print()

    print("=== Security Alerts ===\n")
    if alerts:
        for alert in alerts:
            print(f"  [{alert['severity']}] {alert['type']}")
            print(f"    URL: {alert['url']}")
            print(f"    Reason: {alert['reason']}")
            print()
    else:
        print("  No alerts.")

    print(f"=== Summary: {len(alerts)} alerts across {len(grouped)} domains ===")

    # Expected alerts:
    # [HIGH]     MALICIOUS_DOMAIN - malware-c2.evil.com (3 URLs)
    # [CRITICAL] SSRF - 169.254.169.254 metadata access
    # [MEDIUM]   OPEN_REDIRECT - redirect param pointing to http://evil.com
    # [HIGH]     BASE64_EXFIL - "c2VjcmV0cw==" decodes to "secrets"
    #
    # NOT flagged:
    #   api.example.com - normal API traffic
    #   cdn.legit-site.com - normal CDN access
    #   internal.corp.net - internal admin (grouped but not alerted)