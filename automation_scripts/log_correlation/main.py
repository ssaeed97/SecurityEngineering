"""
LOG CORRELATION - Hashmap-Based Security Event Correlator

=====================================================================
REFERENCE NOTES - Hashmaps, O(1) Lookup, defaultdict, Log Correlation
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Security investigations require correlating events across multiple
    log sources: auth logs, access logs, network logs, endpoint logs
  - SIEMs (Splunk, Elastic) do this internally, but understanding the
    underlying algorithm shows engineering depth
  - Same pattern applies to: correlating IDS alerts with firewall logs,
    matching VPN logins with access events, joining threat intel feeds
    with internal telemetry


HASHMAP = PYTHON DICT:
------------------------
  A hashmap stores key-value pairs with O(1) lookup.
  In Python, dict IS a hashmap. Every time you use {}, you use a hashmap.

  Why O(1)? Internally, Python hashes the key to get an array index,
  then jumps directly to that slot. No scanning needed.

  user_data = {"192.168.1.100": ["event1", "event2"]}
  user_data["192.168.1.100"]   # → instant lookup, O(1)


WHY HASHMAPS MATTER FOR LOG CORRELATION:
------------------------------------------
  Problem: Given auth_logs (n entries) and access_logs (m entries),
  find all access events for each authenticated IP.

  NAIVE - nested loops, O(n × m):
    for auth in auth_logs:           # n iterations
        for access in access_logs:   # m iterations EACH TIME
            if auth.ip == access.ip:
                # match found

    1000 auth × 10000 access = 10,000,000 comparisons

  HASHMAP - index one log, walk the other, O(n + m):
    access_by_ip = {}
    for access in access_logs:       # m iterations, ONE pass
        access_by_ip[access.ip].append(access)

    for auth in auth_logs:           # n iterations, ONE pass
        events = access_by_ip[auth.ip]   # O(1) lookup

    1000 + 10000 = 11,000 operations - 1000x faster


defaultdict(list) - AUTO-GROUPING PATTERN:
--------------------------------------------
  The most common pattern for log correlation:
  "Group all events by IP (or user, or session ID)"

  from collections import defaultdict

  events_by_ip = defaultdict(list)
  for event in logs:
      events_by_ip[event_ip].append(event)

  Result:
  {
      "192.168.1.100": [event1, event2, event3],
      "10.0.0.5": [event4, event5],
  }

  Without defaultdict, you'd need:
      if ip not in events_by_ip:
          events_by_ip[ip] = []
      events_by_ip[ip].append(event)

  defaultdict saves 2 lines every time.


PARSE ONCE, REUSE - AVOID REPEATED .split():
-----------------------------------------------
  BAD - splits the same string multiple times:
    if "FAILED" in log.split()[3]:
        auth_by_ip[log.split()[2]].append(log)

  GOOD - split once, store in variables:
    parts = log.split()
    ip = parts[2]
    status = parts[3]
    if status == "LOGIN_FAILED":
        auth_by_ip[ip].append(log)


DETECTION PATTERN - FAILED → SUCCESS → ADMIN ACCESS:
-------------------------------------------------------
  This is a classic account compromise indicator:
    1. Attacker tries credentials → multiple LOGIN_FAILED
    2. Attacker succeeds → LOGIN_SUCCESS
    3. Attacker escalates → accesses /admin paths

  Algorithm:
    - Track failed logins per IP in a dict
    - On LOGIN_SUCCESS, check if that IP had prior failures
    - If yes, look up their access log entries for admin paths
    - If admin paths found → flag as potential compromise


ONE-LINE RECALLS:
------------------
  Hashmap:      "Python dict IS a hashmap - O(1) lookup by key"
  Correlation:  "Index one log by IP in O(m), walk the other in O(n) -
                 total O(n+m) instead of O(n×m)"
  defaultdict:  "Auto-creates empty list for new keys - perfect for
                 grouping events by IP"
  Parse once:   "Split once, store in variables - don't call .split()
                 multiple times on the same string"
  Pattern:      "Failed → Success → Admin = potential account compromise"

=====================================================================
"""

from collections import defaultdict


def correlate_logs(auth_logs, access_logs):
    """
    Correlate auth and access logs by IP to detect suspicious patterns:
    failed login(s) → successful login → admin access = potential compromise.

    Uses hashmap (dict) indexing for O(n+m) correlation instead of O(n×m).

    Args:
        auth_logs: List of auth log strings
        access_logs: List of access log strings

    Returns:
        List of dicts describing flagged IPs with their suspicious activity
    """
    # Step 1: Index access logs by IP - O(m)
    access_by_ip = defaultdict(list)
    for line in access_logs:
        parts = line.split()
        ip = parts[2]
        access_by_ip[ip].append({
            "timestamp": parts[0] + " " + parts[1],
            "method": parts[3],
            "path": parts[4],
            "status": parts[5],
        })

    # Step 2: Walk auth logs, track failures, detect pattern - O(n)
    failed_ips = defaultdict(list)
    flagged = []

    for line in auth_logs:
        parts = line.split()
        timestamp = parts[0] + " " + parts[1]
        ip = parts[2]
        status = parts[3]
        user = parts[4].split("=")[1]

        if status == "LOGIN_FAILED":
            failed_ips[ip].append({"timestamp": timestamp, "user": user})

        elif status == "LOGIN_SUCCESS" and ip in failed_ips:
            # This IP had failures before a success - check for admin access
            admin_actions = [
                a for a in access_by_ip[ip]       # O(1) lookup by IP
                if a["path"].startswith("/admin")  # filter admin paths
            ]

            if admin_actions:
                flagged.append({
                    "ip": ip,
                    "user": user,
                    "failed_attempts": len(failed_ips[ip]),
                    "login_success_at": timestamp,
                    "admin_actions": admin_actions,
                })

    return flagged


if __name__ == "__main__":
    auth_logs = [
        # 192.168.1.100 - Clean login, no prior failures
        "2025-04-09 10:15:32 192.168.1.100 LOGIN_SUCCESS user=admin",

        # 10.0.0.5 - Failed logins then success, but no admin access after
        "2025-04-09 10:15:33 10.0.0.5 LOGIN_FAILED user=root",
        "2025-04-09 10:15:35 10.0.0.5 LOGIN_FAILED user=root",
        "2025-04-09 10:15:38 10.0.0.5 LOGIN_SUCCESS user=root",

        # 172.16.0.50 - Normal user, clean login
        "2025-04-09 10:15:36 172.16.0.50 LOGIN_SUCCESS user=developer",

        # 203.45.167.22 - SUSPICIOUS: failed → success → admin access
        "2025-04-09 10:15:40 203.45.167.22 LOGIN_FAILED user=admin",
        "2025-04-09 10:15:42 203.45.167.22 LOGIN_FAILED user=admin",
        "2025-04-09 10:15:45 203.45.167.22 LOGIN_SUCCESS user=admin",
    ]

    access_logs = [
        # 192.168.1.100 - Accessed admin, but login was clean (no failures)
        "2025-04-09 10:15:33 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:34 192.168.1.100 GET /admin/dashboard 200",

        # 10.0.0.5 - Had failures, but only accessed non-admin paths
        "2025-04-09 10:15:39 10.0.0.5 GET /api/users 200",
        "2025-04-09 10:15:40 10.0.0.5 DELETE /api/users/5 200",

        # 203.45.167.22 - Had failures, succeeded, then hit admin paths
        "2025-04-09 10:15:46 203.45.167.22 GET /admin/dashboard 200",
        "2025-04-09 10:15:47 203.45.167.22 GET /admin/users 200",
        "2025-04-09 10:15:48 203.45.167.22 POST /admin/users/create 201",

        # 172.16.0.50 - Normal user activity
        "2025-04-09 10:15:50 172.16.0.50 GET /api/products 200",
    ]

    results = correlate_logs(auth_logs, access_logs)

    print("=== Suspicious Activity: Failed Login → Success → Admin Access ===\n")
    if results:
        for r in results:
            print(f"  IP: {r['ip']}")
            print(f"  User: {r['user']}")
            print(f"  Failed attempts: {r['failed_attempts']}")
            print(f"  Logged in at: {r['login_success_at']}")
            print(f"  Admin actions:")
            for action in r['admin_actions']:
                print(f"    {action['method']} {action['path']} -> {action['status']}")
            print()
    else:
        print("  No suspicious patterns detected")

    # Expected output:
    # FLAGGED: 203.45.167.22 - 2 failed logins, then success, then admin access
    #
    # NOT flagged:
    #   192.168.1.100 - accessed admin but had NO prior failures (clean login)
    #   10.0.0.5      - had failures then success, but accessed /api not /admin
    #   172.16.0.50   - clean login, normal user activity