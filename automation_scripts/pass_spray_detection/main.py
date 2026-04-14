"""
PASSWORD SPRAYING DETECTOR — Tuple Key Pattern for Multi-Dimensional Tracking
Security Engineer Coding Practice Problem #15

=====================================================================
REFERENCE NOTES — Tuple Keys, Spraying vs Brute Force, defaultdict(set)
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Password spraying is one of the most common attacks against
    enterprise environments — it's how real breaches start
  - Traditional per-user rate limiting misses it because each user
    only sees 1-2 failures
  - Detection requires tracking failures across TWO dimensions
    simultaneously: source IP AND time window
  - Same tuple key pattern applies to: detecting port scanning
    (ip, port_range), API abuse (api_key, endpoint), data exfil
    (user, destination), lateral movement (source, destination)


SPRAYING vs BRUTE FORCE:
---------------------------
  BRUTE FORCE:
    Same IP → Same user → Many passwords
    Example: 1000 login attempts for "admin" from 203.45.167.22
    Detection: Count failures per (ip, user) — easy to catch

  PASSWORD SPRAYING:
    Same IP → Many users → Few passwords (often just 1-2 common ones)
    Example: Try "Password123" against admin, jsmith, developer, root...
    Detection: Count UNIQUE USERS per (ip, hour) — the key insight

  Why spraying evades basic defenses:
    - Per-user lockout: each user only sees 1-2 failures → no lockout
    - Per-user rate limit: same — too few per user to trigger
    - The attacker distributes attempts across many accounts

  What catches spraying:
    - Per-IP tracking of unique users targeted
    - "Same IP hit 50 different usernames in one hour" → clearly automated


TUPLE KEYS — TWO DIMENSIONS IN ONE DICT:
-------------------------------------------
  Problem: track failures by BOTH ip AND hour simultaneously.

  Approach 1 — Nested dicts (messy):
    data = {}
    if ip not in data:
        data[ip] = {}
    if hour not in data[ip]:
        data[ip][hour] = set()
    data[ip][hour].add(user)
    # Access: data[ip][hour] — two levels of nesting

  Approach 2 — Tuple keys (clean):
    data = defaultdict(set)
    data[(ip, hour)].add(user)
    # Access: data[(ip, hour)] — flat, one level

  Both achieve the same result, but tuple keys are:
    - Less code (no nested initialization)
    - Easier to iterate (one loop, not nested loops)
    - Easier to read (explicit about what you're tracking)

  You can use any hashable values as tuple keys:
    (ip, hour)              → track per IP per hour
    (user, endpoint)        → track per user per endpoint
    (source_ip, dest_ip)    → track lateral movement
    (api_key, date)         → track API usage per day


defaultdict(set) — AUTO-DEDUPLICATING GROUPS:
------------------------------------------------
  defaultdict(set) creates an empty set for new keys automatically.

  data = defaultdict(set)
  data[("203.45.167.22", "10")].add("admin")
  data[("203.45.167.22", "10")].add("jsmith")
  data[("203.45.167.22", "10")].add("admin")    # duplicate — ignored!

  len(data[("203.45.167.22", "10")])  → 2 (admin + jsmith)

  vs defaultdict(list):
  data = defaultdict(list)
  data[("203.45.167.22", "10")].append("admin")
  data[("203.45.167.22", "10")].append("admin")  # duplicate — kept!

  len(data[("203.45.167.22", "10")])  → 2 (admin counted twice!)

  Rule: use set when you need UNIQUE items, list when order/duplicates matter.


COMPROMISE DETECTION PATTERN:
--------------------------------
  Spraying alone is concerning. Spraying followed by a successful login
  is critical — it means the attacker found valid credentials.

  Detection:
    1. Identify spray IPs (many unique failed users)
    2. Check if any of those IPs also had a LOGIN_SUCCESS
    3. Check if the successful user was in the failed set
    4. If all three → account compromised via spraying


ONE-LINE RECALLS:
------------------
  Tuple key:    "(ip, hour) as dict key — track two dimensions in one flat dict"
  set vs list:  "set for unique counts (spraying), list for ordered data (timeline)"
  Spraying:     "Many unique users from one IP = spraying. Many attempts on one user = brute force"
  Compromise:   "Spray IP + successful login + user was in failed set = account compromised"

=====================================================================
"""

from collections import defaultdict


def detect_spraying(logs, unique_user_threshold=3):
    """
    Detect password spraying attacks using (ip, hour) tuple keys.

    Spraying = same IP targets many different users in the same hour.
    Different from brute force where one user gets many attempts.

    Args:
        logs: List of auth log strings
        unique_user_threshold: Min unique users targeted to flag as spraying

    Returns:
        Dict with spray_alerts and compromised_accounts
    """
    # Track unique failed usernames per (ip, hour) — tuple key with set
    failed_by_ip_hour = defaultdict(set)

    # Track all failed users per IP (for compromise detection)
    failed_users_by_ip = defaultdict(set)

    # Track successful logins
    successful_logins = []

    for line in logs:
        parts = line.split()
        timestamp = parts[0] + " " + parts[1]
        hour = parts[1].split(":")[0]
        status = parts[2]
        user = parts[3].split("=")[1]
        ip = parts[4].split("=")[1]

        if status == "LOGIN_FAILED":
            failed_by_ip_hour[(ip, hour)].add(user)
            failed_users_by_ip[ip].add(user)

        elif status == "LOGIN_SUCCESS":
            successful_logins.append({
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
            })

    # Detect spraying: IP targeting many unique users in one hour
    spray_alerts = []
    for (ip, hour), users in failed_by_ip_hour.items():
        if len(users) >= unique_user_threshold:
            spray_alerts.append({
                "ip": ip,
                "hour": hour,
                "unique_users_targeted": len(users),
                "users": sorted(users),
            })

    # Detect compromised accounts: spray IP that also got a success
    compromised = []
    spray_ips = {alert["ip"] for alert in spray_alerts}

    for login in successful_logins:
        if login["ip"] in spray_ips:
            if login["user"] in failed_users_by_ip[login["ip"]]:
                compromised.append(login)

    return {
        "spray_alerts": sorted(spray_alerts, key=lambda x: x["unique_users_targeted"], reverse=True),
        "compromised_accounts": compromised,
    }


if __name__ == "__main__":
    auth_logs = [
        # === 203.45.167.22 — PASSWORD SPRAYING (hour 10) ===
        # Same IP, 5 different users, rapid succession → classic spraying
        # Then succeeds on "root" → account compromised
        "2025-04-09 10:00:05 LOGIN_FAILED user=admin ip=203.45.167.22",
        "2025-04-09 10:00:06 LOGIN_FAILED user=jsmith ip=203.45.167.22",
        "2025-04-09 10:00:07 LOGIN_FAILED user=developer ip=203.45.167.22",
        "2025-04-09 10:00:08 LOGIN_FAILED user=root ip=203.45.167.22",
        "2025-04-09 10:00:09 LOGIN_FAILED user=test ip=203.45.167.22",
        # Second round with same users
        "2025-04-09 10:00:15 LOGIN_FAILED user=admin ip=203.45.167.22",
        "2025-04-09 10:00:16 LOGIN_FAILED user=jsmith ip=203.45.167.22",
        "2025-04-09 10:00:17 LOGIN_FAILED user=developer ip=203.45.167.22",
        "2025-04-09 10:00:18 LOGIN_FAILED user=root ip=203.45.167.22",
        # Attacker cracks root's password
        "2025-04-09 10:00:19 LOGIN_SUCCESS user=root ip=203.45.167.22",

        # === 10.0.0.5 — BRUTE FORCE, NOT SPRAYING ===
        # Same IP, same user (alice), 3 failures → brute force on one account
        # Should NOT be flagged as spraying (only 1 unique user)
        "2025-04-09 10:00:30 LOGIN_FAILED user=alice ip=10.0.0.5",
        "2025-04-09 10:00:31 LOGIN_FAILED user=alice ip=10.0.0.5",
        "2025-04-09 10:00:32 LOGIN_FAILED user=alice ip=10.0.0.5",
        "2025-04-09 10:00:33 LOGIN_SUCCESS user=alice ip=10.0.0.5",

        # === 203.45.167.22 — CONTINUED SPRAYING (hour 11) ===
        # Same attacker IP, new hour, targeting 3 users → still spraying
        "2025-04-09 11:00:05 LOGIN_FAILED user=admin ip=203.45.167.22",
        "2025-04-09 11:00:06 LOGIN_FAILED user=jsmith ip=203.45.167.22",
        "2025-04-09 11:00:07 LOGIN_FAILED user=developer ip=203.45.167.22",

        # === 172.16.0.50 — NORMAL USERS ===
        # Legitimate logins, no failures → completely normal
        "2025-04-09 12:15:00 LOGIN_SUCCESS user=jsmith ip=172.16.0.50",
        "2025-04-09 12:15:05 LOGIN_SUCCESS user=developer ip=172.16.0.50",
    ]

    results = detect_spraying(auth_logs, unique_user_threshold=3)

    print("=== Password Spraying Detection ===\n")

    if results["spray_alerts"]:
        print("SPRAY ALERTS:")
        for alert in results["spray_alerts"]:
            print(f"\n  IP: {alert['ip']} | Hour: {alert['hour']}:00")
            print(f"  Unique users targeted: {alert['unique_users_targeted']}")
            print(f"  Users: {', '.join(alert['users'])}")
    else:
        print("  No spraying detected.")

    print()

    if results["compromised_accounts"]:
        print("COMPROMISED ACCOUNTS (spray IP got a successful login):")
        for account in results["compromised_accounts"]:
            print(f"\n  User: {account['user']}")
            print(f"  IP: {account['ip']}")
            print(f"  Time: {account['timestamp']}")
    else:
        print("  No compromised accounts detected.")

    # Summary
    print("\n=== Summary ===")
    print(f"  Spray alerts: {len(results['spray_alerts'])}")
    print(f"  Compromised accounts: {len(results['compromised_accounts'])}")

    # Expected output:
    # SPRAY ALERTS:
    #   203.45.167.22 hour 10 — 5 unique users (admin, developer, jsmith, root, test)
    #   203.45.167.22 hour 11 — 3 unique users (admin, developer, jsmith)
    #
    # COMPROMISED:
    #   root from 203.45.167.22 at 10:00:19
    #
    # NOT flagged:
    #   10.0.0.5 — only targeted alice (1 user = brute force, not spraying)
    #   172.16.0.50 — only successes, no failures