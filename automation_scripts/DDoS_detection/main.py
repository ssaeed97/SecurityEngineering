"""
DDOS DETECTION — Sliding Window Request Rate Analyzer


=====================================================================
REFERENCE NOTES — Sliding Window, defaultdict, datetime, Two Pointers
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Real-time DDoS detection requires efficient counting of requests
    per source within time windows
  - Same pattern applies to: brute force detection, rate limiting,
    anomaly detection, log-based alerting
  - Sliding window is the standard algorithm for any "count events
    within a rolling time period" problem


SLIDING WINDOW — THE CORE TECHNIQUE:
---------------------------------------
  Problem: "How many events from this IP happened in any 10-second span?"

  Naive approach: For each event, scan all other events within 10 seconds.
    → O(n²) — too slow for millions of log entries.

  Sliding window: Sort timestamps, use two pointers (left and right).
    → O(n) per IP — left and right only ever move forward.

  How it works:
    1. Sort timestamps for each IP
    2. right pointer advances one step every iteration (the for loop)
    3. left pointer advances ONLY when the window exceeds the time limit
    4. Count of events in window = right - left + 1

  Why right - left + 1?
    Both endpoints are inclusive. If left=2, right=5:
    Elements in window: index 2, 3, 4, 5 = 4 elements
    Math: 5 - 2 + 1 = 4

  Visual:
    timestamps = [10, 11, 12, 50, 51, 52]
    window = 5 seconds

    right=0: [10]               left=0, count=1
    right=1: [10, 11]           left=0, count=2
    right=2: [10, 11, 12]       left=0, count=3
    right=3: [10, 11, 12, 50]   50-10=40 > 5 → left slides to 3
             [50]               left=3, count=1  ← old burst fell out
    right=4: [50, 51]           left=3, count=2
    right=5: [50, 51, 52]       left=3, count=3


defaultdict(list) — AUTO-CREATING DICT:
-----------------------------------------
  Normal dict crashes if key doesn't exist:
    d = {}
    d["new_key"].append(1)   # → KeyError!

  defaultdict creates the default value automatically:
    from collections import defaultdict
    d = defaultdict(list)
    d["new_key"].append(1)   # → {"new_key": [1]}  no error

  Common defaults:
    defaultdict(list)    → empty list for new keys (grouping)
    defaultdict(int)     → 0 for new keys (counting)
    defaultdict(set)     → empty set for new keys (unique grouping)


datetime.strptime() — PARSING TIMESTAMPS:
--------------------------------------------
  Converts a string timestamp into a datetime object:
    from datetime import datetime
    dt = datetime.strptime("2025-04-09 10:15:32", "%Y-%m-%d %H:%M:%S")

  Common format codes:
    %Y = 4-digit year    %m = month (01-12)    %d = day (01-31)
    %H = hour (00-23)    %M = minute (00-59)   %S = second (00-59)

  .timestamp() converts to Unix seconds (float):
    dt.timestamp()  → 1744186532.0

  Why Unix seconds? Because subtraction gives you seconds directly:
    ts2 - ts1 = difference in seconds as a float


ONE-LINE RECALLS:
------------------
  Sliding window: "Right advances every step, left advances when window
                   is too wide — count is right minus left plus one"
  defaultdict:    "Auto-creates default value for missing keys — list for
                   grouping, int for counting"
  strptime:       "String Parse Time — converts text timestamp to datetime
                   using format codes"
  Complexity:     "O(n) per IP because both pointers only move forward"

=====================================================================
"""

from datetime import datetime
from collections import defaultdict


def detect_ddos(logs, threshold=10, window_seconds=10):
    """
    Detect potential DDoS sources using sliding window analysis.

    For each source IP, checks if any rolling window of window_seconds
    contains more than threshold requests.

    Args:
        logs: List of log strings in format:
              "YYYY-MM-DD HH:MM:SS <IP> <METHOD> <PATH> <STATUS>"
        threshold: Max requests allowed in the window before flagging
        window_seconds: Size of the rolling time window in seconds

    Returns:
        List of (ip, max_request_count) tuples, sorted by count descending
    """
    # Step 1: Parse logs and group timestamps by IP
    ip_timestamps = defaultdict(list)

    for line in logs:
        parts = line.split()
        ip = parts[2]
        timestamp = datetime.strptime(
            parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S"
        ).timestamp()
        ip_timestamps[ip].append(timestamp)

    # Step 2: Sliding window check per IP
    flagged = []

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()
        max_count = 0
        left = 0

        for right in range(len(timestamps)):
            # Shrink window from left if it exceeds window_seconds
            while timestamps[right] - timestamps[left] > window_seconds:
                left += 1

            # Current window size (inclusive of both endpoints)
            count = right - left + 1
            max_count = max(max_count, count)

        if max_count >= threshold:
            flagged.append((ip, max_count))

    return sorted(flagged, key=lambda x: x[1], reverse=True)


if __name__ == "__main__":
    logs = [
        # === 192.168.1.100 — DDoS attacker: 15 requests in ~8 seconds ===
        # Should be FLAGGED (exceeds threshold of 10 in a 10-second window)
        "2025-04-09 10:15:32 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:32 192.168.1.100 GET /api/products 200",
        "2025-04-09 10:15:33 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:33 192.168.1.100 POST /api/login 401",
        "2025-04-09 10:15:34 192.168.1.100 GET /api/orders 200",
        "2025-04-09 10:15:34 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:34 192.168.1.100 GET /api/products 200",
        "2025-04-09 10:15:35 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:35 192.168.1.100 GET /api/orders 200",
        "2025-04-09 10:15:36 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:37 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:37 192.168.1.100 POST /api/login 401",
        "2025-04-09 10:15:38 192.168.1.100 GET /api/login 200",
        "2025-04-09 10:15:39 192.168.1.100 GET /api/users 200",
        "2025-04-09 10:15:40 192.168.1.100 GET /api/users 200",

        # === 10.0.0.5 — Two bursts, but NOT within 10 seconds of each other ===
        # Burst 1: 6 requests at 10:15:33-10:15:36
        # Burst 2: 5 requests at 10:16:00-10:16:03
        # Gap between bursts is 24 seconds — neither burst alone exceeds threshold
        # Should NOT be flagged
        "2025-04-09 10:15:33 10.0.0.5 GET /index.html 200",
        "2025-04-09 10:15:33 10.0.0.5 GET /about 200",
        "2025-04-09 10:15:34 10.0.0.5 GET /contact 200",
        "2025-04-09 10:15:35 10.0.0.5 GET /products 200",
        "2025-04-09 10:15:35 10.0.0.5 GET /faq 200",
        "2025-04-09 10:15:36 10.0.0.5 GET /home 200",
        "2025-04-09 10:16:00 10.0.0.5 GET /index.html 200",
        "2025-04-09 10:16:01 10.0.0.5 GET /about 200",
        "2025-04-09 10:16:02 10.0.0.5 GET /products 200",
        "2025-04-09 10:16:02 10.0.0.5 GET /contact 200",
        "2025-04-09 10:16:03 10.0.0.5 GET /faq 200",

        # === 172.16.0.50 — Normal user: low volume, no bursts ===
        # 4 requests spread across 30 seconds — well under threshold
        # Should NOT be flagged
        "2025-04-09 10:15:34 172.16.0.50 GET /about 200",
        "2025-04-09 10:15:42 172.16.0.50 GET /products 200",
        "2025-04-09 10:15:50 172.16.0.50 GET /contact 200",
        "2025-04-09 10:16:05 172.16.0.50 GET /home 200",

        # === 203.45.167.22 — Brute forcer: 12 requests in 6 seconds ===
        # All hitting the login endpoint with 401s — classic brute force pattern
        # Should be FLAGGED (exceeds threshold of 10 in a 10-second window)
        "2025-04-09 10:20:00 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:00 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:01 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:01 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:02 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:02 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:03 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:03 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:04 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:05 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:05 203.45.167.22 POST /api/login 401",
        "2025-04-09 10:20:06 203.45.167.22 POST /api/login 200",
    ]

    print("=== DDoS Detection Results ===")
    print(f"Threshold: {10} requests in {10} second window\n")

    results = detect_ddos(logs, threshold=10, window_seconds=10)

    if results:
        print("FLAGGED IPs:")
        for ip, count in results:
            print(f"  {ip}: {count} requests in window")
    else:
        print("  No IPs exceeded threshold")

    # Show all IPs and their max window counts for reference
    print("\n=== All IPs Summary ===")
    all_results = detect_ddos(logs, threshold=0, window_seconds=10)
    for ip, count in all_results:
        status = "FLAGGED" if count >= 10 else "OK"
        print(f"  {ip}: max {count} requests in any 10s window [{status}]")