"""
APACHE LOG RATE ANALYZER — Sliding Window IP Rate Detection

=====================================================================
REFERENCE NOTES — Apache Log Parsing, Sliding Window, Timestamp Math
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Apache/Nginx access logs are the first thing you check during
    a suspected DDoS, brute force, or web scraping incident
  - Identifying IPs that exceed a request threshold within a time
    window is the foundation of rate limiting and WAF rules
  - Same technique used in: building fail2ban-style tools, writing
    SIEM correlation rules, investigating suspicious traffic spikes


APACHE COMBINED LOG FORMAT:
------------------------------
  203.45.167.22 - - [24/Mar/2025:10:15:32 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
  │               │  │                              │                          │    │    │    │
  IP           user  timestamp                      request                  status bytes ref  user-agent

  Parsing the timestamp:
    log.split()[3]  → "[24/Mar/2025:10:15:32"
    
    datetime.strptime("[24/Mar/2025:10:15:32", "[%d/%b/%Y:%H:%M:%S")
    
    Format codes:
      %d  = day (24)
      %b  = abbreviated month (Mar)
      %Y  = 4-digit year (2025)
      %H  = hour (10)
      %M  = minute (15)
      %S  = second (32)


SLIDING WINDOW RECAP:
-----------------------
  1. Group timestamps by IP using defaultdict(list)
  2. Sort each IP's timestamps
  3. Two pointers: right advances every step, left advances when
     window exceeds the time limit
  4. Count = right - left + 1 (inclusive)
  5. If count >= threshold → flag the IP


ONE-LINE RECALLS:
------------------
  Apache timestamp:  "split()[3] then strptime with [%d/%b/%Y:%H:%M:%S"
  Sliding window:    "Sort, two pointers, right always advances, left
                      advances when window too wide, count = right-left+1"
  defaultdict(list): "Auto-creates empty list for new keys — perfect
                      for grouping timestamps by IP"

=====================================================================
"""

from collections import defaultdict
from datetime import datetime


def parse_apache_timestamp(raw_timestamp):
    """
    Parse Apache log timestamp into Unix seconds.
    
    Input:  "[24/Mar/2025:10:15:32"
    Output: float (Unix timestamp)
    """
    return datetime.strptime(raw_timestamp, "[%d/%b/%Y:%H:%M:%S").timestamp()


def detect_high_rate_ips(logs, threshold=10, window_seconds=10):
    """
    Detect IPs exceeding a request threshold within a sliding time window.
    
    Uses the sliding window algorithm:
      1. Group timestamps by IP
      2. Sort each IP's timestamps
      3. Slide a window of window_seconds across the sorted timestamps
      4. If any window contains >= threshold requests, flag the IP

    Args:
        logs: List of Apache Combined Log Format strings
        threshold: Max requests allowed in the window before flagging
        window_seconds: Size of the rolling time window in seconds

    Returns:
        List of (ip, max_request_count) tuples, sorted by count descending
    """
    # Step 1: Group timestamps by IP
    ip_timestamps = defaultdict(list)

    for line in logs:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        ip = parts[0]
        raw_timestamp = parts[3]
        timestamp = parse_apache_timestamp(raw_timestamp)
        ip_timestamps[ip].append(timestamp)

    # Step 2: Sliding window check per IP
    flagged = []

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()
        left = 0
        max_count = 0

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


def analyze_logs(filepath, threshold=10, window_seconds=10):
    """
    Full analysis pipeline: read file, detect high-rate IPs, print report.
    """
    with open(filepath, "r") as f:
        logs = f.readlines()

    flagged = detect_high_rate_ips(logs, threshold, window_seconds)

    # Build summary of all IPs
    ip_counts = defaultdict(int)
    for line in logs:
        line = line.strip()
        if not line:
            continue
        ip_counts[line.split()[0]] += 1

    return {
        "total_lines": len([l for l in logs if l.strip()]),
        "unique_ips": len(ip_counts),
        "flagged": flagged,
        "all_ip_counts": dict(ip_counts),
    }


if __name__ == "__main__":
    # Inline test data covering multiple scenarios
    test_logs = [
        # === 203.45.167.22 — HIGH RATE: 14 requests in ~7 seconds ===
        # Hammering /admin/login — classic brute force pattern
        '203.45.167.22 - - [24/Mar/2025:10:15:32 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:33 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:34 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:35 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:35 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:36 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:36 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:36 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:37 +0000] "POST /admin/login HTTP/1.1" 200 1536 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:38 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:39 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:39 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:39 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '203.45.167.22 - - [24/Mar/2025:10:15:39 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',

        # === 10.0.0.1 — SUSPICIOUS BUT BELOW THRESHOLD ===
        # Directory traversal attempts — only 2 requests
        '10.0.0.1 - - [24/Mar/2025:10:15:34 +0000] "GET /../../etc/passwd HTTP/1.1" 403 256 "-" "python-requests/2.28"',
        '10.0.0.1 - - [24/Mar/2025:10:15:38 +0000] "GET /api/../../../etc/shadow HTTP/1.1" 403 256 "-" "python-requests/2.28"',

        # === 192.168.1.50 — NORMAL USER ===
        # Single legitimate API request
        '192.168.1.50 - admin [24/Mar/2025:10:15:33 +0000] "POST /api/users HTTP/1.1" 200 1024 "https://example.com" "curl/7.68.0"',

        # === 172.16.0.100 — NORMAL USER ===
        # Single page view
        '172.16.0.100 - - [24/Mar/2025:10:15:36 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    ]

    print("=== Apache Log Rate Analysis ===")
    print(f"Threshold: {10} requests in {10} second window\n")

    flagged = detect_high_rate_ips(test_logs, threshold=10, window_seconds=10)

    if flagged:
        print("FLAGGED IPs:")
        for ip, count in flagged:
            print(f"  {ip}: {count} requests in window")
    else:
        print("  No IPs exceeded threshold.")

    # Show all IPs for context
    print("\nAll IPs Summary:")
    all_results = detect_high_rate_ips(test_logs, threshold=0, window_seconds=10)
    for ip, count in all_results:
        status = "FLAGGED" if count >= 10 else "OK"
        print(f"  {ip}: max {count} requests in any 10s window [{status}]")

    # Expected output:
    # FLAGGED: 203.45.167.22 — 14 requests in window (brute force)
    #
    # NOT flagged:
    #   10.0.0.1     — 2 requests (suspicious content but low volume)
    #   192.168.1.50 — 1 request (normal user)
    #   172.16.0.100 — 1 request (normal user)