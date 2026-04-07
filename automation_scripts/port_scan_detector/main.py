"""
PORT SCAN DETECTOR — Network Log Analyzer
Security Engineer Practice Problem

=====================================================================
THE PROBLEM
=====================================================================

You are given a log file of network connections. Each line contains:

    source_addr:source_port -> dest_addr:dest_port

Example:
    192.168.1.10:44312 -> 10.0.0.5:22
    192.168.1.10:44313 -> 10.0.0.5:80
    10.10.10.10:60001 -> 10.0.0.5:22
    10.10.10.10:60002 -> 10.0.0.5:23
    10.10.10.10:60003 -> 10.0.0.5:25
    10.10.10.10:60004 -> 10.0.0.5:80

Write a function that detects port scanning. A source IP should be
flagged if it connects to MORE THAN 3 unique destination ports on
a SPECIFIC destination IP.

In the example above:
  - 192.168.1.10 hit 2 unique ports on 10.0.0.5 → NOT flagged
  - 10.10.10.10 hit 4 unique ports on 10.0.0.5  → FLAGGED

Output the flagged source IPs.

=====================================================================
REFERENCE NOTES — Tuple Keys, Sets, Tracking Pairs
=====================================================================

CLARIFYING QUESTIONS TO ASK (and design choices based on answers):
-------------------------------------------------------------------

  ABOUT THE DATA:

  Q: "How big is the file?"
     → Small (hourly rotation): f.read().splitlines() — load all into memory
     → Huge (days of logs):     for line in f: — process line by line

  Q: "Is the log format consistent, or could there be malformed lines?"
     → Consistent:   split() directly, no validation needed
     → Could be messy: wrap parsing in try/except, skip bad lines with continue or use regex for more robust parsing

  Q: "Are IPs always IPv4, or could there be IPv6?"
     → IPv4 only:  split(":")[0] works (one colon separating IP and port)
     → IPv6 too:   need rsplit(":", 1) because IPv6 has multiple colons
                    e.g., "2001:db8::1:8080" → rsplit(":", 1) gives ["2001:db8::1", "8080"]

  Q: "Could there be duplicate entries — same connection logged twice?"
     → Yes: set() already handles this — duplicates are ignored automatically
     → No:  set() still works, just no duplicates to filter

  ABOUT THE DETECTION LOGIC:

  Q: "Is the threshold strictly greater than 3, or 3 and above?"
     → Greater than 3:     if len(ports) > threshold
     → 3 and above:        if len(ports) >= threshold
     Always clarify — off-by-one errors lose you points

  Q: "Do we care about time windows — 3 ports in 1 minute vs 24 hours?"
     → No time window:  simple dict tracking (current solution)
     → Yes time window: store timestamps with each port, filter by window
                        e.g., tracker[pair] = [(port, timestamp), ...]
                        then count unique ports within the last N minutes
     This is a STRONG question — shows you understand that 3 ports over
     24 hours is normal, but 3 ports in 10 seconds is a scan.

  Q: "Should I flag just the source IP, or also report the destination and ports?"
     → Just source IP:  return a list of IPs
     → Full context:    return (src_ip, dst_ip, port_count, list_of_ports)
     More context = more useful for incident response

  ABOUT THE ENVIRONMENT:

  Q: "Is this a one-time analysis or processing a live stream?"
     → One-time:   read file, process, output results (current solution)
     → Live stream: need a sliding window, periodic cleanup of old data,
                    possibly using a queue or time-bucketed dict

  Q: "What should happen with the output — print, file, or alert?"
     → Print:  current solution
     → File:   write results to output file
     → Alert:  integrate with SIEM/alerting system


INITIALIZING BLANK DATA STRUCTURES:
--------------------------------------
  my_list  = []        ordered, duplicates allowed, use .append()
  my_dict  = {}        key-value pairs, use d[key] = value
  my_set   = set()     unordered, no duplicates, use .add()
                       NOTE: {} creates a dict, NOT a set!
  my_tuple = ()        immutable list, can be used as a dict key


TUPLES AS DICT KEYS:
----------------------
  Dict keys must be IMMUTABLE (can't change after creation).
    tuple  → immutable → CAN be a key     ✅
    list   → mutable   → CANNOT be a key  ❌
    set    → mutable   → CANNOT be a key  ❌
    string → immutable → CAN be a key     ✅
    int    → immutable → CAN be a key     ✅

  This lets us track data per PAIR:
    tracker = {}
    pair = (src_ip, dst_ip)          # tuple of two values
    tracker[pair] = set()            # maps the pair to a set of ports

  This is the key insight for this problem: we need to count unique
  ports per (source, destination) combination, not just per source.


WHY WE TRACK PER (SRC, DST) PAIR:
------------------------------------
  If source 192.168.1.10 connects to:
    10.0.0.5:22, 10.0.0.5:80         → 2 ports on 10.0.0.5
    10.0.0.6:443, 10.0.0.6:80        → 2 ports on 10.0.0.6

  Total unique ports = 4, but per-destination it's only 2 each.
  That's NOT port scanning — it's normal traffic to two servers.

  But if 10.10.10.10 connects to:
    10.0.0.5:22, 10.0.0.5:23, 10.0.0.5:25, 10.0.0.5:80, 10.0.0.5:443

  That's 5 unique ports on ONE destination = port scanning.


FILE READING METHODS:
-----------------------
  # METHOD 1: read() → entire file as ONE string
  content = f.read()                    # "line one\nline two\nline three\n"

  # METHOD 2: read().splitlines() → list of lines, NO \n  ← USE THIS
  lines = f.read().splitlines()         # ["line one", "line two", "line three"]

  # METHOD 3: readlines() → list of lines, WITH \n
  lines = f.readlines()                 # ["line one\n", "line two\n", "line three\n"]

  # METHOD 4: loop line by line → memory efficient for huge files
  for line in f:                        # "line one\n" then "line two\n" ...
      line = line.strip()               # need .strip() to remove \n

  DEFAULT TO: f.read().splitlines() — cleanest, no \n to deal with.

  ALWAYS use "with open()" — it auto-closes the file even if an error occurs:
    with open("file.txt", "r") as f:    # "r" = read, "w" = write, "a" = append
        lines = f.read().splitlines()


SET FOR UNIQUE COUNTING:
--------------------------
  set.add(value) automatically deduplicates.
  If the same port appears multiple times, the set only stores it once.
  len(my_set) gives you the count of unique values.


ONE-LINE RECALLS:
------------------
  Tuple as key:  "Tuples are immutable so they can be dict keys — use (src, dst) to track pairs"
  set():         "set() for blank set, NOT {} — that's a dict"
  This problem:  "Track unique dst_ports per (src_ip, dst_ip) pair, flag if count > threshold"

=====================================================================
"""


def detect_port_scanning(log_lines, threshold=3):
    """Detect source IPs scanning multiple unique ports on a specific destination.

    Args:
        log_lines: list of strings in format "src_ip:src_port -> dst_ip:dst_port"
        threshold: flag if unique destination ports exceed this number

    Returns:
        list of (src_ip, dst_ip, port_count) tuples for flagged pairs
    """
    # Key: (src_ip, dst_ip) → Value: set of unique dst_ports
    scan_tracker = {}

    for line in log_lines:
        parts = line.strip().split(" -> ")
        src_ip = parts[0].split(":")[0]
        dst_ip = parts[1].split(":")[0]
        dst_port = parts[1].split(":")[1]

        pair = (src_ip, dst_ip)
        if pair not in scan_tracker:
            scan_tracker[pair] = set()
        scan_tracker[pair].add(dst_port)

    flagged = []
    for (src_ip, dst_ip), ports in scan_tracker.items():
        if len(ports) > threshold:
            flagged.append((src_ip, dst_ip, len(ports)))

    return flagged


if __name__ == "__main__":
    with open("connections.log", "r") as f:
        logs = f.read().splitlines()

    flagged = detect_port_scanning(logs)
    for src_ip, dst_ip, count in flagged:
        print(f"ALERT: {src_ip} scanned {count} unique ports on {dst_ip}")