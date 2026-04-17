"""
SSH AUTH LOG PARSER - Brute Force Attack Analyzer

=====================================================================
REFERENCE NOTES - Non-Capturing Groups, Variable Init, Invalid Users
=====================================================================

NON-CAPTURING GROUPS (?:):
---------------------------
  Regular parentheses () do TWO things:
    1. Group parts of a pattern together (so ? or + applies to all of them)
    2. Capture the matched text into group(1), group(2), etc.

  Sometimes you need #1 but not #2. That's what (?:) does.

  Example: matching "invalid user " as an optional phrase
    (invalid\suser\s)?     → groups AND captures → takes up a group number
    (?:invalid\suser\s)?   → groups but does NOT capture → no group number used

  When to use which:
    (?:...)?  → "this part is optional, I DON'T care about its value"
    (...)?    → "this part is optional, I DO want to check its value"

  In this exercise we REMOVED (?:) and used () instead, because we needed
  to check whether "invalid user" was present to track invalid usernames.
  match.group(2) gives us "invalid user " or None - we use that to decide.


VARIABLE PLACEMENT BUG - THE #1 LOOP MISTAKE:
-----------------------------------------------
  WRONG - lists reset on every iteration:
    for log in logs:
        results = []          # ← created inside loop = reset every time!
        results.append(x)     # only keeps the last iteration's data

  RIGHT - lists persist across all iterations:
    results = []              # ← created OUTSIDE loop = accumulates data
    for log in logs:
        results.append(x)     # keeps everything

  In an interview, catch this by TESTING - "why do I only have 1 result
  when there should be more?" Then check where your lists are initialized.


HANDLING TWO LOG FORMATS WITH ONE REGEX:
------------------------------------------
  The challenge: SSH logs have two formats for failed logins:
    "Failed password for root from 203.45.167.22..."         ← valid user
    "Failed password for invalid user test from 10.0.0.1..." ← invalid user

  The trick: make "invalid user " optional with (invalid\suser\s)?
  
  Pattern: r'(Failed|Accepted)\spassword\sfor\s(invalid\suser\s)?(\w+)\sfrom\s([\d\.]+)'
  
  For "Failed password for root from 203.45.167.22":
    group(1) = "Failed"
    group(2) = None              ← "invalid user" wasn't there
    group(3) = "root"
    group(4) = "203.45.167.22"

  For "Failed password for invalid user test from 10.0.0.1":
    group(1) = "Failed"
    group(2) = "invalid user "   ← it was there, so it's captured
    group(3) = "test"
    group(4) = "10.0.0.1"

  Checking: if is_invalid:  → True when group(2) has a value, False when None


REGEX PATTERN BREAKDOWN:
--------------------------
  r'.*?:\s(Failed|Accepted)\spassword\sfor\s(invalid\suser\s)?(\w+)\sfrom\s([\d\.]+)'

  .*?:\s                    → skip timestamp and hostname, stop at ": "
  (Failed|Accepted)         → CAPTURE group 1: the status
  \spassword\sfor\s         → match literal " password for "
  (invalid\suser\s)?        → CAPTURE group 2: "invalid user " or None (optional)
  (\w+)                     → CAPTURE group 3: the username
  \sfrom\s                  → match literal " from "
  ([\d\.]+)                 → CAPTURE group 4: the IP address
                               [\d\.]+ = one or more digits or dots


NEW REGEX PATTERN - CHARACTER CLASS []:
-----------------------------------------
  [\d\.]    → match a digit OR a dot (character class)
  [\d\.]+   → one or more of (digit or dot) - perfect for IP addresses

  Character classes [] let you define a SET of allowed characters:
    [abc]     → matches a, b, or c
    [0-9]     → matches any digit (same as \d)
    [a-zA-Z]  → matches any letter
    [\d\.]    → matches a digit or a literal dot


ONE-LINE RECALLS:
------------------
  (?:):          "Group without capturing - use when ? needs to apply to multiple words but you don't need the value"
  Loop bug:      "Initialize lists OUTSIDE the loop - inside means reset every iteration"
  Two formats:   "Make the differing part optional with ()? - group is None when absent, has value when present"
  [] class:      "Square brackets define a set of allowed characters - [\d\.]+ matches IP addresses"

=====================================================================
"""

import re
from collections import Counter


def analyze_ssh_logs(log_lines):
    """
    Parse SSH auth log lines and extract security-relevant info.

    Log format:
    Mar 24 10:15:32 webserver sshd[12345]: Failed password for root from 203.45.167.22 port 52413 ssh2
    Mar 24 10:15:34 webserver sshd[12347]: Failed password for invalid user test from 10.0.0.1 port 33021 ssh2
    """
    pattern = r'.*?:\s(Failed|Accepted)\spassword\sfor\s(invalid\suser\s)?(\w+)\sfrom\s([\d\.]+)'
    #               ^group1: status                    ^group2: invalid or None  ^group3: user  ^group4: IP

    failed_ips = []
    failed_usernames = []
    invalid_users = set()

    for line in log_lines:
        match = re.search(pattern, line)
        if not match:
            continue

        status = match.group(1)       # "Failed" or "Accepted"
        is_invalid = match.group(2)   # "invalid user " or None
        user = match.group(3)         # the actual username
        ip = match.group(4)           # IP address

        if status == "Failed":
            failed_ips.append(ip)
            failed_usernames.append(user)

            if is_invalid:
                invalid_users.add(user)

    return {
        "top_attackers": Counter(failed_ips).most_common(3),
        "targeted_users": Counter(failed_usernames).most_common(),
        "invalid_users": sorted(invalid_users),
    }


if __name__ == "__main__":
    with open("ssh_log.txt", "r") as f:
        logs = f.read().splitlines()

    results = analyze_ssh_logs(logs)

    print("=== Top Attackers (IP: failed attempts) ===")
    for ip, count in results["top_attackers"]:
        print(f"  {ip}: {count} attempts")

    print("\n=== Targeted Usernames ===")
    for user, count in results["targeted_users"]:
        print(f"  {user}: {count} attempts")

    print("\n=== Invalid (non-existent) Users Attempted ===")
    for user in results["invalid_users"]:
        print(f"  {user}")