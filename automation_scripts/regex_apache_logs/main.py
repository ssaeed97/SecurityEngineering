"""
REGEX LOG PARSER - Apache Access Log Analyzer

=====================================================================
REFERENCE NOTES - Regex Patterns, Skipping, Capture Groups
=====================================================================

REGEX CHEAT SHEET - EVERY PATTERN USED IN THIS EXERCISE:
----------------------------------------------------------

  MATCHING CHARACTERS:
    \d        → one digit (0-9)
    \d+       → one or more digits
    \d{3}     → exactly 3 digits (we used this for status codes like 401)
    \w        → one "word" character (letter, digit, or underscore)
    \w+       → one or more word characters (we used this for HTTP methods: GET, POST)
    \s        → one whitespace character (space, tab, newline)
    \S        → one NON-whitespace character
    \S*       → zero or more non-whitespace characters
    .         → any single character EXCEPT newline
    \.        → a literal dot (backslash "escapes" the special meaning)

  QUANTIFIERS (how many times to match):
    +         → one or more        (greedy - grabs as much as possible)
    *         → zero or more       (greedy)
    ?         → zero or one        (makes something optional)
    +?        → one or more        (lazy - grabs as LITTLE as possible)
    *?        → zero or more       (lazy)
    {3}       → exactly 3 times
    {1,3}     → between 1 and 3 times

  ANCHORS:
    ^         → start of string
    $         → end of string

  SPECIAL SEQUENCES:
    .*        → match anything, as much as possible (greedy)
    .*?       → match anything, as LITTLE as possible (lazy)
    ".*?"     → match everything between two quotes (lazy stops at first closing quote)
    ".*"      → match everything between FIRST opening and LAST closing quote (greedy - usually wrong!)


THE ? IN REGEX - IT HAS TWO MEANINGS:
---------------------------------------

  MEANING 1: "Optional" (after a character or group)
    colou?r       → matches "color" OR "colour" (the u is optional)
    https?://     → matches "http://" OR "https://" (the s is optional)

  MEANING 2: "Lazy/non-greedy" (after a quantifier like * or +)
    .*?           → match as LITTLE as possible
    .+?           → match one or more, but as FEW as possible

    This is the one we used. The difference:
      ".*"   on   '"hello" and "world"'   → matches '"hello" and "world"' (greedy: first " to LAST ")
      ".*?"  on   '"hello" and "world"'   → matches '"hello"'             (lazy: first " to NEXT ")


HOW REGEX "SKIPPING" WORKS:
-----------------------------
  Regex doesn't have a "skip" command. Instead, we MATCH the parts we
  don't care about WITHOUT capturing them, and we CAPTURE the parts we
  want using parentheses ().

  Think of it like a read head moving across the string:

  Log line:
  203.45.167.22 - - [24/Mar/2025:10:15:32 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"

  Pattern breakdown:
  ┌──────────────────────────┐
  │ (\d+\.\d+\.\d+\.\d+)    │  ← CAPTURE group 1: the IP address
  │                          │     \d+ = one or more digits
  │                          │     \.  = literal dot
  │                          │     Result: "203.45.167.22"
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ .*?                      │  ← SKIP: match as little as possible until the next part fits
  │                          │     This eats: ' - - [24/Mar/2025:10:15:32 +0000] '
  │                          │     We don't care about this data, so no parentheses = no capture
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ "(\w+)                   │  ← Match a literal quote, then CAPTURE group 2: the HTTP method
  │                          │     \w+ = one or more word chars
  │                          │     Result: "GET"
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \s(\/\S*)                │  ← Match a space, then CAPTURE group 3: the path
  │                          │     \/ = literal forward slash
  │                          │     \S* = zero or more non-whitespace
  │                          │     Result: "/admin/login"
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \sHTTP.*?"               │  ← SKIP: match ' HTTP/1.1"'
  │                          │     Matches the HTTP version and the closing quote
  │                          │     No parentheses = not captured
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \s(\d{3})                │  ← Match a space, then CAPTURE group 4: status code
  │                          │     \d{3} = exactly 3 digits
  │                          │     Result: "401"
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \s\d+                    │  ← SKIP: match the byte count (e.g., " 512")
  │                          │     No parentheses = not captured
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \s".*?"                  │  ← SKIP: match the referer field (e.g., ' "-"')
  │                          │     ".*?" = everything between quotes (lazy)
  │                          │     No parentheses = not captured
  └──────────────────────────┘
  ┌──────────────────────────┐
  │ \s"(.*?)"                │  ← Match ' "', then CAPTURE group 5: user agent, then '"'
  │                          │     .*? = anything, lazy (stops at the closing quote)
  │                          │     Result: "Mozilla/5.0"
  └──────────────────────────┘

  THE RULE:   parentheses () = CAPTURE it (I want this data)
              no parentheses = SKIP it (just move past it)


CAPTURE GROUPS - HOW TO ACCESS THEM:
--------------------------------------
  match = re.search(pattern, line)
  match.group(0)   → the ENTIRE match (everything the pattern touched)
  match.group(1)   → first set of parentheses  (IP)
  match.group(2)   → second set of parentheses (method)
  match.group(3)   → third set of parentheses  (path)
  match.group(4)   → fourth set of parentheses (status code)
  match.group(5)   → fifth set of parentheses  (user agent)


re.search() vs re.findall():
------------------------------
  re.search(pattern, string)
    → finds FIRST match, returns a match object with .group()
    → use for: structured parsing where you extract multiple fields from one line
    → returns None if no match (always check: if not match: continue)

  re.findall(pattern, string)
    → finds ALL matches, returns a list of strings
    → use for: finding every occurrence of a simple pattern
    → if pattern has capture groups, returns only the captured parts
    → returns empty list [] if no match


SET vs LIST:
--------------
  list  → allows duplicates, preserves order. Use .append() to add.
  set   → NO duplicates, unordered. Use .add() to add.

  When problem says "unique", think set immediately.


ONE-LINE RECALLS:
------------------
  Regex skipping:  "Parentheses capture, no parentheses skip - .*? eats what you don't need"
  ? after *:       ".*? is lazy (match as little as possible), .* is greedy (match as much as possible)"
  ? after char:    "s? means s is optional"
  Capture groups:  "re.search() + group(1), group(2)... to extract structured fields"
  set:             "Use set() when the problem says 'unique' - .add() deduplicates automatically"

=====================================================================
"""

import re
from collections import Counter


def analyze_logs(log_lines):
    """
    Parse Apache Combined Log Format and extract security-relevant info.

    Log format:
    IP - user [timestamp] "METHOD /path HTTP/ver" STATUS bytes "referer" "user-agent"
    """
    # This one regex extracts all the fields we need in one pass
    # Each set of parentheses () is a capture group
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s(\/\S*)\sHTTP.*?"\s(\d{3})\s\d+\s".*?"\s"(.*?)"'
    #           ^group 1: IP          ^g2:method ^g3:path          ^g4:status   ^g5:user-agent

    failed_login_ips = []
    suspicious_paths = []
    non_browser_agents = set()  # set = unique only

    for line in log_lines:
        match = re.search(pattern, line)
        if not match:
            continue

        ip = match.group(1)
        method = match.group(2)
        path = match.group(3)
        status = match.group(4)
        user_agent = match.group(5)

        # Check for failed auth
        if status == "401":
            failed_login_ips.append(ip)

        # Check for directory traversal
        if ".." in path:
            suspicious_paths.append(path)

        # Check for non-browser user agents
        if "Mozilla" not in user_agent:
            non_browser_agents.add(user_agent)  # .add() for sets

    return {
        "failed_logins": Counter(failed_login_ips).most_common(),
        "suspicious_paths": suspicious_paths,
        "non_browser_agents": list(non_browser_agents),
    }


if __name__ == "__main__":
    with open("raw_log.txt", "r") as f:
        logs = f.read().splitlines()

    results = analyze_logs(logs)

    print("=== Failed Logins (IP: count) ===")
    for ip, count in results["failed_logins"]:
        print(f"  {ip}: {count} attempts")

    print("\n=== Suspicious Paths (directory traversal) ===")
    for path in results["suspicious_paths"]:
        print(f"  {path}")

    print("\n=== Non-Browser User Agents ===")
    for agent in results["non_browser_agents"]:
        print(f"  {agent}")