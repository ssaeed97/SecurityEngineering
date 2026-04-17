# Security Engineer — Coding Prep

![Python](https://img.shields.io/badge/Language-Python-3776AB?logo=python&logoColor=white)
![Log Analysis](https://img.shields.io/badge/Security-Log%20Analysis-red)
![Regex](https://img.shields.io/badge/Tool-Regex-blue)
![Networking](https://img.shields.io/badge/Tool-Socket%20%7C%20Port%20Scanning-2496ED)
![Cryptography](https://img.shields.io/badge/Topic-Cryptography-7B42BC)
![AppSec](https://img.shields.io/badge/Topic-AppSec%20%7C%20IDOR%20%7C%20JWT-orange)

Practice problems for **SE-level coding**.

## What This Is

Hands-on coding prep for day-to-day security engineering tasks. Each folder contains a security-themed Python problem, the solution, and reference notes on the concepts used.

The coding bar for SE is **not LeetCode** — it's practical scripting: parsing logs, detecting attacks, analyzing data, automating security tasks. These problems target exactly that.

---

## Problems

| # | Folder | Problem | Key Concepts |
|---|--------|---------|--------------|
| 1 | `apache_log_rate_analyzer/` | Parse Apache logs, detect IPs exceeding a request rate threshold within a sliding time window | Sliding window (two pointers), `datetime.strptime()`, `defaultdict(list)`, rate-based detection |
| 2 | `api_requests/` | Query a threat intelligence API for IP reputation, handle failures gracefully, batch-process multiple IPs | `requests`, `unittest`, `@patch` mocking, `.get()` safe access, HTTP error handling |
| 3 | `balanced_brackets/` | Validate that brackets, braces, and parentheses are balanced in config files and policy definitions | Stack (LIFO), opener/closer matching, position-aware error reporting |
| 4 | `caesar_cipher/` | Encrypt and decrypt text using the Caesar cipher; handle wrap-around and both cases | `ord()`/`chr()`, modular arithmetic (`% 26`), `isalpha()`/`islower()`/`isupper()` |
| 5 | `cloudtrail_log_analyzer/` | Analyze AWS CloudTrail logs for account compromise indicators across three detection tiers | Tiered detection (always-bad → parameter-based → aggregate), `defaultdict`, `Counter`, nested JSON `.get()` |
| 6 | `common_words/` | Count word frequency in text with progressive cleaning: raw, normalized, and stop-word filtered | `Counter`, `re.sub()` for punctuation stripping, stop word sets with O(1) lookup, `.split()` on whitespace |
| 7 | `DDoS_detection/` | Detect DDoS attacks by flagging IPs exceeding request thresholds in time windows | Sliding window, timestamp parsing, `defaultdict(list)`, threshold-based flagging |
| 8 | `firewall_conflict/` | Parse firewall rules and detect conflicting ALLOW/DENY entries on the same port and direction | `defaultdict(list)` grouping by `(direction, protocol, port)`, contradiction detection, dangerous port exposure checks |
| 9 | `IDOR_exploit/` | Enumerate a vulnerable API endpoint by iterating sequential user IDs to expose PII and admin accounts | `requests`, sequential ID enumeration, `.get()` safe dict access, rate limiting awareness |
| 10 | `jwt_decoder/` | Decode and analyze JWTs for security issues: `alg:none` attacks, missing signatures, expired tokens, admin role abuse | Base64 decoding, JSON parsing, Unix timestamp comparison, `time.time()`, alert tiering |
| 11 | `log_correlation/` | Correlate auth logs with access logs by IP to detect failed → success → admin access compromise chains | Hashmap indexing O(n+m) vs nested loops O(n×m), `defaultdict(list)`, parse-once pattern |
| 12 | `log_deny_count/` | Parse firewall logs, count DENY entries per source IP, return the top N offenders | `Counter`, `.get(key, default)`, `sorted()` with `lambda`, data structure selection |
| 13 | `merge_overlap/` | Merge overlapping time intervals from vulnerability scans and detect coverage gaps | Sort by start + merge pattern, `lambda` in `key=`, `max()` for range extension, O(n log n) |
| 14 | `nearest_element/` | Find the nearest value in a sorted list to a given target using binary search | Binary search, two-pointer boundary logic, `bisect` module, O(log n) |
| 15 | `pass_spray_detection/` | Detect password spraying (one IP, many users) vs brute force (many attempts, one user); flag compromised accounts | Tuple key `(ip, hour)` with `defaultdict(set)`, spraying vs brute force distinction, compromise correlation |
| 16 | `port_scan_detector/` | Detect port scanning from connection logs by flagging source IPs contacting too many unique ports on one destination | Tuple key `(src_ip, dst_ip)` → `set` of ports, `f.read().splitlines()`, `defaultdict` vs manual init |
| 17 | `port_scanner/` | TCP port scanner using raw sockets; scan a range of ports on a target host | `socket.socket()`, `connect_ex()`, `settimeout()`, `argparse`, `finally` for cleanup, `KeyboardInterrupt` |
| 18 | `regex_apache_logs/` | Parse Apache access logs with regex to extract failed logins, directory traversal paths, and non-browser agents | `re.search()`, capture groups `()`, lazy `.*?` vs greedy `.*`, `set` for unique values |
| 19 | `regex_ssh_auth_log/` | Parse SSH auth logs across two log formats to identify brute-force attackers, targeted usernames, and invalid users | Non-capturing groups `(?:)`, optional groups `()?`, character classes `[\d\.]`, variable init outside loops |
| 20 | `string_addition/` | Add two large integers represented as strings digit-by-digit without converting to int | Two pointers from right, carry logic (`// 10`, `% 10`), integer overflow context |
| 21 | `url_categorizer/` | Parse and categorize URLs for threats: open redirects, Base64-encoded params, SSRF indicators, C2 beacons | `urlparse`, `parse_qs`, Base64 detection regex, open redirect patterns, SSRF indicators |

---

## How to Use This

1. Read the problem description in the folder's `main.py` header
2. Attempt a solution before looking at the answer
3. Compare with the reference solution
4. Study the reference notes at the top of each file for concept refreshers

---

## Contributing

This is a living reference. Contributions, corrections, and new problems are welcome via pull request.

## License

MIT License — see the [LICENSE](../LICENSE) file for details.