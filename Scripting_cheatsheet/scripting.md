# Python Scripting Cheat Sheet — Security Engineer Coding Problems

> Quick reference for solving coding problems in Security Engineering. Follow: Input → Parse → Process → Output. When stuck, find your problem type below and use the pattern.

---

## Table of Contents

- [Problem-Solving Framework](#problem-solving-framework)
- [Data Structures — When to Use What](#data-structures--when-to-use-what)
- [Pattern Library — Find Your Problem Type](#pattern-library--find-your-problem-type)
- [Parsing Techniques](#parsing-techniques)
- [Python Built-ins You Need](#python-built-ins-you-need)
- [Common Gotchas](#common-gotchas)
- [One-Liner Recalls](#one-liner-recalls)

---

## Problem-Solving Framework

For every coding problem, answer these four questions in order:

```
1. INPUT    → What am I reading? (file, list, string, API response, JSON)
2. PARSE    → How do I break it into usable pieces? (split, regex, json.loads, urlparse)
3. PROCESS  → What do I do with each piece? (count, compare, group, flag, search)
4. OUTPUT   → What do I return? (list, dict, count, boolean, sorted results)
```

**Then pick the data structure:**

```
"Find the most common X"          → Counter
"Find unique X"                   → set
"Group items by category"         → defaultdict(list) or defaultdict(set)
"Track two dimensions at once"    → defaultdict with tuple key
"Check membership fast"           → set (for values) or dict (for key-value)
"Keep items in order"             → list
"Match openers to closers"        → stack (list with append/pop)
"Search sorted data efficiently"  → binary search (two pointers)
"Find overlapping ranges"         → sort + merge adjacent
"Count events in time windows"    → sliding window (two pointers on sorted data)
```

---

## Data Structures — When to Use What

### list — Ordered, Allows Duplicates

```python
items = []
items.append("event")       # add to end
items[0]                     # access by index
items[-1]                    # last item
len(items)                   # count
items.sort()                 # sort in place (modifies original)
sorted(items)                # new sorted list (original unchanged)
```

**Use when:** order matters, collecting results, building output.

### dict — Key-Value Pairs, O(1) Lookup

```python
data = {}
data["ip"] = "10.0.0.1"                 # set value
data.get("ip", "unknown")               # safe lookup with default
data.get("missing_key")                 # returns None, no crash
(data.get("nested") or {}).get("key")   # safe nested lookup

for key, value in data.items():          # iterate both
for key in data:                         # iterate keys only
```

**Use when:** need fast lookup by key, building structured records.
**Critical:** `.get(key, default)` is safe. `data[key]` crashes on missing keys.

### set — Unique Items, O(1) Membership Check

```python
seen = set()
seen.add("admin")           # add item (duplicates ignored)
"admin" in seen              # O(1) check — instant
len(seen)                    # count of unique items

# Set operations
a - b                        # difference: in a but not b
a & b                        # intersection: in both
a | b                        # union: everything
```

**Use when:** need unique items, fast membership checking, comparing groups.

### Counter — Count Occurrences, Get Top N

```python
from collections import Counter

counts = Counter(["a", "b", "a", "a", "b"])
# Counter({"a": 3, "b": 2})

counts.most_common(3)        # top 3 as [(item, count), ...]
counts["a"]                  # access count directly: 3
```

**Use when:** "find the most common X", "count occurrences", "rank by frequency".

### defaultdict — Auto-Creating Values

```python
from collections import defaultdict

# Auto-create empty list for new keys (grouping)
groups = defaultdict(list)
groups["admin"].append("event1")     # no KeyError on new key

# Auto-create empty set for new keys (unique grouping)
unique = defaultdict(set)
unique["admin"].add("ip1")           # duplicates auto-ignored

# Auto-create 0 for new keys (counting)
counts = defaultdict(int)
counts["admin"] += 1                 # starts at 0, no KeyError
```

**Use when:** grouping items by category, counting without checking if key exists.

### Tuple Keys — Track Two Dimensions

```python
from collections import defaultdict

# Track unique users per (ip, hour) — two dimensions, one dict
tracker = defaultdict(set)
tracker[("203.45.167.22", "10")].add("admin")
tracker[("203.45.167.22", "10")].add("jsmith")

len(tracker[("203.45.167.22", "10")])   # 2 unique users from this IP in hour 10

# Other useful tuple keys:
# (user, hour)          → login attempts per user per hour
# (source_ip, dest_ip)  → lateral movement tracking
# (direction, protocol, port) → firewall rule grouping
```

**Use when:** need to track something across two dimensions simultaneously.

### Stack — Last In, First Out (LIFO)

```python
stack = []
stack.append("(")            # push
stack[-1]                    # peek at top
stack.pop()                  # pop and return top
len(stack) == 0              # check if empty
```

**Use when:** matching openers/closers (brackets, tags), parsing nested structures.

---

## Pattern Library — Find Your Problem Type

### Pattern 1: "Find the Top N Most Common X"

**Examples:** Most common IP, top attacked users, most frequent error codes.

```python
from collections import Counter

items = [extract_field(line) for line in logs]
top_n = Counter(items).most_common(n)
# Returns: [("item", count), ("item", count), ...]
```

### Pattern 2: "Group Items by Category"

**Examples:** Group events by IP, group rules by port, group findings by severity.

```python
from collections import defaultdict

groups = defaultdict(list)
for item in items:
    key = item["category"]
    groups[key].append(item)

# Access: groups["admin"] → [event1, event2, ...]
```

### Pattern 3: "Correlate Two Data Sources by Key"

**Examples:** Join auth logs with access logs, match IPs across sources.

```python
from collections import defaultdict

# Step 1: Index one source by key — O(m)
index = defaultdict(list)
for item in source_a:
    index[item["ip"]].append(item)

# Step 2: Walk other source, look up — O(n), each lookup O(1)
for item in source_b:
    matches = index[item["ip"]]     # O(1) lookup
    # Process matches...

# Total: O(n + m) instead of O(n × m)
```

### Pattern 4: "Detect Events Exceeding Threshold in Time Window"

**Examples:** DDoS detection, brute force detection, rate limiting.

```python
from collections import defaultdict
from datetime import datetime

# Group timestamps by IP
ip_times = defaultdict(list)
for line in logs:
    ip, timestamp = parse(line)
    ip_times[ip].append(timestamp)

# Sliding window per IP
for ip, times in ip_times.items():
    times.sort()
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window_seconds:
            left += 1
        count = right - left + 1    # items in current window
        if count >= threshold:
            flag(ip, count)
```

### Pattern 5: "Detect Spraying/Distributed Attacks"

**Examples:** Password spraying, distributed scanning, coordinated abuse.

```python
from collections import defaultdict

# Tuple key: (source, time_bucket) → set of unique targets
attacks = defaultdict(set)
for event in events:
    key = (event["ip"], event["hour"])
    attacks[key].add(event["username"])

# Flag: many unique targets from one source = spraying
for (ip, hour), targets in attacks.items():
    if len(targets) >= threshold:
        flag(ip, hour, targets)
```

### Pattern 6: "Find Conflicts or Contradictions"

**Examples:** Firewall rule conflicts, policy contradictions, duplicate rules.

```python
from collections import defaultdict

# Group by what should be unique
groups = defaultdict(list)
for rule in rules:
    key = (rule["direction"], rule["protocol"], rule["port"])
    groups[key].append(rule)

# Check each group for contradictions
for key, group_rules in groups.items():
    actions = {r["action"] for r in group_rules}
    if "ALLOW" in actions and "DENY" in actions:
        flag_conflict(key, group_rules)
```

### Pattern 7: "Merge Overlapping Ranges"

**Examples:** Merge time windows, consolidate IP ranges, combine scan results.

```python
intervals.sort(key=lambda x: x[0])    # sort by start
merged = [intervals[0]]

for current in intervals[1:]:
    last = merged[-1]
    if current[0] <= last[1]:          # overlap check
        last[1] = max(last[1], current[1])  # extend
    else:
        merged.append(current)         # new range
```

### Pattern 8: "Search Sorted Data Efficiently"

**Examples:** Find target in sorted list, binary search, nearest value.

```python
def binary_search(numbers, target):
    left, right = 0, len(numbers) - 1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return mid                  # found
        elif numbers[mid] < target:
            left = mid + 1              # search right half
        else:
            right = mid - 1             # search left half
    # After loop: right = floor, left = ceiling
    return left  # or handle not-found
```

### Pattern 9: "Match Openers to Closers"

**Examples:** Balanced brackets, matching HTML tags, nested structure validation.

```python
stack = []
matches = {")": "(", "]": "[", "}": "{"}

for char in text:
    if char in {"(", "[", "{"}:
        stack.append(char)
    elif char in matches:
        if not stack or stack[-1] != matches[char]:
            return False                # mismatch
        stack.pop()

return len(stack) == 0                  # empty = balanced
```

### Pattern 10: "Enumerate and Exploit IDOR"

**Examples:** User enumeration, resource discovery, sequential ID exploitation.

```python
import requests

found = []
for id in range(start, end + 1):
    try:
        resp = requests.get(f"{url}/api/resource/{id}", timeout=5)
        if resp.status_code == 200:
            found.append(resp.json())
    except requests.exceptions.RequestException:
        continue

# Categorize results
admins = [u for u in found if u.get("role") == "admin"]
```

### Pattern 11: "Tiered Detection (Always Bad → Conditionally Bad → Aggregate Bad)"

**Examples:** CloudTrail analysis, SIEM rules, security event categorization.

```python
from collections import defaultdict, Counter

always_suspicious = {"StopLogging", "DeleteTrail", "CreateAccessKey"}
alerts = []
user_counts = Counter()

for event in events:
    name = event.get("eventName", "")
    user_counts[event.get("user", "")] += 1

    # Tier 1: always bad
    if name in always_suspicious:
        alerts.append({"tier": 1, "event": name})

    # Tier 2: bad with certain parameters
    if name == "RunInstances" and event.get("count", 0) > 5:
        alerts.append({"tier": 2, "event": name})

# Tier 3: bad in aggregate
for user, count in user_counts.items():
    if count > threshold:
        alerts.append({"tier": 3, "user": user, "count": count})
```

### Pattern 12: "Flood Fill / Count Connected Components"

**Examples:** Count islands, find network segments, identify clusters.

```python
def count_islands(grid):
    rows, cols = len(grid), len(grid[0])
    count = 0

    def dfs(r, c):
        if r < 0 or r >= rows or c < 0 or c >= cols or grid[r][c] == 0:
            return
        grid[r][c] = 0              # mark visited
        dfs(r+1, c)                 # down
        dfs(r-1, c)                 # up
        dfs(r, c+1)                 # right
        dfs(r, c-1)                 # left

    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 1:
                count += 1          # new island found
                dfs(r, c)           # sink it

    return count
```

### Pattern 13: "Digit-by-Digit Arithmetic on Strings"

**Examples:** Add large numbers, multiply strings, compare version numbers.

```python
def add_strings(num1, num2):
    result = []
    carry = 0
    i, j = len(num1) - 1, len(num2) - 1

    while i >= 0 or j >= 0 or carry:
        d1 = int(num1[i]) if i >= 0 else 0
        d2 = int(num2[j]) if j >= 0 else 0
        total = d1 + d2 + carry
        carry = total // 10
        result.append(str(total % 10))
        i -= 1
        j -= 1

    return "".join(reversed(result))
```

---

## Parsing Techniques

### Split — The Default Parser

```python
line = "2025-04-09 10:15:32 192.168.1.100 GET /api/users 200"
parts = line.split()
# ['2025-04-09', '10:15:32', '192.168.1.100', 'GET', '/api/users', '200']

# Split on specific delimiter
"user=admin".split("=")          # ['user', 'admin']
"user=admin".split("=", 1)       # ['user', 'admin'] — maxsplit for safety

# Split with maxsplit (preserves rest)
"arn:aws:s3:::my-bucket/data/*".split(":", 5)
# ['arn', 'aws', 's3', '', '', 'my-bucket/data/*']
```

### Regex — When Split Isn't Enough

```python
import re

# Extract structured fields
pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s(\S+).*?"\s(\d{3})'
match = re.search(pattern, line)
ip = match.group(1)
method = match.group(2)

# Key regex patterns:
# \d+           one or more digits
# \S+           one or more non-whitespace
# \w+           one or more word characters
# .*?           match anything, lazy (as little as possible)
# (\d{3})       capture exactly 3 digits (status code)
# ([\d\.]+)     capture IP address (digits and dots)
# (?:...)?      non-capturing optional group
```

### JSON — Structured Data

```python
import json

data = json.loads('{"key": "value"}')       # string → dict
data.get("key", "default")                  # safe access

# Nested safe access:
params = event.get("requestParameters") or {}
bucket = params.get("bucketName", "unknown")
```

### URL Parsing

```python
from urllib.parse import urlparse, parse_qs

parsed = urlparse("https://api.example.com/v1/users?id=123&role=admin")
parsed.scheme     # "https"
parsed.netloc     # "api.example.com"
parsed.path       # "/v1/users"

params = parse_qs(parsed.query)
# {"id": ["123"], "role": ["admin"]}
```

### CSV Parsing

```python
# Simple CSV (no quoted fields)
header = lines[0].split(",")
for line in lines[1:]:
    parts = line.split(",")
    rule = dict(zip(header, parts))

# Complex CSV
import csv
reader = csv.DictReader(lines)
for row in reader:
    print(row["column_name"])
```

### Timestamp Parsing

```python
from datetime import datetime

dt = datetime.strptime("2025-04-09 10:15:32", "%Y-%m-%d %H:%M:%S")
unix_ts = dt.timestamp()         # float seconds since epoch
# Now: ts2 - ts1 = difference in seconds

# Quick hour extraction without datetime:
hour = "10:15:32".split(":")[0]  # "10"
```

### Base64 Decoding (JWT, encoded data)

```python
import base64
import json

# Standard base64
decoded = base64.b64decode("c2VjcmV0cw==")   # b"secrets"

# JWT base64url (add padding back first)
def decode_jwt_part(part):
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    return json.loads(base64.urlsafe_b64decode(part))
```

---

## Python Built-ins You Need

### sorted() vs .sort()

```python
# sorted() — returns NEW list, original unchanged
result = sorted(data, key=lambda x: x[1], reverse=True)

# .sort() — modifies ORIGINAL, returns None
data.sort(key=lambda x: x[0])

# Use sorted() by default — safer
```

### lambda — Inline Functions for key=

```python
# Sort by second element
sorted(data, key=lambda x: x[1])

# Sort by dict key
sorted(alerts, key=lambda x: x["severity"])

# Sort by multiple criteria
sorted(data, key=lambda x: (x["tier"], x["severity"]))

# Find max/min by specific field
max(items, key=lambda x: x[1])
min(events, key=lambda x: x["timestamp"])
```

### enumerate() — Index + Value

```python
for i, item in enumerate(my_list):
    print(f"Index {i}: {item}")

for i, line in enumerate(lines, start=1):   # start counting from 1
    print(f"Line {i}: {line}")
```

### List Comprehensions — Filter and Transform

```python
# Filter
admins = [u for u in users if u.get("role") == "admin"]
failed = [log for log in logs if "FAILED" in log]

# Transform
ips = [line.split()[2] for line in logs]
upper = [name.upper() for name in names]

# Filter + Transform
admin_names = [u["name"] for u in users if u["role"] == "admin"]
```

### String Methods

```python
s.split()                    # split on whitespace
s.split(",", 1)              # split on comma, max 1 split
s.strip()                    # remove leading/trailing whitespace
s.lower()                    # lowercase for case-insensitive compare
s.startswith("http://")      # prefix check
s.endswith(".xml")           # suffix check
"pattern" in s               # substring check
s.replace("old", "new")     # replace substring
s.isdigit()                  # all digits?
s.isalpha()                  # all letters?
```

### File I/O

```python
# Read all lines
with open("file.txt", "r") as f:
    lines = f.read().splitlines()

# Read line by line (memory efficient for large files)
with open("file.txt", "r") as f:
    for line in f:
        process(line.strip())
```

### Error Handling

```python
try:
    result = risky_operation()
except SpecificError as e:
    handle_specific(e)
except Exception as e:
    handle_general(e)
finally:
    cleanup()                # always runs

# For API calls:
import requests
try:
    resp = requests.get(url, timeout=5)
except requests.exceptions.Timeout:
    return {"status": "timeout"}
except requests.exceptions.ConnectionError:
    return {"status": "connection_error"}
```

### Bitwise Operations

```python
n & (n - 1) == 0            # power of 2 check
n & 1                        # check if odd (last bit is 1)
n >> 1                       # divide by 2
n << 1                       # multiply by 2
```

---

## Common Gotchas

### 1. Variable Inside Loop (The #1 Bug)

```python
# WRONG — resets every iteration
for line in logs:
    results = []             # ← inside loop!
    results.append(parse(line))
# results only has last item

# RIGHT — persists across iterations
results = []                 # ← outside loop!
for line in logs:
    results.append(parse(line))
```

### 2. Forgetting Counter for "Most Common"

```python
# WRONG — extracts but doesn't count
ips = [line.split()[0] for line in logs]
print(ips)  # just a flat list

# RIGHT — count and rank
from collections import Counter
ips = [line.split()[0] for line in logs]
print(Counter(ips).most_common(5))
```

### 3. Using == Instead of .get() on Dicts

```python
# CRASHES if key missing
if data["role"] == "admin":

# SAFE — returns None/default
if data.get("role") == "admin":
```

### 4. ASCII Math for Bracket Matching

```python
# WRONG — ] and } aren't adjacent to [ and { in ASCII
if stack[-1] == chr(ord(char) - 1):

# RIGHT — use a mapping dict
matches = {")": "(", "]": "[", "}": "{"}
if stack[-1] == matches[char]:
```

### 5. Forgetting "or carry" in Addition

```python
# WRONG — loses the final carry
while i >= 0 or j >= 0:

# RIGHT — keeps going if carry remains
while i >= 0 or j >= 0 or carry:
```

### 6. Modifying List While Iterating

```python
# WRONG — unpredictable behavior
for item in my_list:
    if condition:
        my_list.remove(item)

# RIGHT — build a new list
my_list = [item for item in my_list if not condition]
```

### 7. Not Handling Edge Cases

```python
# Always check at the start:
if not data:          # empty input
    return []
if len(data) == 1:    # single element
    return data
```

---

## One-Liner Recalls

| Problem Type | Recall |
|---|---|
| Most common X | `Counter(items).most_common(n)` |
| Group by category | `defaultdict(list)`, key = category, append items |
| Unique items | `set()` with `.add()` |
| Two dimensions | Tuple key `(ip, hour)` in `defaultdict(set)` |
| Correlate two sources | Index one in dict, walk the other — O(n+m) |
| Time window detection | Sort timestamps, sliding window with two pointers |
| Overlap/merge | Sort by start, merge if `next_start <= current_end` |
| Sorted data search | Binary search — cut in half each step, O(log n) |
| Match open/close | Stack — push openers, pop on matching closer |
| Digit arithmetic | Two pointers from right, `// 10` for carry, `% 10` for digit |
| Flood fill / islands | DFS from each unvisited cell, mark visited by setting to 0 |
| Tiered detection | Set for tier 1, conditionals for tier 2, Counter for tier 3 |
| Safe dict access | `.get(key, default)` — never crashes on missing keys |
| Sort by custom field | `sorted(data, key=lambda x: x[field])` |
| Parse timestamps | `datetime.strptime()` then `.timestamp()` for math |

---

## Interview Approach Reminders

1. **Talk through your approach BEFORE coding** — "I'll parse each line, group by IP using a defaultdict, then use Counter to find the top offenders"
2. **Start simple, then iterate** — get a working version first, then add edge cases and improvements
3. **Name your variables clearly** — `failed_ips` not `x`, `login_attempts` not `data`
4. **Handle edge cases** — empty input, missing fields, single element
5. **Know your complexity** — "This is O(n) because I make one pass through the data"
6. **Offer improvements** — "In production I'd add rate limiting / threading / caching"

---

## Contributing

This reference guide is a living document. Contributions, corrections, and additions are welcome via pull request.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.