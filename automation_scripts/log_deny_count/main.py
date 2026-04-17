"""
FIREWALL LOG PARSER - Top Denied IPs

=====================================================================
REFERENCE NOTES - Data Structures, Counter, Sorting
=====================================================================

DATA STRUCTURES - WHEN TO USE WHAT:
-----------------------------------
  list    → ordered, allows duplicates. Use when order matters.
            Example: collecting log entries in sequence.

  dict    → key-value pairs, fast lookup. Use when associating data.
            Example: mapping IPs to their deny counts.

  set     → unordered, no duplicates, fast membership check.
            Example: collecting all unique IPs seen.

  tuple   → like a list but immutable (can't change after creation).
            Example: a record like (timestamp, src_ip, dst_ip).


COUNTER (from collections):
----------------------------
  from collections import Counter

  Counter takes any iterable and counts occurrences automatically.

  fruits = ["apple", "banana", "apple", "apple", "banana"]
  counts = Counter(fruits)
  # → Counter({"apple": 3, "banana": 2})

  counts.most_common(2)
  # → [("apple", 3), ("banana", 2)]   ← already sorted, highest first

  It's just a dict subclass, so you can do counts["apple"] → 3


.get(key, default) - SAFE DICT LOOKUP:
----------------------------------------
  Normal lookup crashes if key missing:
    d = {}
    d["x"] += 1   # → KeyError!

  .get() returns a default instead of crashing:
    d = {}
    d["x"] = d.get("x", 0) + 1   # → {"x": 1}   (0 + 1 = 1)
    d["x"] = d.get("x", 0) + 1   # → {"x": 2}   (1 + 1 = 2)

  The second argument is the default: 0 for counting, [] for lists, "" for strings.


LAMBDA - INLINE MINI FUNCTION:
-------------------------------
  lambda x: x[1]   means   "take x, return x[1]"

  It's a shortcut for:
    def get_second(x):
        return x[1]

  Used with sorted() to tell it WHAT to sort by:
    sorted(data, key=lambda x: x[1])            # sort by second element
    sorted(data, key=lambda x: x[1], reverse=True)  # sort descending


SORTING A DICT BY VALUES:
--------------------------
  deny_count = {"192.168.1.105": 2, "172.16.0.50": 5, "10.10.10.10": 1}

  # .items() gives tuples: [("192.168.1.105", 2), ("172.16.0.50", 5), ...]
  # lambda x: x[1] says "sort by the count (second element)"
  # reverse=True means highest first

  sorted_ips = sorted(deny_count.items(), key=lambda x: x[1], reverse=True)
  top_3 = sorted_ips[:3]

  OR just use Counter which does this for you:
  Counter(deny_ips).most_common(3)


ONE-LINE RECALLS:
------------------
  Counter:  "Counter counts, most_common sorts - pass it a list, get ranked results"
  .get():   ".get(key, default) is a safe dict lookup - returns default instead of crashing"
  lambda:   "lambda x: what_to_return - an inline function, used with sorted(key=)"
  Sorting:  "sorted(dict.items(), key=lambda x: x[1], reverse=True) - sort dict by values"

=====================================================================
"""

from collections import Counter


def top_denied_ips(logs, top_n=3):
    """Return the top N source IPs with the most DENY entries."""
    deny_ips = []

    for log in logs:
        parts = log.split()
        if parts[2] == "DENY":
            deny_ips.append(parts[3])

    ip_counts = Counter(deny_ips)
    return ip_counts.most_common(top_n)


if __name__ == "__main__":
    logs = [
        "2025-03-24 10:15:32 DENY 192.168.1.105 → 10.0.0.5:443",
        "2025-03-24 10:15:33 ALLOW 192.168.1.110 → 10.0.0.5:80",
        "2025-03-24 10:15:35 DENY 192.168.1.105 → 10.0.0.5:22",
        "2025-03-24 10:15:36 DENY 172.16.0.50 → 10.0.0.5:443",
        "2025-03-24 10:15:37 DENY 172.16.0.50 → 10.0.0.5:22",
        "2025-03-24 10:15:38 DENY 172.16.0.50 → 10.0.0.5:80",
        "2025-03-24 10:15:39 DENY 10.10.10.10 → 10.0.0.5:22",
    ]

    results = top_denied_ips(logs)
    for ip, count in results:
        print(f"{ip}: {count} denies")