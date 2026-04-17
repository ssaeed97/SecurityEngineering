"""
MERGE OVERLAPPING INTERVALS - Sort and Merge Pattern

=====================================================================
REFERENCE NOTES - Sorting, Lambda, Merge Pattern, Overlap Detection
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Merge overlapping vulnerability scan time windows
  - Consolidate overlapping IP ranges in firewall rules
  - Combine overlapping maintenance windows
  - Merge overlapping alert timeframes in SIEM
  - Same pattern applies anywhere you need to consolidate ranges


THE ALGORITHM - SORT THEN MERGE:
-----------------------------------
  1. Sort intervals by start time
     → Guarantees overlapping intervals are adjacent
     → Without sorting, you'd compare every pair: O(n²)

  2. Walk through sorted intervals:
     → If next start <= current end → they overlap → merge
     → If next start > current end → no overlap → start new

  3. Merge = extend the current interval's end:
     → new end = max(current end, next end)
     → max() handles both partial overlap and full containment

  Complexity: O(n log n) for sort + O(n) for merge = O(n log n)


THE OVERLAP CHECK:
--------------------
  After sorting by start time, only ONE comparison needed:

    if next_start <= current_end → OVERLAP

  Why this works after sorting:
    Sorted: [1,3] [2,6] [8,10]
    We know 2 >= 1 (sorted), so we only check if 2 <= 3
    If yes → they overlap. If no → gap between them.

  Four cases (all handled by the same check):
    [1,3] [2,6]   → 2 <= 3 → overlap → merge to [1,6]
    [1,4] [2,3]   → 2 <= 4 → overlap → merge to [1, max(4,3)] = [1,4]
    [1,4] [4,5]   → 4 <= 4 → touching → merge to [1,5]
    [1,3] [5,7]   → 5 <= 3? NO → no overlap


LAMBDA - INLINE FUNCTIONS:
-----------------------------
  lambda x: x[0]   means   "take x, return x[0]"

  Used with sorted/sort to control WHAT to sort by:
    intervals.sort(key=lambda x: x[0])       # sort by start time
    sorted(data, key=lambda x: x[1])         # sort by second element
    sorted(alerts, key=lambda x: x["severity"])  # sort dicts by key

  Also used with max/min:
    max(items, key=lambda x: x[1])           # item with largest second element
    min(events, key=lambda x: x["timestamp"]) # earliest event

  Rule: lambda for key= parameter, list comprehension for filtering/mapping.


ONE-LINE RECALLS:
------------------
  Algorithm:  "Sort by start, walk through - if next start <= current end,
               merge with max of both ends"
  Why sort:   "After sorting, overlaps are adjacent - one comparison per pair"
  Lambda:     "lambda x: x[0] in sort key= - controls what to sort by"
  Complexity: "O(n log n) for the sort, O(n) for the merge"

=====================================================================
"""


def merge_intervals(intervals):
    """
    Merge overlapping intervals.

    Args:
        intervals: List of [start, end] pairs

    Returns:
        List of merged [start, end] pairs with no overlaps
    """
    if not intervals:
        return []

    # Sort by start time - guarantees overlaps are adjacent
    intervals.sort(key=lambda x: x[0])

    merged = [intervals[0]]

    for current in intervals[1:]:
        last = merged[-1]

        if current[0] <= last[1]:               # overlap: next start <= previous end
            last[1] = max(last[1], current[1])   # extend the end
        else:
            merged.append(current)               # no overlap, start new interval

    return merged


def merge_intervals_security(scan_windows):
    """
    Security-themed version: merge overlapping vulnerability scan windows.

    Each window is a dict with start, end, scanner name.
    Returns merged windows with list of scanners that covered each period.
    """
    if not scan_windows:
        return []

    # Sort by start time
    sorted_windows = sorted(scan_windows, key=lambda x: x["start"])

    merged = [{
        "start": sorted_windows[0]["start"],
        "end": sorted_windows[0]["end"],
        "scanners": [sorted_windows[0]["scanner"]],
    }]

    for current in sorted_windows[1:]:
        last = merged[-1]

        if current["start"] <= last["end"]:
            last["end"] = max(last["end"], current["end"])
            if current["scanner"] not in last["scanners"]:
                last["scanners"].append(current["scanner"])
        else:
            merged.append({
                "start": current["start"],
                "end": current["end"],
                "scanners": [current["scanner"]],
            })

    return merged


if __name__ == "__main__":
    print("=== Basic Interval Merging ===\n")

    test_cases = [
        # (input, expected, description)
        (
            [[1,3], [2,6], [8,10], [15,18]],
            [[1,6], [8,10], [15,18]],
            "Partial overlap + non-overlapping"
        ),
        (
            [[1,4], [4,5]],
            [[1,5]],
            "Touching at boundary"
        ),
        (
            [[1,4], [2,3]],
            [[1,4]],
            "Fully contained interval"
        ),
        (
            [[1,4], [0,4]],
            [[0,4]],
            "Unsorted input"
        ),
        (
            [[1,4], [0,1]],
            [[0,4]],
            "Touching at start"
        ),
        (
            [[1,3], [5,7], [9,11]],
            [[1,3], [5,7], [9,11]],
            "No overlaps at all"
        ),
        (
            [[1,10], [2,3], [4,5], [6,7]],
            [[1,10]],
            "One large interval contains all others"
        ),
        (
            [],
            [],
            "Empty input"
        ),
    ]

    all_passed = True
    for intervals, expected, description in test_cases:
        # Make a copy since sort modifies in place
        result = merge_intervals([i[:] for i in intervals])
        status = "✓" if result == expected else "✗ FAIL"
        if result != expected:
            all_passed = False
        print(f"  {status}  {description}")
        print(f"       Input:    {intervals}")
        print(f"       Output:   {result}")
        print()

    print(f"  {'All tests passed!' if all_passed else 'Some tests FAILED'}")

    # Security-themed example
    print("\n=== Security Application: Merge Scan Windows ===\n")

    scan_windows = [
        {"start": 0, "end": 30, "scanner": "Qualys"},
        {"start": 25, "end": 60, "scanner": "Acunetix"},
        {"start": 55, "end": 90, "scanner": "Burp Suite"},
        {"start": 120, "end": 150, "scanner": "Qualys"},
        {"start": 130, "end": 160, "scanner": "Nessus"},
    ]

    merged_scans = merge_intervals_security(scan_windows)

    print("  Original scan windows:")
    for w in scan_windows:
        print(f"    {w['scanner']}: {w['start']}min - {w['end']}min")

    print("\n  Merged coverage periods:")
    for m in merged_scans:
        scanners = ", ".join(m["scanners"])
        print(f"    {m['start']}min - {m['end']}min (covered by: {scanners})")

    # Gap detection
    print("\n  Coverage gaps:")
    for i in range(len(merged_scans) - 1):
        gap_start = merged_scans[i]["end"]
        gap_end = merged_scans[i + 1]["start"]
        if gap_end > gap_start:
            print(f"    NO COVERAGE: {gap_start}min - {gap_end}min")