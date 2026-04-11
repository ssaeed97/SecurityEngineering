"""
BINARY SEARCH for NEAREST ELEMENT — Find Target or Nearest Number
Security Engineer Coding Practice Problem #6

=====================================================================
REFERENCE NOTES — Binary Search, Sorted Lists, O(log n) Efficiency
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Searching through sorted datasets efficiently (sorted IPs, timestamps,
    log entries, port ranges, sorted alert severities)
  - Understanding algorithmic complexity shows engineering maturity
  - Binary search is a building block for more complex search problems
    like finding the first occurrence of an event in a time window


LINEAR vs BINARY SEARCH:
--------------------------
  Linear search: check every element one by one → O(n)
    10 elements = 10 checks, 1 million elements = 1 million checks

  Binary search: cut search space in half each step → O(log n)
    10 elements = ~4 checks, 1 million elements = ~20 checks

  Binary search REQUIRES a sorted list. If the list isn't sorted,
  you must sort it first (O(n log n)) or use linear search.


HOW BINARY SEARCH WORKS:
---------------------------
  Maintain two pointers: left (start) and right (end).
  Each step:
    1. Find the middle: mid = (left + right) // 2
    2. If numbers[mid] == target → found it, return
    3. If numbers[mid] < target → target is in the right half → left = mid + 1
    4. If numbers[mid] > target → target is in the left half → right = mid - 1
    5. When left > right → pointers crossed, target doesn't exist

  After the loop when searching for nearest:
    right = index of largest number SMALLER than target (floor)
    left  = index of smallest number LARGER than target (ceiling)
    Compare distances to both to find the nearest.


EDGE CASES — WHEN POINTERS GO OUT OF BOUNDS:
-----------------------------------------------
  Case 1: target smaller than all elements
    right goes to -1 (past the beginning)
    left stays at 0
    → Nearest is numbers[0] (first element)

    Example: numbers=[5, 10, 15], target=2
      mid=1 → 10 > 2 → right=0
      mid=0 → 5 > 2  → right=-1
      right=-1, left=0 → return numbers[0] = 5

  Case 2: target larger than all elements
    left goes to len(numbers) (past the end)
    right stays at last index
    → Nearest is numbers[-1] (last element)

    Example: numbers=[5, 10, 15], target=20
      mid=1 → 10 < 20 → left=2
      mid=2 → 15 < 20 → left=3
      left=3, right=2 → return numbers[-1] = 15

  Case 3: target between two elements (normal case)
    Both left and right are valid indices
    → Compare distances: target - numbers[right] vs numbers[left] - target


THE // OPERATOR — INTEGER DIVISION:
--------------------------------------
  Regular division:  7 / 2  = 3.5
  Integer division:  7 // 2 = 3   (floors the result)

  Used in binary search because array indices must be integers.
  (left + right) // 2 gives the middle index without decimals.


ONE-LINE RECALLS:
------------------
  Binary search:  "Cut in half each step — O(log n). Left and right converge."
  After loop:     "right = floor (largest smaller), left = ceiling (smallest larger)"
  Edge cases:     "right < 0 means below everything, left >= len means above everything"
  When to use:    "Only on sorted data. If unsorted, sort first or use linear."
  // operator:    "Integer division — floors the result, needed for array indices"

=====================================================================
"""


def find_nearest(numbers, target):
    """
    Find target in sorted list, or return the nearest number.
    Uses binary search for O(log n) efficiency.
    """
    left = 0
    right = len(numbers) - 1

    while left <= right:
        mid = (left + right) // 2

        if numbers[mid] == target:
            return target
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1

    # Pointers have crossed:
    # right = largest number < target
    # left  = smallest number > target

    if right < 0:
        return numbers[0]
    if left >= len(numbers):
        return numbers[-1]

    if target - numbers[right] <= numbers[left] - target:
        return numbers[right]
    else:
        return numbers[left]


def find_nearest_linear(numbers, target):
    """
    Linear search alternative — O(n), works on unsorted lists too.
    Included for comparison with binary search approach.
    """
    if target in numbers:
        return target
    if target <= numbers[0]:
        return numbers[0]
    if target >= numbers[-1]:
        return numbers[-1]

    for pos in range(len(numbers) - 1):
        if numbers[pos] < target < numbers[pos + 1]:
            if target - numbers[pos] <= numbers[pos + 1] - target:
                return numbers[pos]
            else:
                return numbers[pos + 1]


if __name__ == "__main__":
    numbers = [1, 3, 5, 8, 12, 15, 19, 23, 28, 35]

    test_cases = [
        (12, "Exact match"),
        (10, "Between 8 and 12"),
        (20, "Between 19 and 23"),
        (0,  "Below all elements"),
        (40, "Above all elements"),
        (1,  "First element exact"),
        (35, "Last element exact"),
        (4,  "Equidistant — returns lower"),
    ]

    print(f"List: {numbers}\n")
    print("=== Binary Search (O(log n)) ===")
    for target, description in test_cases:
        result = find_nearest(numbers, target)
        print(f"  Target: {target:>3} → Nearest: {result:>3}  ({description})")

    print("\n=== Linear Search (O(n)) ===")
    for target, description in test_cases:
        result = find_nearest_linear(numbers, target)
        print(f"  Target: {target:>3} → Nearest: {result:>3}  ({description})")