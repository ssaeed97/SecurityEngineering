"""
LARGE NUMBER ADDITION - Add Two Numbers Stored as Strings

=====================================================================
REFERENCE NOTES - Two Pointers, Carry Arithmetic, String Manipulation
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Tests fundamental understanding of how arithmetic works at the
    lowest level - important for understanding overflow vulnerabilities
  - Integer overflow is a real security vulnerability: buffer overflows,
    integer wraparound attacks, incorrect size calculations
  - Same two-pointer pattern used in: comparing log timestamps,
    merging sorted data, string comparison algorithms
  - Shows you can implement algorithms from scratch, not just call
    library functions


WHY NOT JUST USE int()?
--------------------------
  In Python, int() handles arbitrary precision - no overflow.
  But the interviewer wants to see you implement the logic because:

  1. Many languages (C, Java, Go) DO overflow at 32/64 bits
  2. It tests your understanding of carry arithmetic
  3. Same pattern applies to other digit-by-digit operations
     (subtraction, multiplication, comparison)
  4. Shows algorithmic thinking, not just language knowledge

  In an interview, mention: "Python handles big integers natively,
  but I'll implement the manual approach to show the algorithm."


THE ALGORITHM - GRADE SCHOOL ADDITION:
-----------------------------------------
      9 9 9
    + 0 0 1
    -------

  Start from the RIGHT (ones place):
    Step 1: 9 + 1 + carry(0) = 10 → write 0, carry = 1
    Step 2: 9 + 0 + carry(1) = 10 → write 0, carry = 1
    Step 3: 9 + 0 + carry(1) = 10 → write 0, carry = 1
    Step 4: no digits left, carry = 1 → write 1, carry = 0

  Result (built right-to-left): ["0","0","0","1"] → reversed → "1000"


TWO POINTERS FROM THE RIGHT:
-------------------------------
  num1 = "999"    → i starts at 2 (last index)
  num2 = "1"      → j starts at 0 (last index)

  Each step: read digit at pointer, move pointer left (i -= 1)
  When pointer goes below 0: treat as 0 (number is exhausted)

  This handles different-length numbers automatically:
    "999" + "1" → when j goes to -1, digit2 becomes 0


CARRY MATH:
-------------
  total = digit1 + digit2 + carry

  carry = total // 10     → integer division
    10 // 10 = 1   (carry the 1)
    9 // 10 = 0    (no carry)
    18 // 10 = 1   (carry the 1, max possible with single digits + carry)

  digit = total % 10      → remainder
    10 % 10 = 0    (write 0)
    9 % 10 = 9     (write 9)
    18 % 10 = 8    (write 8)


THE "or carry" CONDITION:
---------------------------
  while i >= 0 or j >= 0 or carry:

  Without "or carry":
    "999" + "1" would give "000" - the final carry is lost!

  The loop must continue even after both numbers are exhausted
  if there's still a carry to write.


ONE-LINE RECALLS:
------------------
  Algorithm:    "Two pointers from the right, add digits + carry,
                 // 10 for new carry, % 10 for digit to write"
  or carry:     "Keep looping while carry remains - without it,
                 '999' + '1' loses the leading 1"
  Different lengths: "When pointer < 0, treat digit as 0"
  Build result: "Append digits right-to-left, reverse at the end"

=====================================================================
"""


def add_strings(num1, num2):
    """
    Add two large numbers represented as strings.
    Handles numbers of any length, including those larger than 64-bit.

    Args:
        num1: First number as string (e.g., "999999999999999999")
        num2: Second number as string (e.g., "1")

    Returns:
        Sum as string (e.g., "1000000000000000000")
    """
    result = []
    carry = 0
    i = len(num1) - 1
    j = len(num2) - 1

    while i >= 0 or j >= 0 or carry:
        digit1 = int(num1[i]) if i >= 0 else 0
        digit2 = int(num2[j]) if j >= 0 else 0

        total = digit1 + digit2 + carry
        carry = total // 10
        result.append(str(total % 10))

        i -= 1
        j -= 1

    return "".join(reversed(result))


def add_strings_builtin(num1, num2):
    """
    Python's built-in approach for comparison.
    Python handles arbitrary precision natively - no overflow.
    In an interview, mention this exists but implement manually.
    """
    return str(int(num1) + int(num2))


if __name__ == "__main__":
    test_cases = [
        # (num1, num2, expected)
        ("123", "456", "579"),                          # basic addition
        ("999", "1", "1000"),                           # carry propagation
        ("999", "999", "1998"),                         # carry on every digit
        ("0", "0", "0"),                                # zeros
        ("1", "0", "1"),                                # one zero
        ("999999999999999999", "1", "1000000000000000000"),  # beyond 64-bit
        ("123456789", "987654321", "1111111110"),        # large numbers
        ("50", "50", "100"),                            # carry creates new digit
        ("9999999999999999999999999999", "1", "10000000000000000000000000000"),  # way beyond any int
    ]

    print("=== Large Number String Addition ===\n")

    all_passed = True
    for num1, num2, expected in test_cases:
        result = add_strings(num1, num2)
        builtin = add_strings_builtin(num1, num2)
        status = "✓" if result == expected else "✗ FAIL"
        match = "✓" if result == builtin else "✗ MISMATCH"

        if result != expected:
            all_passed = False

        print(f"  {status}  {num1} + {num2}")
        print(f"       = {result}  (matches builtin: {match})")
        print()

    print(f"  {'All tests passed!' if all_passed else 'Some tests FAILED'}")

    # Demonstrate the overflow problem in other languages
    print("\n=== Why This Matters for Security ===")
    print(f"  32-bit max:  {2**31 - 1}")
    print(f"  64-bit max:  {2**63 - 1}")
    print(f"  Our result:  {add_strings('9999999999999999999999999999', '1')}")
    print(f"  Python handles this natively, but C/Java/Go would overflow.")
    print(f"  Integer overflow is a real vulnerability class - buffer sizes,")
    print(f"  length calculations, and financial computations can all go wrong.")