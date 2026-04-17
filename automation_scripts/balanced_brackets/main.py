"""
BALANCED BRACKETS - Stack-Based Bracket Validator

=====================================================================
REFERENCE NOTES - Stacks, String Processing, Dict Mapping
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Stacks are used in parsing: HTML tags, JSON/XML validation,
    expression evaluation, call stack analysis in debugging
  - Same pattern applies to: validating nested security policies,
    parsing log formats with nested structures, checking config file
    syntax, analyzing code for matching open/close patterns
  - Shows understanding of data structures beyond just lists and dicts


STACK - LAST IN, FIRST OUT (LIFO):
-------------------------------------
  A stack is like a stack of plates - you can only add to the top
  and remove from the top. The most recent item comes off first.

  In Python, a list IS a stack:
    stack = []
    stack.append("(")    # push → stack is ["("]
    stack.append("[")    # push → stack is ["(", "["]
    stack[-1]            # peek at top → "["
    stack.pop()          # pop → returns "[", stack is ["("]
    len(stack) == 0      # check if empty

  Operations:
    push    = stack.append(item)    add to top
    pop     = stack.pop()           remove from top
    peek    = stack[-1]             look at top without removing
    isEmpty = len(stack) == 0       check if empty


WHY A STACK FOR BRACKETS:
----------------------------
  When you see "(", you need to remember it to match with ")" later.
  But the MOST RECENT opening bracket must be closed FIRST.

  Example: {[()]}
    See { → remember it (might need to match later)
    See [ → remember it (more recent than {)
    See ( → remember it (most recent)
    See ) → must match the MOST RECENT opener → ( ✅
    See ] → must match the MOST RECENT opener → [ ✅
    See } → must match the MOST RECENT opener → { ✅

  "Most recent first" = Last In First Out = Stack.


THE ALGORITHM:
----------------
  1. Walk through each character in the string
  2. If it's an opening bracket → push onto stack
  3. If it's a closing bracket →
     a. If stack is empty → no matching opener → INVALID
     b. If top of stack matches → pop it off → continue
     c. If top doesn't match → wrong nesting → INVALID
  4. Skip non-bracket characters (letters, numbers, spaces)
  5. After all characters: empty stack = VALID, items left = INVALID


DICT MAPPING vs ASCII MATH:
------------------------------
  DON'T use ord() math to match brackets:
    ord('(') = 40,  ord(')') = 41   → difference of 1
    ord('[') = 91,  ord(']') = 93   → difference of 2!
    ord('{') = 123, ord('}') = 125  → difference of 2!

  Only () are adjacent in ASCII. [] and {} have gaps.

  DO use a dict mapping:
    matches = {")": "(", "]": "[", "}": "{"}
    matches[")"]  → "("    (what should be on top of stack)


VARIABLE PLACEMENT - CRITICAL BUG TO AVOID:
----------------------------------------------
  WRONG - stack resets every character:
    for char in string:
        stack = []              # ← inside loop = reset every time!
        stack.append(char)

  RIGHT - stack persists across all characters:
    stack = []                  # ← outside loop = accumulates
    for char in string:
        stack.append(char)

  This bug makes the function always return True because the stack
  is always empty at the end (it was reset on the last character).


ONE-LINE RECALLS:
------------------
  Stack:        "List as stack - append() pushes, pop() pops, [-1] peeks"
  Algorithm:    "Push openers, on closer check top matches - pop if yes,
                 False if no. Empty stack at end = balanced."
  Dict map:     "matches = {')':'(', ']':'[', '}':'{'} - don't use ASCII math"
  Init outside: "Stack OUTSIDE the loop - inside means reset every iteration"

=====================================================================
"""


def is_balanced(s):
    """
    Check if brackets in string are properly balanced and nested.

    Handles (), [], {} and ignores non-bracket characters.
    Uses a stack: push openers, match closers against top of stack.

    Args:
        s: String potentially containing brackets

    Returns:
        True if all brackets are balanced, False otherwise
    """
    stack = []
    matches = {")": "(", "]": "[", "}": "{"}
    openers = {"(", "[", "{"}

    for char in s:
        if char in openers:
            stack.append(char)
        elif char in matches:
            if not stack:
                return False
            if stack[-1] == matches[char]:
                stack.pop()
            else:
                return False

    return len(stack) == 0


def validate_with_details(s):
    """
    Extended version that returns details about WHERE the mismatch occurs.
    Useful for debugging config files, code, or policy definitions.
    """
    stack = []
    matches = {")": "(", "]": "[", "}": "{"}
    openers = {"(", "[", "{"}

    for i, char in enumerate(s):
        if char in openers:
            stack.append((char, i))
        elif char in matches:
            if not stack:
                return {
                    "valid": False,
                    "error": f"Closing '{char}' at position {i} with nothing open",
                    "position": i,
                }
            top_char, top_pos = stack[-1]
            if top_char == matches[char]:
                stack.pop()
            else:
                return {
                    "valid": False,
                    "error": f"Closing '{char}' at position {i} doesn't match opening '{top_char}' at position {top_pos}",
                    "position": i,
                }

    if stack:
        unclosed = [(char, pos) for char, pos in stack]
        return {
            "valid": False,
            "error": f"Unclosed brackets: {unclosed}",
            "position": stack[-1][1],
        }

    return {"valid": True, "error": None, "position": None}


if __name__ == "__main__":
    test_cases = [
        # (input, expected result)
        ("()",                                         True),
        ("()[]{}",                                     True),
        ("{[()]}",                                     True),
        ("if (x[0] > {y: 1}) { return true; }",       True),
        ("",                                           True),
        ("({[]})",                                     True),
        ("(]",                                         False),
        ("([)]",                                       False),
        ("(((",                                        False),
        ("}",                                          False),
        ("{[}]",                                       False),
        ("((()))",                                     True),
    ]

    print("=== Balanced Brackets - Basic Check ===\n")
    all_passed = True
    for s, expected in test_cases:
        result = is_balanced(s)
        status = "✓" if result == expected else "✗ FAIL"
        if result != expected:
            all_passed = False
        display = s if s else "(empty)"
        print(f"  {status}  {display:45} → {result}")

    print(f"\n  {'All tests passed!' if all_passed else 'Some tests FAILED'}")

    print("\n=== Detailed Validation (shows WHERE errors occur) ===\n")
    error_cases = [
        "(]",
        "([)]",
        "(((",
        "}",
        "function test() { if (x > [1,2) { return; } }",
    ]

    for s in error_cases:
        result = validate_with_details(s)
        print(f"  Input: {s}")
        if result["valid"]:
            print(f"    Result: Valid")
        else:
            print(f"    Result: Invalid - {result['error']}")
        print()