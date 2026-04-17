"""
WORD FREQUENCY COUNTER - Text Analysis Tool
Security Engineer Coding Practice Problem #5

=====================================================================
REFERENCE NOTES - Counter, String Cleaning, Stop Words, Text Processing
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Log analysis often requires counting occurrences of patterns
  - Same technique applies to counting IPs, URLs, error codes, user agents
  - Counter is the go-to tool whenever you need "top N most common" anything


COUNTER - THE COUNTING SHORTCUT:
----------------------------------
  from collections import Counter

  Counter takes any iterable and counts occurrences:
    Counter(["a", "b", "a", "a", "b"])
    # → Counter({"a": 3, "b": 2})

  .most_common(n) returns the top N as sorted list of tuples:
    Counter(words).most_common(5)
    # → [("security", 4), ("application", 2), ...]

  It's a dict subclass, so you can also do:
    counts["security"]  → 4


TEXT CLEANING FOR ACCURATE COUNTING:
--------------------------------------
  Raw text has problems:
    "Security" vs "security"  → same word, counted separately
    "security." vs "security" → punctuation creates false duplicates

  Fix with:
    text.lower()                        → normalize case
    re.sub(r'[^\w\s]', '', text)       → strip all punctuation

  Regex breakdown:
    [^\w\s]  → match any character that is NOT a word char or whitespace
    \w       → letters, digits, underscore
    \s       → whitespace (space, tab, newline)
    ^        → inside [] means "NOT these characters"
    So [^\w\s] matches punctuation, symbols, special chars - and we replace with ''


STOP WORDS - FILTERING NOISE:
-------------------------------
  Common words like "is", "the", "a", "for" dominate frequency counts
  but carry no meaning. Filtering them reveals the actual content.

  Simple approach - define a set of stop words:
    stop_words = {"is", "a", "for", "the", "and", "to", "of", "in"}
    words = [w for w in text.split() if w not in stop_words]

  Why a set and not a list?
    Sets have O(1) lookup - checking "is this word a stop word?"
    is instant regardless of how many stop words you have.
    Lists have O(n) lookup - slower as the list grows.


.split() HANDLES MULTIPLE DELIMITERS:
---------------------------------------
  text.split()  → splits on ANY whitespace (spaces, tabs, newlines)
  No need to splitlines() then join() then split() again.

  "hello   world\nfoo\tbar".split()
  # → ["hello", "world", "foo", "bar"]


ONE-LINE RECALLS:
------------------
  Counter:      "Counter counts, most_common sorts - pass it a list, get ranked results"
  Text clean:   "lower() for case, re.sub(r'[^\w\s]', '', text) for punctuation"
  Stop words:   "Use a set for O(1) lookup, filter with list comprehension"
  split():      "No args = splits on all whitespace including newlines"

=====================================================================
"""

from collections import Counter
import re


def word_frequency(text, top_n=5):
    """Return the top N most frequent words in the given text."""
    words = text.split()
    return Counter(words).most_common(top_n)


def word_frequency_clean(text, top_n=5):
    """
    Return top N most frequent words with text cleaning applied.
    
    Normalizes case and strips punctuation so that:
      - "Security" and "security" count as the same word
      - "security." and "security" count as the same word
    """
    cleaned = re.sub(r'[^\w\s]', '', text.lower())
    words = cleaned.split()
    return Counter(words).most_common(top_n)


def word_frequency_filtered(text, top_n=5, custom_stop_words=None):
    """
    Return top N most frequent meaningful words.
    
    Applies case normalization, punctuation removal, and stop word filtering
    to surface content-carrying words instead of common filler.
    """
    default_stop_words = {
        "is", "a", "an", "the", "and", "to", "of", "in", "for",
        "on", "at", "by", "be", "it", "or", "as", "do", "if",
        "so", "no", "not", "but", "are", "was", "has", "had",
        "should", "would", "could", "can", "will", "may", "with",
        "this", "that", "from", "they", "been", "have", "its",
        "were", "their", "which", "each", "every",
    }

    stop_words = custom_stop_words if custom_stop_words is not None else default_stop_words
    cleaned = re.sub(r'[^\w\s]', '', text.lower())
    words = [w for w in cleaned.split() if w not in stop_words]
    return Counter(words).most_common(top_n)


if __name__ == "__main__":
    with open("text.txt", "r") as f:
        text = f.read()

    print("=== Basic Word Frequency (Top 5) ===")
    for word, count in word_frequency(text):
        print(f"  {word}: {count}")

    print("\n=== Cleaned Word Frequency (Top 5) ===")
    for word, count in word_frequency_clean(text):
        print(f"  {word}: {count}")

    print("\n=== Filtered Word Frequency - Stop Words Removed (Top 5) ===")
    for word, count in word_frequency_filtered(text):
        print(f"  {word}: {count}")