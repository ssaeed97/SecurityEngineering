# Security Engineer - Coding Prep

Practice problems for the **SE-level coding**.

## What This Repo Is

This is my hands-on coding prep for day-today security engineer tasks. Each folder contains a security-themed Python problem, the solution, and reference notes on the concepts used.

The coding bar for SE is **not LeetCode** — it's practical scripting: parsing logs, analyzing data, automating security tasks. These exercises target exactly that.

## Problems

| # | Folder | Problem | Key Concepts |
|---|--------|---------|--------------|
| 1 | `log_deny_count/` | Parse firewall logs, count DENY entries per source IP, return the top N offenders | `Counter`, `.get()`, `lambda`, `sorted()`, data structures |
| 2 | *coming soon* | Regex log parsing | `re` module, `findall`, `search`, capture groups |
| 3 | *coming soon* | Port scanner | `socket`, error handling, command-line args |
| 4 | *coming soon* | Caesar cipher | String manipulation, `ord()`/`chr()`, modular arithmetic |
| 5 | *coming soon* | JSON auth log analyzer | `json`, file I/O, time-window analysis |
| 6 | *coming soon* | Network traffic analyzer | CSV parsing, data aggregation, anomaly detection |

## How I'm Using This

1. Read the problem description
2. Attempt a solution before looking at the answer
3. Compare with the reference solution
4. Study the notes at the top of each file for concept refreshers
5. Re-do the problem from scratch a few days later (spaced repetition)
