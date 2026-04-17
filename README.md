# Security Engineering

![Python](https://img.shields.io/badge/Language-Python-3776AB?logo=python&logoColor=white)
![Security Engineering](https://img.shields.io/badge/Focus-Security%20Engineering-red)
![OWASP](https://img.shields.io/badge/Reference-OWASP-000000?logo=owasp&logoColor=white)
![STRIDE](https://img.shields.io/badge/Threat%20Modeling-STRIDE-orange)

A hands-on reference for security engineering, covering practical scripting, application security concepts, threat modeling, and interview preparation.

---

## What This Is

This repository is a structured study resource built around the skills that matter in security engineering roles at product and consulting companies. It is not a collection of CTF writeups or theoretical notes, everything here is grounded in the kind of work security engineers actually do: writing detection scripts, reviewing code for vulnerabilities, modeling threats, and reasoning about cryptography and authentication.

The content is organized into four areas, each independently useful:

- **Scripting problems** that mirror real SE coding interviews and day-to-day automation tasks
- **Application security reference** covering OWASP, secure code review, and common vulnerability patterns
- **Threat modeling reference** with worked scenarios using STRIDE
- **Python patterns cheatsheet** for quickly identifying the right data structure or algorithm for a given problem

---

## Who This Is For
 
**Anyone learning security engineering** -  each scripting problem includes detailed reference notes explaining the underlying concepts, why they matter in real SE work, and how to recall the solution approach. Each cheatsheet covers a distinct domain within security engineering and focuses on how to apply that knowledge in practical, real-world scenarios. The cheatsheets are not introductions to a topic, they assume familiarity with the concepts and are designed to help you implement that knowledge effectively when it counts.
 
---
 
## Scope and Roadmap
 
This repository is continuously evolving. New domains and topics are added as they are encountered in real security engineering work and assessed to be a necessary part of a well-rounded security engineering skillset. The goal is not to be exhaustive, it is to be practically useful across the areas that come up most in the field.

---

## Contents

| Folder | Description |
|--------|-------------|
| `automation_scripts/` | 21 Python scripting problems for SE-level coding prep: log parsing, attack detection, network analysis, cryptography, AppSec exploitation, and AWS security |
| `OWASP_cheatsheet/` | Application security reference covering OWASP Top 10 (2025), cryptography, TLS, secure code review patterns, and common SE interview questions |
| `STRIDE_cheatsheet/` | STRIDE threat modeling reference with category differentiation guide, structured interview methodology, and four fully worked scenarios |
| `Scripting_cheatsheet/` | Python quick reference for SE coding problems: data structure selection guide, 13 security-themed patterns, parsing techniques, common gotchas, and one-liner recalls |

---

## How to Use This

Each section is independently navigable, start wherever is most relevant to what you are working on.

For the scripting problems, the recommended approach is:

1. Read the problem statement in the folder's `main.py` header
2. Attempt a solution before reading the reference solution
3. Compare your approach with the reference implementation
4. Study the concept notes at the top of each file

The cheatsheets are designed as quick-reference companions, useful during active study and as a refresher before interviews.

---

## Contributing

This is a living reference. Contributions, corrections, and new problems are welcome via pull request.

## License

MIT License - see the [LICENSE](LICENSE) file for details.