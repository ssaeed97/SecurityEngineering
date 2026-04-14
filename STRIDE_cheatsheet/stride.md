# STRIDE Threat Modeling — Cheat Sheet & Practice Scenarios

> Quick reference for STRIDE threat modeling in security engineer interviews. Includes differentiation guide, structured methodology, and four complete worked scenarios.

---

## Table of Contents

- [STRIDE Quick Reference](#stride-quick-reference)
- [How to Differentiate Overlapping Categories](#how-to-differentiate-overlapping-categories)
- [Interview Methodology — 5-7 Minutes](#interview-methodology--5-7-minutes)
- [Clarifying Questions That Actually Matter](#clarifying-questions-that-actually-matter)
- [Business-Specific vs Generic Threats](#business-specific-vs-generic-threats)
- [Scenario 1: Online Banking Application](#scenario-1-online-banking-application)
- [Scenario 2: Ride-Sharing Application](#scenario-2-ride-sharing-application)
- [Scenario 3: E-Commerce Platform](#scenario-3-e-commerce-platform)
- [Scenario 4: Human Capital Management (HCM) Platform](#scenario-4-human-capital-management-hcm-platform)

---

## STRIDE Quick Reference

| Letter | Threat | Security Property Violated | One-Line Definition | Quick Test |
|--------|--------|---------------------------|---------------------|------------|
| **S** | Spoofing | Authentication | Pretending to be someone or something you're not | "Is someone faking their identity?" |
| **T** | Tampering | Integrity | Modifying data or code without authorization | "Is data being changed in transit or at rest?" |
| **R** | Repudiation | Non-repudiation / Accountability | Denying you performed an action, and nobody can prove otherwise | "Can someone deny they did this?" |
| **I** | Information Disclosure | Confidentiality | Exposing data to someone not authorized to see it | "Is data visible to the wrong person?" |
| **D** | Denial of Service | Availability | Making a system unavailable to legitimate users | "Can someone prevent others from using this?" |
| **E** | Elevation of Privilege | Authorization | Performing actions beyond your permitted role | "Can someone do something beyond their role?" |

---

## How to Differentiate Overlapping Categories

The three most commonly confused categories are Spoofing, Information Disclosure, and Elevation of Privilege. Here's how to tell them apart.

### Same Vulnerability, Different STRIDE Category

An attacker discovers they can change `/api/orders/1001` to `/api/orders/1002`:

- If they **see** another customer's order details → **Information Disclosure** (accessed data they shouldn't see)
- If they **modify** another customer's order → **Elevation of Privilege** (performed an action they shouldn't be able to)
- If they change the order's `seller_id` to impersonate a different seller → **Spoofing** (pretending to be someone else)

Same endpoint, same vulnerability (IDOR), but the **primary impact** determines the STRIDE category.

### Decision Matrix

| Question | If Yes → | Example |
|----------|----------|---------|
| Is someone faking their identity? | **Spoofing** | Attacker logs in as another user, fake seller account mimicking a brand |
| Is data being modified without authorization? | **Tampering** | Changing price in checkout request, modifying timesheet hours |
| Can someone deny performing an action? | **Repudiation** | Customer claims they never placed an order, manager denies approving a termination |
| Is data visible to the wrong person? | **Information Disclosure** | Viewing another user's salary, cross-tenant data leak |
| Is the service being made unavailable? | **Denial of Service** | Bots hoarding flash sale inventory, overloading payroll processing |
| Is someone acting beyond their role? | **Elevation of Privilege** | Customer accessing seller endpoints, employee accessing manager functions |

### Interview Tip

If a threat fits multiple categories, pick the **primary impact** and mention it once:

*"This IDOR vulnerability primarily leads to information disclosure of order data, but could also enable privilege escalation if the endpoint allows modification."*

One sentence, covers all angles. Don't repeat the same threat under three different letters.

---

## Interview Methodology — 5-7 Minutes

Follow this exact structure every time:

### Step 1 — Clarify (30 seconds)
Ask 2-3 questions that genuinely change your answer. Don't ask more than 3.

### Step 2 — Components + Trust Boundaries (1 minute)
List the major components, then identify where trusted meets untrusted.

### Step 3 — STRIDE (4-5 minutes)
For each letter, give 1-2 business-specific threats with mitigations. Use this template:

> *"For [STRIDE letter], my top concern is [specific threat]. An attacker could [specific attack action], which would result in [specific business impact]. I'd mitigate this with [specific control]."*

### Step 4 — Prioritize (30 seconds)
> *"If I had to prioritize, the highest risk is [X] because [business reason]."*

---

## Clarifying Questions That Actually Matter

### Questions that change your answer:

| Question | Why It Matters |
|----------|---------------|
| Public-facing vs internal? | Changes which threats you lead with — external attackers vs insider threats |
| Cloud (AWS/Azure/GCP) or on-premise? | Cloud: SSRF, IAM misconfig, shared responsibility. On-prem: network segmentation, physical security |
| What data does it handle? (PII, PCI, HIPAA) | Regulations dictate specific required controls |
| Multi-tenant or single-tenant? | Multi-tenant: cross-tenant isolation is the #1 threat |
| Third-party integrations? | Each integration is a trust boundary where data leaves your control |

### Questions that are mostly theater (skip these):
- "What's the tech stack?" — rarely changes threat model
- "How many users?" — only affects DoS discussion
- "What's the team structure?" — irrelevant for threat modeling

---

## Business-Specific vs Generic Threats

The single biggest differentiator between a good and great STRIDE answer.

### The Test

Ask yourself: *"Could I say this exact same threat for literally any application?"*

| Threat | Generic? | Better Version |
|--------|----------|----------------|
| "Implement TLS" | Yes — applies to everything ❌ | "Driver could intercept ride destination via MITM to stalk the rider" ✅ |
| "Ensure proper authentication" | Yes — applies to everything ❌ | "Attacker changes direct deposit bank account to steal employee's salary" ✅ |
| "Implement rate limiting" | Yes — applies to everything ❌ | "Bots hoard all flash sale inventory for cart timeout duration, blocking real customers" ✅ |
| "Use a WAF" | Yes — applies to everything ❌ | "Attacker submits fake ride requests to trigger surge pricing in a specific area" ✅ |

### The Formula

**Business risk first → Technical control second**

❌ *"I would implement rate limiting to prevent DoS."*

✅ *"Attackers could create hundreds of fake ride requests to artificially trigger surge pricing, causing legitimate riders to pay inflated fares. I'd mitigate with anomaly detection on booking patterns, device fingerprinting, and rate limiting per account."*

---

## Scenario 1: Online Banking Application

**System:** Mobile app, web portal, API backend. Users check balances, transfer money, pay bills, deposit checks by photo.

**Components:** Mobile app, web portal, API backend, authentication service, account database, payment processor, check image processing service, notification service.

**Key trust boundaries:** Client apps ↔ API backend, backend ↔ payment processor, backend ↔ check image service, bank ↔ user's email/phone (for MFA).

| STRIDE | Top Threat | Attack | Business Impact | Mitigation |
|--------|-----------|--------|----------------|------------|
| **S** | Account takeover via credential stuffing | Attacker uses leaked credentials from other breaches to log into banking accounts | Unauthorized transfers, financial loss | MFA required, breached password list checks, risk-based authentication |
| **S** | SIM swap attacks | Attacker takes over victim's phone number to intercept SMS MFA codes | Complete account compromise bypassing MFA | Prefer TOTP/hardware keys over SMS, monitor for SIM change signals |
| **T** | Transaction modification in transit | Attacker modifies "transfer $100 to Alice" to "transfer $10,000 to attacker" | Direct financial loss | TLS with certificate pinning in mobile app, sign transactions with per-transaction nonce |
| **T** | Check image manipulation | Attacker modifies check photo to change the amount before server-side OCR | Fraudulent deposits | Server-side OCR cross-checked with user-entered amount, hold suspicious deposits for manual review |
| **R** | Payment disputes | Customer claims "I didn't authorize that transfer" | Investigation cost, potential reimbursement | Comprehensive audit logging with timestamp, IP, device fingerprint, geolocation, biometric confirmation for high-value transactions |
| **I** | PII at rest exposure | Account numbers, SSNs, transaction history stored in database | Regulatory penalties, identity theft at scale | Encrypt at rest with AES-256-GCM, application-layer encryption for sensitive fields, tokenize account numbers for PCI |
| **I** | Check images contain PII | Routing numbers, account numbers, signatures visible in check photos | Identity theft, account fraud | Encrypt check images at rest, strict access controls, auto-delete after retention period |
| **D** | Application-layer DDoS | Attacker floods login or check deposit API | Customers can't access accounts | WAF, rate limiting per IP and per account, CAPTCHA after failures, AWS Shield |
| **D** | Account lockout abuse | Attacker triggers lockout on legitimate users' accounts | Customers denied access to their own money | Progressive delays instead of permanent lockout, unlock via verified secondary channel |
| **E** | IDOR on account endpoints | Changing `/api/accounts/1001` to `/api/accounts/1002` to view another user's balance | Unauthorized access to financial data | Server-side authorization on every request, verify authenticated user owns the requested account |
| **E** | Transaction limit bypass | Attacker modifies client-side logic to bypass daily transfer limits | Large unauthorized transfers | Enforce all limits server-side, never rely on client validation |

**Priority:** *"Account takeover leads to direct financial loss. Check image fraud enables deposit manipulation. Both need immediate controls."*

---

## Scenario 2: Ride-Sharing Application

**System:** Rider app, driver app, backend API, payment service, GPS tracking, ratings, customer support.

**Components:** Rider app, driver app, backend API, payment processing, Google Maps integration, notification service, rating system, customer support portal, database.

**Key trust boundaries:** Rider app ↔ backend, driver app ↔ backend, backend ↔ payment processor, backend ↔ Google Maps API (location data leaves your infra), customer support ↔ backend (elevated access).

| STRIDE | Top Threat | Attack | Business Impact | Mitigation |
|--------|-----------|--------|----------------|------------|
| **S** | GPS spoofing by drivers | Driver fakes location to appear closer to riders or inflates trip distance | Customers overcharged, unfair driver advantage | Server-side trip distance validation comparing GPS data against expected route from maps API |
| **S** | Fake driver accounts | Attacker creates driver account with stolen identity to pick up riders | Physical safety risk, fraudulent payments collected | Identity verification with background checks, document verification, in-person activation |
| **T** | Fare manipulation via route tampering | Driver takes longer route, GPS data tampered to justify inflated fare | Customer overcharged | Server-side fare calculation comparing expected vs actual route, flag anomalies |
| **T** | Rating manipulation | Driver creates fake rider accounts to give themselves 5-star ratings | Unfair competitive advantage, erodes trust in rating system | Anomaly detection on rating patterns, device fingerprinting, minimum trip completion for rating eligibility |
| **R** | Safety incident disputes | Rider reports dangerous driver behavior, driver denies it | Legal liability, no evidence for resolution | Trip recording with GPS trail and timestamps, optional in-trip audio with consent |
| **I** | Post-trip stalking | After trip ends, driver retains access to rider's drop-off address or phone number | Physical safety risk — real-world incidents documented | Mask exact addresses after trip completion, phone number proxying so drivers never see real numbers |
| **I** | Google Maps data leakage | Every GPS coordinate sent to Google — sensitive for domestic violence survivors, public figures | Privacy violation under GDPR for location data | Review Google Maps data processing agreement, minimize location data sent, allow riders to opt out of precise tracking |
| **D** | Surge pricing manipulation | Attackers create hundreds of fake ride requests in an area to trigger surge pricing, then cancel | Legitimate riders pay inflated prices | Anomaly detection on booking patterns, device fingerprinting, rate limiting |
| **D** | Driver supply manipulation | Attacker books and cancels rides to keep drivers busy, reducing availability | Service degradation in target area | Cancellation penalties, pattern detection, progressive restrictions |
| **E** | Rider to driver endpoint access | Rider's account accesses driver API endpoints to view other riders' locations | Data breach, privacy violation | Strict role separation in API, separate authorization middleware per role |
| **E** | API key leakage from mobile APK | Attacker decompiles APK, extracts Google Maps API key, makes unlimited calls on your account | API cost explosion, potential service disruption | Never embed sensitive API keys in mobile apps, proxy all third-party API calls through backend |

**Priority:** *"GPS spoofing and surge pricing manipulation have the highest business impact — one causes direct customer overcharging, the other manipulates the entire pricing model. Post-trip stalking is the highest safety risk."*

---

## Scenario 3: E-Commerce Platform

**System:** Customer app, seller portal, shared backend API, payment via Stripe, warehouse integration API, review system, product catalog.

**Components:** Customer app, seller portal, shared backend API, Stripe payment integration, third-party warehouse/logistics API, review/rating system, product catalog, order management, search service.

**Key trust boundaries:** Client apps ↔ backend, backend ↔ Stripe (money moves here), backend ↔ warehouse API (API key-based), customer role ↔ seller role (same backend), seller ↔ seller (horizontal isolation).

| STRIDE | Top Threat | Attack | Business Impact | Mitigation |
|--------|-----------|--------|----------------|------------|
| **S** | Seller brand impersonation | Attacker creates fake seller mimicking legitimate brand, lists counterfeit products, collects payments, never ships | Customer financial loss, brand reputation damage, platform trust erosion | Seller identity verification with business registration, brand protection program |
| **S** | Seller account takeover | Attacker compromises high-rated seller, changes payout bank account, continues selling using stolen reputation | Payments redirected to attacker, seller financial loss | MFA on seller accounts, re-authentication for bank changes, 48-hour hold on payroll after bank modification, notification on payout changes |
| **T** | Price manipulation at checkout | Attacker modifies price in API request from $500 to $5, backend trusts client-submitted total | Direct revenue loss at scale | All pricing computed server-side, never trust client-submitted prices, sign cart contents with server hash |
| **T** | Review score tampering | Attacker submits crafted API request with `rating=5` regardless of UI selection, or uses bots for mass fake reviews | Marketplace integrity compromised, unfair seller advantage | Server-side review validation, device fingerprinting, minimum purchase requirement for reviews |
| **R** | Chargeback fraud | Customer receives product, disputes charge claiming non-delivery, seller loses product and money | Seller financial loss, platform absorbs chargeback fees | Delivery confirmation with signature/photo, weight verification at shipping, comprehensive audit trail |
| **R** | Seller ships empty box | Seller marks order shipped with valid tracking for wrong/empty package, claims they shipped correctly | Customer loss, dispute resolution cost | Weight verification at shipping, delivery photo requirement, buyer protection program |
| **I** | Seller analytics leakage | Competitor accesses another seller's sales volume, pricing history, inventory through API manipulation | Unfair competitive advantage, seller trust erosion | Strict authorization on analytics endpoints, object ownership validation on every request |
| **I** | Payment data leakage | Misconfigured Stripe integration logs or stores full card numbers | PCI violation, massive fines, customer identity theft | Full card numbers never touch your backend (Stripe handles), PCI compliance audit, never log payment data |
| **D** | Flash sale inventory hoarding | Bots add all inventory to cart during flash sale, hold for timeout, never checkout, block real customers | Lost sales, customer frustration, event failure | Progressive cart timeout, CAPTCHA, device fingerprinting, bot detection |
| **D** | Review bombing | Coordinated campaign floods competitor's product with 1-star reviews | Competitor's sales tank, marketplace manipulation | Anomaly detection on review patterns, rate limiting reviews per account, verified purchase requirement |
| **E** | Customer accessing seller endpoints | Shared backend — customer crafts requests to seller API endpoints to modify listings or view inventory | Marketplace integrity compromise, data breach | Server-side role enforcement on every endpoint, separate authorization middleware per role |
| **E** | Mass assignment on order status | API accepts `status` field in order update — customer sets order to "refunded" without returning product | Financial loss from fraudulent refunds | Allowlist fields per role, customers cannot modify order status |

**Priority:** *"Price manipulation causes direct revenue loss with a code fix. Flash sale abuse destroys sales events. Seller account takeover redirects real money. Fix server-side price validation first, then add bot detection, then bank change protections."*

---

## Scenario 4: Human Capital Management (HCM) Platform

**System:** Cloud-based, multi-tenant HCM. Employee self-service, payroll processing, manager portal, HR admin portal, time tracking, executive reporting dashboards and PDF reports.

**Components:** Employee portal, manager portal, HR admin portal, executive reporting module, payroll processing engine, time tracking service, direct deposit / banking integration, benefits enrollment system, tenant isolation layer, database (SSNs, salaries, bank accounts).

**Key trust boundaries:** Between tenants (most critical — breach exposes all clients), between role levels (employee/manager/HR/executive on shared backend), backend ↔ banking integration (money moves here), reporting module ↔ backend (PDF exports leave the system).

| STRIDE | Top Threat | Attack | Business Impact | Mitigation |
|--------|-----------|--------|----------------|------------|
| **S** | Payroll redirect attack | Attacker compromises employee self-service account, changes direct deposit bank account to attacker's account | Employee's salary stolen on next payroll cycle — #1 real-world HCM attack | Re-authentication for bank changes, notification to personal email, 24-48 hour hold on payroll after bank modification |
| **S** | Timesheet fraud | Employee modifies user ID in timesheet API to clock hours under a colleague's account | Payroll fraud, inflated overtime costs | Server-side user identity from session token not request params, dual approval for overtime |
| **T** | Salary manipulation | Manager or HR admin modifies compensation after approval, or employee intercepts and modifies performance review score | Unauthorized pay increases, financial loss to employer | Dual approval for compensation changes, audit trail with before/after values, backend validates against approved amounts |
| **T** | Timesheet tampering | Employee submits 40 hours, modifies API request to 60 before manager approval | Overpayment, payroll fraud | Backend validates submitted hours against clock-in/clock-out records, flag discrepancies for review |
| **R** | Termination disputes | Company terminates employee, employee claims never notified or termination was unauthorized | Legal liability, wrongful termination lawsuit | Immutable audit logs for all HR actions, digital acknowledgment from affected employee, logs in separate system HR admins cannot modify |
| **R** | Payroll disputes | Employee claims incorrect payment, no records to prove calculation was correct | Legal liability, back-pay claims | Immutable records of hours, rate, deductions, payment, and delivery confirmation for each pay period |
| **I** | Cross-tenant data exposure | HR admin from Company A changes tenant ID parameter, sees Company B's employee SSNs, salaries, bank accounts | Catastrophic breach affecting every client — regulatory penalties, lawsuits, platform death | Tenant ID derived from authenticated session server-side (never from client input), row-level security at database layer, tenant isolation testing |
| **I** | PDF report exposure | Executive downloads salary report, emails to personal account, leaves company — PDF has every employee's compensation | Salary data breach, employee trust erosion, potential discrimination lawsuits | Watermark PDFs with downloader's identity, log all downloads, consider view-only dashboards for sensitive data |
| **I** | Role-based data leakage | Manager sees compensation for teams outside their scope, or HR coordinator sees salary data they should only see benefits for | Privacy violation, internal trust erosion | Field-level access control (not just endpoint-level), role-scoped queries |
| **D** | Payroll processing disruption | Attacker crashes or delays payroll system on payday — employees across all tenants don't get paid | Legal liability (missed payroll deadlines), employee panic, massive client churn — unlike website downtime, missed payroll has legal consequences | Payroll runs in isolated infrastructure, circuit breakers between portal and payroll, redundant processing with automatic failover |
| **D** | Document upload abuse | Attacker uploads massive or malformed files through employee document upload (tax forms, IDs) | Resource exhaustion, processing crashes | File size limits, type validation with magic bytes, async processing with circuit breakers |
| **E** | Employee to manager escalation | Employee accesses manager API endpoints to approve their own PTO or view team salary data | Unauthorized PTO, salary data breach | Server-side role enforcement on every API endpoint, separate authorization middleware |
| **E** | Terminated employee retains access | Employee fired but account not deactivated immediately — downloads data, modifies records, or sabotages before revocation | Data breach, data destruction, sabotage | Immediate automated access revocation on termination, session invalidation across all devices, not dependent on manual HR action |
| **E** | HR admin cross-tenant access | HR admin at Company A escalates to Company B's admin portal through API manipulation | Multi-tenant breach, every client at risk | Tenant enforcement at API middleware layer (not frontend), automated tenant isolation testing |

**Priority:** *"Cross-tenant data isolation is #1 — a breach exposes every client simultaneously. Payroll redirect attacks are #2 — real money is stolen. Payroll availability is #3 — missed payroll has legal consequences unlike most other outages."*

---

## One-Line Recalls

| Topic | Recall |
|-------|--------|
| **STRIDE order** | "Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation — think: who are you, can you change it, can you deny it, can you see it, can you break it, can you do more than you should" |
| **Spoofing vs Info Disclosure vs EoP** | "Spoofing = faking identity, Info Disclosure = seeing wrong data, EoP = doing wrong actions — same vuln, different impact determines the category" |
| **Generic vs specific** | "Could I say this for any app? If yes, it's generic. GPS spoofing in ride-sharing, surge pricing manipulation, payroll redirect — those are specific." |
| **Business first** | "Business risk first, technical control second. Lead with what the attacker achieves, not what tool you'd deploy." |
| **Structure** | "Clarify → Components + Trust Boundaries → STRIDE with template → Prioritize. Five to seven minutes total." |
| **The template** | "For [letter], my top concern is [threat]. An attacker could [action], resulting in [business impact]. Mitigate with [control]." |

---

## Contributing

This reference guide is a living document. Contributions, corrections, and additions are welcome via pull request.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.