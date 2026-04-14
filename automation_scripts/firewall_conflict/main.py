"""
FIREWALL RULE CONFLICT DETECTOR — CSV Rule Analysis

=====================================================================
REFERENCE NOTES — CSV Parsing, Tuple Keys, Conflict Detection
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Firewall misconfigurations are a top cause of security incidents
  - Conflicting rules create ambiguity — traffic may be allowed when
    it should be denied, or vice versa
  - Same analysis pattern applies to: IAM policy conflicts, security
    group rules in AWS, WAF rules, network ACLs, RBAC permissions
  - Auditing rulesets for conflicts is a core security engineer task


TYPES OF FIREWALL CONFLICTS:
-------------------------------
  DIRECT CONTRADICTION:
    Rule 11: ALLOW TCP 8080 from 0.0.0.0/0
    Rule 12: DENY  TCP 8080 from 0.0.0.0/0
    Same source, same port, opposite actions → definitely a bug.
    Behavior depends on rule order or firewall implementation.

  OVERLAPPING SCOPE:
    Rule 1: ALLOW TCP 22 from 10.0.0.0/8
    Rule 2: DENY  TCP 22 from 0.0.0.0/0
    Different sources, but 10.0.0.0/8 is inside 0.0.0.0/0.
    Intent: "Allow SSH from internal, deny from everywhere else."
    Risk: If rules are evaluated in wrong order, internal SSH is blocked.
    This MAY be intentional but is worth flagging for review.

  SHADOW RULES:
    A broad DENY before a specific ALLOW "shadows" the ALLOW —
    the specific rule never fires because the broad rule catches first.
    Detection requires knowing rule evaluation order.


TUPLE KEYS FOR GROUPING:
---------------------------
  Rules that apply to the same traffic share (direction, protocol, port).
  Using this as a tuple key groups them for conflict analysis:

    rule_groups = defaultdict(list)
    key = (rule["direction"], rule["protocol"], rule["port"])
    rule_groups[key].append(rule)

  After grouping:
    ("inbound", "TCP", "22") → [Rule 1 ALLOW, Rule 2 DENY]
    ("inbound", "TCP", "443") → [Rule 3 ALLOW]  ← no conflict

  Check each group: if actions set has both ALLOW and DENY → conflict.


CSV PARSING WITHOUT LIBRARIES:
---------------------------------
  For simple CSV (no quoted fields, no commas in values):
    header = lines[0].split(",")
    for line in lines[1:]:
        parts = line.split(",")

  For complex CSV (quoted fields, embedded commas):
    import csv
    reader = csv.DictReader(lines)

  In an interview, simple split is fine unless told otherwise.


SET OPERATIONS FOR CONFLICT DETECTION:
-----------------------------------------
  actions = {r["action"] for r in group_rules}

  This builds a set of unique actions in the group:
    {"ALLOW"}              → no conflict
    {"DENY"}               → no conflict
    {"ALLOW", "DENY"}      → CONFLICT

  Checking: "ALLOW" in actions and "DENY" in actions


ONE-LINE RECALLS:
------------------
  Tuple key:      "(direction, protocol, port) groups rules for same traffic"
  Conflict check: "Set of actions has both ALLOW and DENY → conflict"
  Direct vs scope: "Same source + opposite action = bug. Broad vs specific = review needed."
  CSV parsing:     "Simple CSV: split(',') on each line, skip header"

=====================================================================
"""

from collections import defaultdict


def parse_rules(rule_lines):
    """Parse CSV firewall rules into list of dicts."""
    rules = []
    for line in rule_lines[1:]:  # skip header
        parts = line.split(",")
        rules.append({
            "rule_id": parts[0],
            "direction": parts[1],
            "protocol": parts[2],
            "port": parts[3],
            "source": parts[4],
            "action": parts[5],
        })
    return rules


def detect_conflicts(rule_lines):
    """
    Detect conflicting firewall rules.

    Groups rules by (direction, protocol, port) and flags groups
    that contain both ALLOW and DENY actions.

    Distinguishes between:
      - Direct contradictions (same source, opposite actions — definitely a bug)
      - Overlapping scope (broad vs specific source — may be intentional but risky)

    Args:
        rule_lines: List of CSV strings including header

    Returns:
        List of conflict dicts with details
    """
    rules = parse_rules(rule_lines)

    # Group rules by (direction, protocol, port)
    rule_groups = defaultdict(list)
    for rule in rules:
        key = (rule["direction"], rule["protocol"], rule["port"])
        rule_groups[key].append(rule)

    # Find conflicts: groups with both ALLOW and DENY
    conflicts = []

    for key, group_rules in rule_groups.items():
        actions = {r["action"] for r in group_rules}

        if "ALLOW" in actions and "DENY" in actions:
            allow_rules = [r for r in group_rules if r["action"] == "ALLOW"]
            deny_rules = [r for r in group_rules if r["action"] == "DENY"]

            # Direct contradictions: same source with both ALLOW and DENY
            direct = []
            for a in allow_rules:
                for d in deny_rules:
                    if a["source"] == d["source"]:
                        direct.append({
                            "allow_rule": a["rule_id"],
                            "deny_rule": d["rule_id"],
                            "source": a["source"],
                        })

            # Overlapping scope: 0.0.0.0/0 conflicts with specific subnet
            overlapping = []
            for a in allow_rules:
                for d in deny_rules:
                    if a["source"] != d["source"]:
                        if a["source"] == "0.0.0.0/0" or d["source"] == "0.0.0.0/0":
                            overlapping.append({
                                "allow_rule": a["rule_id"],
                                "allow_source": a["source"],
                                "deny_rule": d["rule_id"],
                                "deny_source": d["source"],
                            })

            severity = "CRITICAL" if direct else "MEDIUM"

            conflicts.append({
                "direction": key[0],
                "protocol": key[1],
                "port": key[2],
                "severity": severity,
                "allow_rules": allow_rules,
                "deny_rules": deny_rules,
                "direct_contradictions": direct,
                "overlapping_scope": overlapping,
            })

    return sorted(conflicts, key=lambda x: x["severity"])


def audit_summary(rule_lines):
    """Generate a full audit summary of the firewall ruleset."""
    rules = parse_rules(rule_lines)
    conflicts = detect_conflicts(rule_lines)

    # Additional checks
    open_to_internet = [
        r for r in rules
        if r["source"] == "0.0.0.0/0" and r["action"] == "ALLOW"
    ]

    dangerous_ports = {"22", "3389", "3306", "5432", "6379"}
    exposed_dangerous = [
        r for r in open_to_internet
        if r["port"] in dangerous_ports
    ]

    return {
        "total_rules": len(rules),
        "conflicts": conflicts,
        "open_to_internet": open_to_internet,
        "dangerous_ports_exposed": exposed_dangerous,
    }


if __name__ == "__main__":
    firewall_rules = [
        "rule_id,direction,protocol,port,source,action",

        # === Port 22 (SSH) — OVERLAPPING SCOPE ===
        # Allow from internal, deny from everywhere
        # Intent is clear but order-dependent
        "1,inbound,TCP,22,10.0.0.0/8,ALLOW",
        "2,inbound,TCP,22,0.0.0.0/0,DENY",

        # === Port 443 (HTTPS) — NO CONFLICT ===
        "3,inbound,TCP,443,0.0.0.0/0,ALLOW",

        # === Port 80 (HTTP) — OVERLAPPING SCOPE ===
        # Allow from everywhere, deny from specific subnet
        "4,inbound,TCP,80,0.0.0.0/0,ALLOW",
        "5,inbound,TCP,80,192.168.1.0/24,DENY",

        # === Port 443 outbound — NO CONFLICT ===
        "6,outbound,TCP,443,0.0.0.0/0,ALLOW",

        # === Port 53 (DNS) — OVERLAPPING SCOPE ===
        # Allow DNS from everywhere, deny from internal
        "7,inbound,UDP,53,0.0.0.0/0,ALLOW",
        "8,inbound,UDP,53,10.0.0.0/8,DENY",

        # === Port 3389 (RDP) — NO CONFLICT (only DENY) ===
        "9,inbound,TCP,3389,0.0.0.0/0,DENY",

        # === Port 3306 (MySQL) — NO CONFLICT (only ALLOW) ===
        "10,inbound,TCP,3306,10.0.0.0/8,ALLOW",

        # === Port 8080 — DIRECT CONTRADICTION ===
        # Same source, same port, opposite actions — definitely a bug
        "11,inbound,TCP,8080,0.0.0.0/0,ALLOW",
        "12,inbound,TCP,8080,0.0.0.0/0,DENY",
    ]

    print("=== Firewall Rule Conflict Analysis ===\n")

    conflicts = detect_conflicts(firewall_rules)

    if conflicts:
        for conflict in conflicts:
            severity = conflict["severity"]
            print(f"  [{severity}] {conflict['direction']} {conflict['protocol']}/{conflict['port']}")

            if conflict["direct_contradictions"]:
                print(f"    DIRECT CONTRADICTION:")
                for dc in conflict["direct_contradictions"]:
                    print(f"      Rule {dc['allow_rule']} (ALLOW) vs Rule {dc['deny_rule']} (DENY)")
                    print(f"      Same source: {dc['source']} — this is a bug")

            if conflict["overlapping_scope"]:
                print(f"    OVERLAPPING SCOPE:")
                for ov in conflict["overlapping_scope"]:
                    print(f"      Rule {ov['allow_rule']} (ALLOW {ov['allow_source']}) vs Rule {ov['deny_rule']} (DENY {ov['deny_source']})")
                    print(f"      Behavior depends on rule evaluation order")

            print()
    else:
        print("  No conflicts detected.")

    # Full audit
    print("=== Full Audit Summary ===\n")
    audit = audit_summary(firewall_rules)
    print(f"  Total rules: {audit['total_rules']}")
    print(f"  Conflicts found: {len(audit['conflicts'])}")
    print(f"  Ports open to internet: {len(audit['open_to_internet'])}")

    if audit["dangerous_ports_exposed"]:
        print(f"\n  WARNING — Dangerous ports open to 0.0.0.0/0:")
        for r in audit["dangerous_ports_exposed"]:
            print(f"    Rule {r['rule_id']}: {r['protocol']}/{r['port']} ({r['action']})")

    # Expected output:
    # CRITICAL: TCP/8080 — direct contradiction (rules 11 vs 12, same source)
    # MEDIUM: TCP/22 — overlapping scope (rules 1 vs 2)
    # MEDIUM: TCP/80 — overlapping scope (rules 4 vs 5)
    # MEDIUM: UDP/53 — overlapping scope (rules 7 vs 8)
    # No dangerous ports exposed to internet (SSH is ALLOW from internal only)