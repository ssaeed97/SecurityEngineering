"""
CLOUDTRAIL LOG ANALYZER - AWS API Call Security Monitor

=====================================================================
REFERENCE NOTES - Tiered Detection, JSON Parsing, AWS Attack Patterns
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - CloudTrail logs every API call in an AWS account
  - After account compromise, attackers follow predictable patterns:
    launch resources, exfiltrate data, create persistence, cover tracks
  - Detection engineering requires categorizing events by risk level
    and checking parameters, not just event names
  - This exact skill is used in building SIEM detection rules,
    GuardDuty custom detections, and incident response runbooks


AWS ACCOUNT COMPROMISE - THE ATTACKER PLAYBOOK:
--------------------------------------------------
  1. DISCOVERY    → DescribeInstances, ListBuckets, GetCallerIdentity
  2. CRYPTOMINING → RunInstances with GPU types (p3, p4, g4, g5)
  3. DATA THEFT   → PutBucketPolicy with Principal:* (make bucket public)
  4. PERSISTENCE  → CreateAccessKey, CreateUser (backdoor credentials)
  5. COVER TRACKS → StopLogging, DeleteTrail (disable CloudTrail)
  6. LATERAL MOVE → AuthorizeSecurityGroupIngress 0.0.0.0/0 (open SSH)

  Knowing this playbook lets you build detections for each stage.


TIERED DETECTION STRATEGY:
-----------------------------
  Tier 1 - ALWAYS SUSPICIOUS:
    Certain API calls are almost never made in normal operations.
    Any occurrence is worth alerting on immediately.
    Examples: StopLogging, DeleteTrail, CreateAccessKey

    Implementation: a set of event names → O(1) membership check

  Tier 2 - SUSPICIOUS DEPENDING ON PARAMETERS:
    Normal API calls that become dangerous with certain inputs.
    Examples:
      RunInstances with 10x GPU instances → cryptomining
      PutBucketPolicy with Principal:* → public data exposure
      AuthorizeSecurityGroupIngress with 0.0.0.0/0 → open to internet

    Implementation: if/elif conditions checking specific parameter values

  Tier 3 - SUSPICIOUS IN AGGREGATE:
    Individual events look fine, but the pattern is concerning.
    Examples:
      Same user from multiple IPs → credential compromise
      High volume of API calls → automated attack tool
      Accessing many different S3 buckets → data exfiltration

    Implementation: defaultdict/Counter tracking state across all events


JSON NAVIGATION - SAFELY ACCESSING NESTED DATA:
--------------------------------------------------
  CloudTrail events are deeply nested JSON. Keys might be missing.

  BAD - crashes on missing keys:
    event["requestParameters"]["bucketName"]   # KeyError if missing

  GOOD - safe navigation with .get() and defaults:
    params = event.get("requestParameters") or {}
    bucket = params.get("bucketName", "unknown")

  The `or {}` handles the case where requestParameters is None
  (not just missing, but explicitly null in the JSON).


SETS FOR FAST MEMBERSHIP CHECKS:
-----------------------------------
  high_risk = {"StopLogging", "DeleteTrail", "CreateAccessKey"}

  "StopLogging" in high_risk   # O(1) - instant, regardless of set size
  "GetObject" in high_risk     # O(1) - instant "no"

  Compare to a list:
  ["StopLogging", "DeleteTrail", "CreateAccessKey"]
  "GetObject" in list_version  # O(n) - must check every element


ONE-LINE RECALLS:
------------------
  Tiered detection: "Tier 1 = always bad (set lookup), Tier 2 = bad with
                     certain params (conditional), Tier 3 = bad in aggregate
                     (Counter/defaultdict)"
  AWS playbook:     "Cryptomine → exfiltrate → persist → cover tracks"
  Safe JSON:        ".get(key, default) chains with 'or {}' for null values"
  Sets:             "O(1) membership check - perfect for 'is this event
                     in the dangerous list?'"

=====================================================================
"""

from collections import defaultdict, Counter


def analyze_cloudtrail(logs):
    """
    Analyze CloudTrail logs for suspicious activity across three tiers.

    Tier 1: Inherently high-risk API calls (always flag)
    Tier 2: Normal calls with dangerous parameters (flag conditionally)
    Tier 3: Suspicious aggregate patterns (flag based on behavior)

    Args:
        logs: List of CloudTrail event dicts

    Returns:
        List of alert dicts sorted by tier and severity
    """

    # === TIER 1: Always suspicious API calls ===
    high_risk_events = {
        # Disabling audit / covering tracks
        "StopLogging", "DeleteTrail", "UpdateTrail",
        # Creating credentials / persistence
        "CreateAccessKey", "CreateLoginProfile", "CreateUser",
        # Modifying permissions
        "PutUserPolicy", "AttachUserPolicy", "AttachRolePolicy",
        # Weakening security
        "DeleteBucketEncryption", "DeleteFlowLogs",
        "DisableEbsEncryptionByDefault",
    }

    # === Detection state ===
    alerts = []
    user_ip_map = defaultdict(set)       # track IPs per user
    user_event_count = Counter()          # track event volume per user

    for event in logs:
        event_name = event.get("eventName", "")
        ip = event.get("sourceIPAddress", "unknown")
        user = event.get("userIdentity", {}).get("userName", "unknown")
        time = event.get("eventTime", "")
        params = event.get("requestParameters") or {}

        # Track aggregate stats
        user_ip_map[user].add(ip)
        user_event_count[user] += 1

        # --- Tier 1: High-risk event check ---
        if event_name in high_risk_events:
            alerts.append({
                "tier": 1,
                "severity": "HIGH",
                "event": event_name,
                "user": user,
                "ip": ip,
                "time": time,
                "reason": f"High-risk API call: {event_name}",
            })

        # --- Tier 2: Parameter-based detection ---

        # RunInstances - expensive or high-count launches (cryptomining)
        if event_name == "RunInstances":
            count = params.get("minCount", 1)
            instance_type = params.get("instanceType", "")
            expensive_types = {"p3.", "p4.", "g4.", "g5.", "inf1.", "trn1."}

            if count > 5 or any(instance_type.startswith(t) for t in expensive_types):
                alerts.append({
                    "tier": 2,
                    "severity": "HIGH",
                    "event": event_name,
                    "user": user,
                    "ip": ip,
                    "time": time,
                    "reason": f"Launching {count}x {instance_type} - possible cryptomining",
                })

        # PutBucketPolicy - public access (data exposure)
        if event_name == "PutBucketPolicy":
            policy = str(params.get("policy", ""))
            bucket = params.get("bucketName", "unknown")
            if '"Principal":"*"' in policy or '"Principal": "*"' in policy:
                alerts.append({
                    "tier": 2,
                    "severity": "CRITICAL",
                    "event": event_name,
                    "user": user,
                    "ip": ip,
                    "time": time,
                    "reason": f"Bucket '{bucket}' policy set to public (Principal: *)",
                })

        # AuthorizeSecurityGroupIngress - open to the world
        if event_name == "AuthorizeSecurityGroupIngress":
            ip_perms = params.get("ipPermissions", {}).get("items", [])
            for perm in ip_perms:
                port = perm.get("fromPort", "")
                ranges = perm.get("ipRanges", {}).get("items", [])
                for r in ranges:
                    if r.get("cidrIp") == "0.0.0.0/0":
                        alerts.append({
                            "tier": 2,
                            "severity": "HIGH",
                            "event": event_name,
                            "user": user,
                            "ip": ip,
                            "time": time,
                            "reason": f"Port {port} opened to 0.0.0.0/0 (entire internet)",
                        })

    # --- Tier 3: Aggregate pattern detection ---

    # Multiple IPs per user (possible credential compromise)
    for user, ips in user_ip_map.items():
        if len(ips) > 1:
            alerts.append({
                "tier": 3,
                "severity": "MEDIUM",
                "event": "MultipleSourceIPs",
                "user": user,
                "ip": ", ".join(sorted(ips)),
                "time": "aggregate",
                "reason": f"User '{user}' seen from {len(ips)} different IPs",
            })

    # High event volume per user (possible automated attack)
    for user, count in user_event_count.items():
        if count > 5:
            alerts.append({
                "tier": 3,
                "severity": "MEDIUM",
                "event": "HighEventVolume",
                "user": user,
                "ip": "aggregate",
                "time": "aggregate",
                "reason": f"User '{user}' made {count} API calls - unusual volume",
            })

    return sorted(alerts, key=lambda x: (x["tier"], x["severity"]))


if __name__ == "__main__":
    cloudtrail_logs = [
        # developer1 - NORMAL: reading instances and S3 objects
        {
            "eventTime": "2025-04-09T10:15:32Z",
            "eventName": "DescribeInstances",
            "sourceIPAddress": "10.0.0.5",
            "userIdentity": {"userName": "developer1", "type": "IAMUser"},
            "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-abc123"}]}},
            "responseElements": None,
            "errorCode": None,
        },
        {
            "eventTime": "2025-04-09T10:15:35Z",
            "eventName": "GetObject",
            "sourceIPAddress": "10.0.0.5",
            "userIdentity": {"userName": "developer1", "type": "IAMUser"},
            "requestParameters": {"bucketName": "internal-docs", "key": "readme.md"},
            "responseElements": None,
            "errorCode": None,
        },
        {
            "eventTime": "2025-04-09T10:15:41Z",
            "eventName": "GetObject",
            "sourceIPAddress": "10.0.0.5",
            "userIdentity": {"userName": "developer1", "type": "IAMUser"},
            "requestParameters": {"bucketName": "internal-docs", "key": "architecture.pdf"},
            "responseElements": None,
            "errorCode": None,
        },

        # admin from 203.45.167.22 - ATTACK SEQUENCE:
        # Step 1: Launch GPU instances (cryptomining)
        {
            "eventTime": "2025-04-09T10:15:33Z",
            "eventName": "RunInstances",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {"instanceType": "p3.16xlarge", "minCount": 10},
            "responseElements": {"instancesSet": {"items": []}},
            "errorCode": None,
        },
        # Step 2: Make customer data bucket public (data exposure)
        {
            "eventTime": "2025-04-09T10:15:34Z",
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {
                "bucketName": "customer-data-prod",
                "policy": '{"Effect":"Allow","Principal":"*"}',
            },
            "responseElements": None,
            "errorCode": None,
        },
        # Step 3: Create backdoor credentials (persistence)
        {
            "eventTime": "2025-04-09T10:15:36Z",
            "eventName": "CreateAccessKey",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {"userName": "backdoor-user"},
            "responseElements": {"accessKey": {"accessKeyId": "AKIA1234567890"}},
            "errorCode": None,
        },
        # Step 4: Disable logging (cover tracks)
        {
            "eventTime": "2025-04-09T10:15:38Z",
            "eventName": "StopLogging",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {"name": "main-trail"},
            "responseElements": None,
            "errorCode": None,
        },
        {
            "eventTime": "2025-04-09T10:15:39Z",
            "eventName": "DeleteTrail",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {"name": "main-trail"},
            "responseElements": None,
            "errorCode": None,
        },
        # Step 5: Open SSH to the internet (lateral movement)
        {
            "eventTime": "2025-04-09T10:15:40Z",
            "eventName": "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "203.45.167.22",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": {
                "ipPermissions": {
                    "items": [{
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]
                }
            },
            "responseElements": None,
            "errorCode": None,
        },

        # admin from DIFFERENT IP - triggers multi-IP detection
        {
            "eventTime": "2025-04-09T10:15:37Z",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.44",
            "userIdentity": {"userName": "admin", "type": "IAMUser"},
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "errorCode": None,
        },
    ]

    alerts = analyze_cloudtrail(cloudtrail_logs)

    print("=== CloudTrail Security Analysis ===\n")

    if not alerts:
        print("  No suspicious activity detected.")
    else:
        current_tier = None
        for alert in alerts:
            if alert["tier"] != current_tier:
                current_tier = alert["tier"]
                tier_labels = {
                    1: "TIER 1 - High-Risk API Calls",
                    2: "TIER 2 - Dangerous Parameters",
                    3: "TIER 3 - Aggregate Patterns",
                }
                print(f"\n--- {tier_labels.get(current_tier, 'Unknown')} ---\n")

            print(f"  [{alert['severity']}] {alert['event']}")
            print(f"    User: {alert['user']} | IP: {alert['ip']}")
            print(f"    Time: {alert['time']}")
            print(f"    Reason: {alert['reason']}")
            print()

    # Summary
    print("=== Summary ===")
    print(f"  Total alerts: {len(alerts)}")
    for tier in [1, 2, 3]:
        tier_alerts = [a for a in alerts if a["tier"] == tier]
        if tier_alerts:
            print(f"  Tier {tier}: {len(tier_alerts)} alerts")

    # Expected output:
    # TIER 1: StopLogging, DeleteTrail, CreateAccessKey (3 alerts)
    # TIER 2: RunInstances GPU, PutBucketPolicy public, SecurityGroup 0.0.0.0/0 (3 alerts)
    # TIER 3: admin from multiple IPs, admin high event volume (2 alerts)
    # developer1: NO alerts (normal read activity)