from collections import Counter
 
"""Return the top N source IPs with the most DENY entries.""" 
def top_denied_ips(logs, top_n=3):
    
    deny_ips = []
 
    for log in logs:
        parts = log.split()
        if parts[2] == "DENY":
            deny_ips.append(parts[3])
 
    ip_counts = Counter(deny_ips)
    return ip_counts.most_common(top_n)
 
 
if __name__ == "__main__":
    logs = [
        "2025-03-24 10:15:32 DENY 192.168.1.105 → 10.0.0.5:443",
        "2025-03-24 10:15:33 ALLOW 192.168.1.110 → 10.0.0.5:80",
        "2025-03-24 10:15:35 DENY 192.168.1.105 → 10.0.0.5:22",
        "2025-03-24 10:15:36 DENY 172.16.0.50 → 10.0.0.5:443",
        "2025-03-24 10:15:37 DENY 172.16.0.50 → 10.0.0.5:22",
        "2025-03-24 10:15:38 DENY 172.16.0.50 → 10.0.0.5:80",
        "2025-03-24 10:15:39 DENY 10.10.10.10 → 10.0.0.5:22",
    ]
 
    results = top_denied_ips(logs)
    for ip, count in results:
        print(f"{ip}: {count} denies")