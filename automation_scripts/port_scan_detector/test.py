"""
192.168.1.10:44312 -> 10.0.0.5:22
192.168.1.10:44313 -> 10.0.0.5:80
192.168.1.10:44314 -> 10.0.0.6:443
192.168.1.10:44315 -> 10.0.0.6:80
10.10.10.10:60001 -> 10.0.0.5:22
10.10.10.10:60002 -> 10.0.0.5:23
10.10.10.10:60003 -> 10.0.0.5:25
10.10.10.10:60004 -> 10.0.0.5:80
10.10.10.10:60005 -> 10.0.0.5:443
172.16.0.50:55001 -> 10.0.0.5:443
172.16.0.50:55002 -> 10.0.0.5:80
"""
from collections import Counter
def parse_log(logs):
    s_ips = []
    port_scanners = {}
    for log in logs:
        s_ip = log.split()[0].split(':')[0]
        d_ip = log.split()[2].split(':')[0]
        d_port = log.split()[2].split(':')[1]
        if port_scanners.get((s_ip,d_ip)) is None:
            port_scanners[(s_ip,d_ip)] = set()
        port_scanners[(s_ip,d_ip)].add(d_port)

    for (s_ip,d_ip),d_port in port_scanners.items():
        if(len(d_port)>3):
            s_ips.append([s_ip,len(d_port)])
    print(s_ips)    
    # s_ip_count = Counter(port_scanners).most_common(1)
    # print(s_ip_count)
    return s_ips

if __name__=="__main__":
    with open("connections.txt","r") as f:
        lines = f.read().splitlines()
    
    result = parse_log(lines)