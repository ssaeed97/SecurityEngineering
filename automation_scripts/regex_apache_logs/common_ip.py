from collections import Counter
import re

'''
10.0.0.1 - - [24/Mar/2025:10:15:34 +0000] "GET /../../etc/passwd HTTP/1.1" 403 256
203.45.167.22 - - [24/Mar/2025:10:15:35 +0000] "POST /admin/login HTTP/1.1" 401 512
172.16.0.100 - - [24/Mar/2025:10:15:36 +0000] "GET /index.html HTTP/1.1" 200 2048
203.45.167.22 - - [24/Mar/2025:10:15:37 +0000] "POST /admin/login HTTP/1.1" 200 1536
10.0.0.1 - - [24/Mar/2025:10:15:38 +0000] "GET /api/../../../etc/shadow HTTP/1.1" 403 256
'''
def parser(lines):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(\S+).*?"(\S*)\s(.*?)"\s(\d+)\s(\d+)'
    log = 0
    logs = {}
    for line in lines:
        match = re.search(pattern,line)
        if not match:
            continue
        ip=match.group(1)
        datetime=match.group(2)
        method=match.group(3)
        path=match.group(4)
        status=match.group(5)
        byte_count=match.group(6)
        logs[log] = {"IP": ip, "DateTime": datetime, "Method": method, "Path": path, "Status": status, "Byte Count": byte_count}
        log+=1
    return logs
    
def common_ips(lines):
    ips = []
    for line in lines:
        ips.append(line.split()[0])
    ips = [line.split()[0] for line in lines]
    return Counter(ips).most_common(2)

if __name__ == "__main__":
    with open("raw_log_2.txt","r") as f:
        lines = f.read().splitlines()
    parsed_logs = parser(lines)
    #print(parsed_logs)
    for key,value in parsed_logs.items():
        
        print(value,end = " ")
        print("\n")
    
    common_ip = common_ips(lines)
    print(", ".join(f"IP{i}: {ip}" for i, ip in enumerate(common_ip, start=1)))
