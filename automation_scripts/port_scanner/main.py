"""
TCP PORT SCANNER — Network Reconnaissance Tool

=====================================================================
REFERENCE NOTES — Sockets, argparse, Error Handling, Networking
=====================================================================

WHY WRITE A PORT SCANNER WHEN NMAP EXISTS?
--------------------------------------------
  In production, you'd use nmap, masscan, or netcat — not this script.
  So why build one?
 
  1. LOCKED-DOWN SYSTEM, NO TOOLS:
     You're on a compromised host during an IR investigation or pentest.
     No nmap, no netcat installed — but Python is there (it's on almost
     every Linux box). You need quick recon from that host.
 
  2. CUSTOM LOGIC:
     You need to scan ports AND immediately send a specific HTTP request
     to every open port to check for a vulnerable endpoint. Or correlate
     results with an internal asset database in real-time. Off-the-shelf
     tools don't do that — you build on top of socket fundamentals.
 
  3. BUILDING DETECTION, NOT OFFENSE:
     Understanding how scanners work at the socket level lets you write
     better detection rules. A connect scan opens a TCP connection and
     immediately closes it without sending data — if you know that
     pattern, you can detect it in network logs and IDS rules.
 
  4. INTERVIEW FUNDAMENTALS:
     Google wants to know you understand what happens at the socket level
     when a connection is made — not that you can type "nmap -sV".

    COMPARISON OF TOOLS:
        nmap     → gold standard. SYN scanning, OS fingerprinting, scripting engine
        netcat   → quick one-off checks. nc -zv 192.168.1.1 80
        masscan  → internet-scale. Can scan all of port 443 in under 6 minutes
        Python   → custom logic, constrained environments, understanding fundamentals

SOCKET BASICS:
---------------
  A socket is an endpoint for network communication. Think of it as
  a phone — you create it, dial a number (IP + port), and either
  someone picks up (open) or they don't (closed/filtered).

  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    AF_INET      → use IPv4 (most common)
    AF_INET6     → use IPv6
    SOCK_STREAM  → use TCP (reliable, connection-based)
    SOCK_DGRAM   → use UDP (fast, connectionless)

  socket.socket() with no args defaults to AF_INET + SOCK_STREAM (TCP/IPv4).


connect() vs connect_ex():
----------------------------
  sock.connect((ip, port))      → raises an EXCEPTION on failure
  sock.connect_ex((ip, port))   → returns an ERROR CODE on failure

  connect_ex returns:
    0   → connection succeeded (port is OPEN)
    non-zero → connection failed (port is CLOSED or FILTERED)

  For a port scanner, connect_ex is better because you don't need
  try/except for every single port — just check if result == 0.


settimeout():
--------------
  sock.settimeout(0.5)   → give up after 0.5 seconds

  Without this, a filtered port (firewall drops packets silently)
  would hang for 30+ seconds waiting for a response. With 1024 ports,
  that's potentially 8+ hours of waiting.

  Good timeout values:
    0.5s  → localhost or fast LAN
    1-2s  → remote hosts on good networks
    3-5s  → slow or distant hosts


PORT STATES — WHAT HAPPENS WHEN YOU SCAN:
-------------------------------------------
  OPEN      → target responds with SYN-ACK → connection succeeds
              A service is listening on this port.

  CLOSED    → target responds with RST (reset) → connection refused
              Host is up but nothing is listening on this port.

  FILTERED  → no response at all → connection times out
              A firewall is silently dropping your packets.


setsockopt(SOL_SOCKET, SO_REUSEADDR, 1):
-------------------------------------------
  When you close a socket, the OS holds the port in TIME_WAIT state
  for 30-60 seconds. If you try to bind the same port again, you get
  "Address already in use" error.

  SO_REUSEADDR tells the OS: "let me reuse this port immediately."
  Only needed for SERVERS (bind/listen), not for clients (connect).
  Useful when testing — you'll restart your listener many times.


ARGPARSE — COMMAND-LINE ARGUMENTS:
------------------------------------
  argparse reads command-line args and converts them to the right types.

  Positional args (required):
    parser.add_argument("target", help="Target IP")
    parser.add_argument("port", type=int, help="Port number")

  Optional args (flags):
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

  Usage:  python script.py 127.0.0.1 80 --timeout 2 -v
  Access: args.target, args.port, args.timeout, args.verbose

  Auto-generates --help for free:
    python script.py --help


TRY / EXCEPT / FINALLY:
-------------------------
  try:
      # code that might fail
  except SpecificError as e:
      # handle that specific error
  except Exception as e:
      # handle any other error
  finally:
      # ALWAYS runs — even if an exception occurred
      # use for cleanup like closing sockets/files

  Why finally matters for sockets:
    Without finally, if an error happens BEFORE sock.close(), the socket
    stays open. Enough leaked sockets = "Too many open files" crash.


KeyboardInterrupt:
--------------------
  try:
      long_running_scan()
  except KeyboardInterrupt:
      print("Scan cancelled by user.")

  Catches Ctrl+C cleanly instead of dumping an ugly stack trace.
  Important for any script that runs for a while (scanning 65535 ports).


HOW TO TEST THIS SCRIPT:
--------------------------
  # Test 1: Scan localhost for common ports
  python port_scanner.py 127.0.0.1 1 1024

  # Test 2: Start a listener in one terminal, scan in another
  # Terminal 1:
  python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',9999)); s.listen(1); input('Listening...')"
  # Terminal 2:
  python port_scanner.py 127.0.0.1 9990 10000

  # Test 3: Scan a specific known port
  python port_scanner.py 127.0.0.1 22 22


ONE-LINE RECALLS:
------------------
  Socket:          "socket() creates it, connect_ex() tests it, 0 means open"
  Timeout:         "settimeout() prevents hanging on filtered ports — always set it"
  connect_ex:      "Returns 0 for open, non-zero for closed/filtered — no exceptions"
  finally:         "finally ALWAYS runs — use it to close sockets and files"
  argparse:        "Positional args are required, --flag args are optional with defaults"
  SO_REUSEADDR:    "Lets you rebind a port immediately — use in test servers"

=====================================================================
"""

import socket
import argparse


def scan_ports(target, start_port, end_port, timeout=0.5):
    """Scan a range of TCP ports on the target and return open ports."""
    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"  Port {port}: OPEN")
        except socket.error as e:
            print(f"  Port {port}: ERROR - {e}")
        finally:
            sock.close()

    return open_ports


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("start_port", type=int, help="Start of port range")
    parser.add_argument("end_port", type=int, help="End of port range")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Timeout per port in seconds (default: 0.5)")

    args = parser.parse_args()

    print(f"Scanning {args.target} ports {args.start_port}-{args.end_port}...")

    try:
        open_ports = scan_ports(args.target, args.start_port, args.end_port, args.timeout)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        exit(1)

    print(f"\nScan complete. {len(open_ports)} open port(s) found.")
    if open_ports:
        print(f"Open ports: {open_ports}")