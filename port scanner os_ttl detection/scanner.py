#!/usr/bin/env python3
"""
Port Scanner with OS Fingerprinting - FIXED VERSION
"""

import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
import logging
import time

# Suppress Scapy warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def port_scan(ip, port, timeout=1):
    """Scan a single port using Scapy (SYN scan) - FIXED"""
    try:
        # Send SYN packet with random source port
        src_port = RandShort()
        pkt = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0, retry=0)

        if resp is None:
            return port, False  # No response

        if resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close the connection politely
                send(IP(dst=ip)/TCP(sport=src_port,
                     dport=port, flags="R"), verbose=0)
                return port, True
            elif resp[TCP].flags == 0x14:  # RST-ACK
                return port, False  # Closed port
        return port, False

    except Exception as e:
        return port, False


def analyze_os(ip):
    """Analyze OS based on TTL from ICMP response - FIXED"""
    try:
        print(f"[*] Sending ICMP request to {ip}...")
        # Send ICMP echo request with timeout
        ans = sr1(IP(dst=ip)/ICMP(), timeout=3, verbose=0, retry=2)

        if ans is None:
            print("[-] No ICMP response received")
            return "Unknown (No ICMP response)", 0

        if ans.haslayer(IP):
            ttl = ans[IP].ttl
            print(f"[+] Received response with TTL: {ttl}")

            # OS fingerprinting based on TTL
            if 55 <= ttl <= 64:
                return "Linux/Unix", ttl
            elif 120 <= ttl <= 128:
                return "Windows", ttl
            elif 220 <= ttl <= 255:
                return "Solaris/Cisco", ttl
            else:
                return f"Unknown (TTL: {ttl})", ttl
        else:
            return "Unknown (No IP layer)", 0

    except Exception as e:
        print(f"[-] OS detection error: {e}")
        return "Unknown (Error)", 0


def parse_ports(ports_arg):
    """Parse port range argument"""
    ports = set()

    for part in ports_arg.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


def port_scan_all(ip, ports_to_scan, max_workers=50, timeout=1):
    """Scan multiple ports efficiently"""
    open_ports = []

    print(f"[*] Scanning ports: {ports_to_scan}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(port_scan, ip, port, timeout): port
            for port in ports_to_scan
        }

        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"[+] Found open port: {port}")

    return open_ports


def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner with OS Fingerprinting",
        epilog="Example: python scanner.py 8.8.8.8 -p 53,80,443"
    )

    parser.add_argument("target", help="Target IP address")
    parser.add_argument(
        "-p", "--ports", help="Ports to scan", default="53,80,443")
    parser.add_argument("-t", "--threads",
                        help="Number of threads", type=int, default=30)
    parser.add_argument("--timeout", help="Timeout per port",
                        type=float, default=2)

    args = parser.parse_args()

    # Check admin privileges on Windows
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] ERROR: Administrator privileges required!")
                print("[-] Please run PowerShell as Administrator")
                print("[-] Right-click PowerShell → 'Run as administrator'")
                return
            else:
                print("[+] Running with administrator privileges")
        except ImportError:
            pass

    try:
        target_ip = args.target
        ports_to_scan = parse_ports(args.ports)

        print(f"[*] Target: {target_ip}")
        print(f"[*] Ports to scan: {ports_to_scan}")
        print(f"[*] Threads: {args.threads}")
        print(f"[*] Timeout: {args.timeout}s")
        print("-" * 50)

        # OS detection first
        print("[*] Performing OS detection...")
        os_guess, ttl = analyze_os(target_ip)
        print(f"[+] OS Detection: {os_guess}")

        print("-" * 50)
        print("[*] Starting port scan...")
        start_time = time.time()

        open_ports = port_scan_all(
            target_ip, ports_to_scan, args.threads, args.timeout)

        scan_time = time.time() - start_time
        print("-" * 50)
        print(f"[+] Scan completed in {scan_time:.2f} seconds!")
        print(f"[+] Open ports: {sorted(open_ports)}")
        print(f"[+] Total open ports: {len(open_ports)}")

    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
