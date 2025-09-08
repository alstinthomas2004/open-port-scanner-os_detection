Port Scanner with OS Fingerprinting 🔍
A Python-based network reconnaissance tool that performs fast port scanning and operating system detection using TTL (Time-To-Live) analysis. Built with Scapy for robust network packet manipulation.

https://img.shields.io/badge/Python-3.6%252B-blue
https://img.shields.io/badge/Scapy-2.5.0-green
https://img.shields.io/badge/License-MIT-yellow
https://img.shields.io/badge/Platform-Windows%2520%257C%2520Linux%2520%257C%2520macOS-lightgrey
https://img.shields.io/badge/Status-Stable-success

✨ Features
Fast SYN Scanning: Multithreaded port scanning using TCP SYN packets for efficient detection

OS Fingerprinting: Identifies operating systems through TTL value analysis

Cross-Platform: Works seamlessly on Windows, Linux, and macOS

Flexible Targeting: Scan specific ports, ranges, or custom port lists

Stealthy Operations: Uses SYN scanning instead of full TCP connections

Comprehensive Reporting: Detailed output with OS detection and open port listings

📸 Demo
Google DNS Scan (8.8.8.8)
https://images/demo-google.png

Local Router Scan (192.168.1.1)
https://images/demo-router.png

Windows Localhost Detection
https://images/demo-localhost.png

Cloudflare Security Scan
https://images/demo-cloudflare.png

🚀 Quick Start
Prerequisites
Python 3.6 or higher

Administrator/root privileges (for raw socket access)

Git (for cloning repository)

Installation
Clone the repository:

bash
git clone https://github.com/YOUR-USERNAME/port-scanner-os-detection.git
cd port-scanner-os-detection
Install dependencies:

bash
pip install -r requirements.txt
Basic Usage
bash
# Scan Google DNS (safe for testing)
python scanner.py 8.8.8.8

# Scan specific ports
python scanner.py 192.168.1.1 -p 80,443,22

# Scan port range with more threads
python scanner.py 10.0.0.1 -p 1-1000 -t 200
