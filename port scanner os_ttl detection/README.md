# Port Scanner with OS Fingerprinting 🔍

A Python-based network reconnaissance tool that performs fast port scanning and operating system detection using TTL (Time-To-Live) analysis.

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/Status-Stable-success)

## ✨ Features

- **Fast SYN Scanning**: Multithreaded port scanning using TCP SYN packets
- **OS Detection**: Identifies operating systems through TTL fingerprinting
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Flexible Targeting**: Scan specific ports, ranges, or common port lists
- **Stealthy**: Uses SYN scanning instead of full TCP connections
- **Comprehensive Reporting**: Detailed output with OS detection and open port listings

## 📸 Demo

![Network Scanning Demo](images/demo-scan.gif)
*Live demonstration of the port scanner in action*

## 🚀 Quick Start

### Prerequisites

- Python 3.6 or higher
- Administrator/root privileges (for raw socket access)
- Git (for cloning repository)

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/alstinthomas2004/open-port-scanner-os_detection.git
cd open-port-scanner-os_detection
