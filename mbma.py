#!/usr/bin/env python3
"""
Mbma - A Fast Multi-Threaded Network Security Auditor & Port Scanner.
Author: Mohamed BOURI
License: MIT
"""

import socket
import argparse
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize ANSI colors for Windows Command Prompt compatibility
if os.name == 'nt':
    os.system('')

# UI Color Palette
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

BANNER = f"""{CYAN}
                                                                       
     ______  _______         _____       ______  _______         _____   
    |      \/       \   ___|\     \     |      \/       \    ___|\    \  
   /          /\     \ |    |\     \   /          /\     \  /    /\    \ 
  /     /\   / /\     ||    | |     | /     /\   / /\     ||    |  |    |
 /     /\ \_/ / /    /||    | /_ _ / /     /\ \_/ / /    /||    |__|    |
|     |  \|_|/ /    / ||    |\    \ |     |  \|_|/ /    / ||    .--.    |
|     |       |    |  ||    | |    ||     |       |    |  ||    |  |    |
|\____\       |____|  /|____|/____/||\____\       |____|  /|____|  |____|
| |    |      |    | / |    /     ||| |    |      |    | / |    |  |    |
 \|____|      |____|/  |____|_____|/ \|____|      |____|/  |____|  |____|
    \(          )/       \(    )/       \(          )/       \(      )/  
     '          '         '    '         '          '         '      '   
                                                                         
{RESET}{BLUE}  [ Network Security Auditor v2.1 ]{RESET}
"""

def grab_banner(s: socket.socket) -> str:
    """Attempt to extract the service banner from an open port."""
    try:
        s.settimeout(1.5)
        s.send(b"Hello\r\n")
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        return " ".join(banner.split()) if banner else "No banner response"
    except Exception:
        return "Unknown Service"

def scan_port(target_ip: str, port: int, timeout: float) -> dict:
    """Scan a single port to determine its state and running service."""
    result = {"port": port, "status": "closed", "banner": ""}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            status = s.connect_ex((target_ip, port))
            
            if status == 0:
                result["status"] = "open"
                result["banner"] = grab_banner(s)
    except Exception:
        pass
    return result

def main():
    print(BANNER)
    
    # Check if the user ran the script without any command-line arguments
    if len(sys.argv) == 1:
        print(f"{BLUE}[*] No arguments provided. Launching Guided Wizard...{RESET}\n")
        
        target = input(f"{CYAN}👉 Enter Target IP or Domain: {RESET}").strip()
        if not target:
            print(f"{RED}[!] Error: Target destination cannot be empty.{RESET}")
            sys.exit(1)
            
        ports_input = input(f"{CYAN}👉 Enter Ports/Range (e.g., 21-80 or 80,443) [Default: 1-1024]: {RESET}").strip()
        ports = ports_input if ports_input else "1-1024"
        
        workers_input = input(f"{CYAN}👉 Enter Thread Count (Speed) [Default: 100]: {RESET}").strip()
        workers = int(workers_input) if workers_input.isdigit() else 100
        
        timeout_input = input(f"{CYAN}👉 Enter Connection Timeout in seconds [Default: 1.0]: {RESET}").strip()
        try:
            timeout = float(timeout_input) if timeout_input else 1.0
        except ValueError:
            timeout = 1.0
    else:
        # Standard CLI Argument Parser mode
        parser = argparse.ArgumentParser(description="Mbma: High-performance concurrent port scanner.")
        parser.add_argument("-t", "--target", required=True, help="Target IP address or host domain.")
        parser.add_argument("-p", "--ports", default="1-1024", help="Range (e.g., 21-80) or list (e.g., 80,443). Default: 1-1024")
        parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent execution threads. Default: 100")
        parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout limit in seconds. Default: 1.0")
        
        args = parser.parse_args()
        target = args.target
        ports = args.ports
        workers = args.workers
        timeout = args.timeout
    
    # Domain to IP Resolution
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[!] Error: Host translation failed for target: {target}{RESET}")
        sys.exit(1)
        
    # Parsing custom port configurations
    ports_to_scan = []
    if "-" in ports:
        try:
            start_p, end_p = map(int, ports.split("-"))
            ports_to_scan = list(range(start_p, end_p + 1))
        except ValueError:
            print(f"{RED}[!] Error: Invalid range syntax. Use standard 'start-end' format.{RESET}")
            sys.exit(1)
    else:
        try:
            ports_to_scan = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            print(f"{RED}[!] Error: Invalid comma-separated port sequence.{RESET}")
            sys.exit(1)

    print(f"\n{BLUE}[+] Target Identity : {RESET}{target_ip} ({target})")
    print(f"{BLUE}[+] Audit Launched  : {RESET}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BLUE}[+] Thread Count    : {RESET}{workers} active workers")
    print(f"{BLUE}[+] Scope Size      : {RESET}{len(ports_to_scan)} targets")
    print("-" * 65)

    open_ports_count = 0
    
    # ThreadPool Execution for high-velocity multi-threaded processing
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, target_ip, port, timeout): port for port in ports_to_scan}
        
        try:
            for future in as_completed(futures):
                res = future.result()
                if res["status"] == "open":
                    open_ports_count += 1
                    print(f"[{GREEN}OPEN{RESET}] Port {res['port']:<5} | Banner: {CYAN}{res['banner']}{RESET}")
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Session interrupted by user interface break. Exiting...{RESET}")
            sys.exit(0)

    print("-" * 65)
    print(f"{GREEN}[+]{RESET} Audit Finished. Discovered {GREEN}{open_ports_count}{RESET} active entry points.")

if __name__ == "__main__":
    main()
