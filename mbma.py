#!/usr/bin/env python3
"""
MBMA v3.1 - Advanced Asynchronous Network Security Auditing Framework.
Components: Subnet Parser, Asyncio Multiplexing, OS Heuristics, Layer 7 HTTP Analyzer.
Author: Mohamed BOURI
License: MIT
"""

import asyncio
import argparse
import json
import sys
import os
import ipaddress
import socket
import ssl
from datetime import datetime

# Enforce native ANSI coloring parameters for Windows 10 Host Terminals
if os.name == 'nt':
    os.system('')
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Monospaced Terminal UI Palette
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
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
                                                                         
{RESET}{BLUE}  [ Advanced Async Auditing Framework v3.1 ]{RESET}
"""

class OSFingerprinter:
    """Heuristic logic processing layer to deduce OS families via network metrics."""
    @staticmethod
    def guess_os(ttl: int) -> str:
        if ttl is None:
            return "Unknown (No Response)"
        if ttl <= 64:
            return "Linux / Android / macOS"
        elif ttl <= 128:
            return "Windows Operating System"
        elif ttl <= 255:
            return "Cisco iOS / Embedded Infrastructure"
        return "Unknown Network Stack OS"

class HTTPHeaderAnalyzer:
    """Application Layer (Layer 7) engine targeting active web servers."""
    CRITICAL_SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]

    @classmethod
    async def analyze(cls, ip: str, port: int, timeout: float) -> dict:
        http_metrics = {
            "web_server": "Undetected",
            "x_powered_by": "Undetected",
            "security_headers_present": {},
            "missing_security_headers": []
        }

        use_ssl = True if port in [443, 8443] else False
        ssl_context = ssl._create_unverified_context() if use_ssl else None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_context), 
                timeout=timeout
            )
            
            # Construct raw HEAD protocol sequence optimized for quick response parsing
            http_request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: Mbma/3.1 (Security Auditor)\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(http_request.encode('utf-8'))
            await writer.drain()

            raw_response = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            response_text = raw_response.decode('utf-8', errors='ignore')
            
            lines = response_text.split("\r\n")
            found_headers = []

            for line in lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if key == "server":
                        http_metrics["web_server"] = value
                    elif key == "x-powered-by":
                        http_metrics["x_powered_by"] = value
                    
                    for sec_header in cls.CRITICAL_SECURITY_HEADERS:
                        if key == sec_header.lower():
                            http_metrics["security_headers_present"][sec_header] = value
                            found_headers.append(sec_header)

            http_metrics["missing_security_headers"] = [
                h for h in cls.CRITICAL_SECURITY_HEADERS if h not in found_headers
            ]

            writer.close()
            await writer.wait_closed()
        except Exception:
            return {}  # Return empty if port dropped connection or isn't running HTTP

        return http_metrics

class NetworkScanner:
    """Asynchronous pipeline orchestration engine controlling tasks execution."""
    def __init__(self, targets: list, ports: list, concurrency: int, timeout: float):
        self.targets = targets
        self.ports = ports
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.results = {}

    async def grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        try:
            writer.write(b"Hello\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode('utf-8', errors='ignore').strip()
            return " ".join(banner.split()) if banner else "Generic Active Service"
        except Exception:
            return "Active Service (Banner Dropped)"
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def scan_single_target_port(self, ip: str, port: int) -> dict:
        async with self.semaphore:
            try:
                connect_coro = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
                
                banner = await self.grab_banner(reader, writer)
                result = {"port": port, "status": "open", "banner": banner, "http_analysis": None}
                
                # Check Layer 7 parameters if port signature matches Web environments
                if port in [80, 443, 8080, 8443]:
                    http_info = await HTTPHeaderAnalyzer.analyze(ip, port, self.timeout)
                    if http_info:
                        result["http_analysis"] = http_info

                return result
            except Exception:
                return {"port": port, "status": "closed"}

    async def extract_ttl(self, ip: str) -> int:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect_ex((ip, 80))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()
            return ttl
        except Exception:
            return 64  # Standard baseline fallback

    async def execute_scan(self):
        for target in self.targets:
            ip = str(target)
            print(f"{YELLOW}[*] Evaluating Target Host: {ip}{RESET}")
            
            ttl_value = await self.extract_ttl(ip)
            detected_os = OSFingerprinter.guess_os(ttl_value)
            print(f"    └── Heuristic Stack Profiling: {CYAN}{detected_os}{RESET} (TTL: {ttl_value})")
            
            self.results[ip] = {
                "host_metrics": {"os_prediction": detected_os, "detected_ttl": ttl_value},
                "open_ports": []
            }
            
            tasks = [self.scan_single_target_port(ip, port) for port in self.ports]
            
            for future in asyncio.as_completed(tasks):
                res = await future
                if res["status"] == "open":
                    print(f"    └── [{GREEN}OPEN{RESET}] Port {res['port']:<5} | Banner: {res['banner']}")
                    
                    if res.get("http_analysis"):
                        http_data = res["http_analysis"]
                        print(f"        ├── {YELLOW}[Layer 7 Data]{RESET} Server Hardware: {CYAN}{http_data['web_server']}{RESET}")
                        if http_data["missing_security_headers"]:
                            missing = ", ".join(http_data["missing_security_headers"])
                            print(f"        └── {RED}[Risk Countermeasure Alert]{RESET} Missing Compliance Headers: {RED}{missing}{RESET}")
                    
                    self.results[ip]["open_ports"].append(res)

def parse_input_scopes(target_arg: str) -> list:
    hosts = []
    try:
        if '/' in target_arg:
            hosts = list(ipaddress.ip_network(target_arg, strict=False).hosts())
        elif '-' in target_arg:
            start_ip, end_ip = target_arg.split('-')
            start_int = int(ipaddress.IPv4Address(start_ip.strip()))
            end_int = int(ipaddress.IPv4Address(end_ip.strip()))
            hosts = [ipaddress.IPv4Address(ip) for ip in range(start_int, end_int + 1)]
        else:
            hosts = [ipaddress.IPv4Address(socket.gethostbyname(target_arg.strip()))]
    except Exception:
        print(f"{RED}[!] Architecture Syntax Error: Target syntax '{target_arg}' unresolvable.{RESET}")
        sys.exit(1)
    return hosts

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="MBMA Core Auditing Tool Pipeline System Execution.")
    parser.add_argument("-t", "--target", required=True, help="Single IP, Subnet CIDR (192.168.1.0/24), or Scope Range (10.0.0.1-10.0.0.10)")
    parser.add_argument("-p", "--ports", default="21,22,23,80,443,445,3389,8080", help="Target scanning list or numerical range (e.g. 21-100)")
    parser.add_argument("-c", "--concurrency", type=int, default=400, help="Asyncio pool task multiplexing limitation.")
    parser.add_argument("--timeout", type=float, default=1.5, help="Network timeout window parameters.")
    parser.add_argument("-o", "--output", help="Save metrics layout to JSON target file output path.")
    
    args = parser.parse_args()
    
    target_hosts = parse_input_scopes(args.target)
    
    if "-" in args.ports:
        sp, ep = map(int, args.ports.split("-"))
        port_list = list(range(sp, ep + 1))
    else:
        port_list = [int(p.strip()) for p in args.ports.split(",")]

    print(f"{BLUE}[+] Network Processing Graph Matrix Mounted{RESET}")
    print(f"[+] Operational Mapping Nodes : {len(target_hosts)}")
    print(f"[+] Total Ports Matrix Size   : {len(port_list)}")
    print("-" * 75)

    scanner = NetworkScanner(target_hosts, port_list, args.concurrency, args.timeout)
    
    start_time = datetime.now()
    asyncio.run(scanner.execute_scan())
    end_time = datetime.now()
    
    print("-" * 75)
    print(f"{GREEN}[✓] Framework processing closed cleanly. Latency window duration: {end_time - start_time}{RESET}")

    if args.output:
        report = {
            "execution_meta": {"engine": "MBMA", "release": "3.1", "duration_seconds": (end_time - start_time).total_seconds()},
            "hosts_matrix": scanner.results
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"{GREEN}[✓] Data layout matrix exported dynamically to: {args.output}{RESET}")

if __name__ == "__main__":
    main()
