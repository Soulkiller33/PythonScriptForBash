import socket
import argparse
import os
import time
import ipaddress
import subprocess

def get_network_prefix():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip_addr = s.getsockname()[0]
        s.close()
        
        parts = local_ip_addr.split('.')
        network_base = f"{parts[0]}.{parts[1]}.{parts[2]}."
        return network_base
    except Exception:
        return None
    
class Fore:
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"
    RESET = "\033[0m"

default_ports = [
    20,21,22,23,25,53,67,68,69,80,
    110,123,135,137,138,139,143,161,162,389,
    443,445,465,514,587,631,993,995,1433,1521,
    1723,3306,3389,5432,5900,8080,8443,8888,79,
    106,111,113,515,554,873,902,989,990,1000
]

def parse_ports(ports_arg, all_ports=False):
    if all_ports:
        return list(range(0, 65536))
    if not ports_arg:
        return default_ports
    elif "-" in ports_arg:
        start, end = map(int, ports_arg.split("-"))
        return list(range(start, end + 1))
    elif "," in ports_arg:
        return [int(p.strip()) for p in ports_arg.split(",")]
    else:
        return [int(ports_arg)]

def local_ip():
    return "127.0.0.1"

def scan_ports(ip, ports, output_file=None, all_ports=False):
    print(Fore.CYAN + "=" * 50 + Fore.RESET)
    print(Fore.CYAN + "        PYTHON PORT SCANNER v1.0         " + Fore.RESET)
    print(Fore.CYAN + "=" * 50 + Fore.RESET)
    print(f" {Fore.YELLOW}[*]{Fore.RESET} Target IP : {Fore.GREEN}{ip}{Fore.RESET}")
    print(Fore.YELLOW + f" [*] Ports     : {Fore.GREEN}{len(ports)} ports selected{Fore.RESET}")
    print(Fore.CYAN + "-" * 50 + Fore.RESET + "\n")

    open_ports = []
    log_lines = [
        "==================================================\n",
        "        PYTHON PORT SCANNER RESULTS              \n",
        "==================================================\n",
        f"Target IP: {ip}\n",
        f"Total Ports Scanned: {len(ports)}\n",
        "--------------------------------------------------\n"
    ]

    start_time = time.time()
    interrupted = False

    try:
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                result = s.connect_ex((ip, port))
                if result == 0:
                    message = f"  [-] PORT {port:<5} -> OPEN"
                    print(Fore.GREEN + message + Fore.RESET)
                    open_ports.append(port)
                    log_lines.append(message + "\n")
                else:
                    if all_ports:
                        closed_msg = f"  [x] PORT {port:<5} -> CLOSED"
                        print(Fore.GRAY + closed_msg + Fore.RESET)
                s.close()
            except socket.gaierror:
                msg = "[!] Hostname could NOT be resolved."
                print(Fore.RED + msg + Fore.RESET)
                log_lines.append(msg + "\n")
                break
            except socket.error:
                msg = "[!] Couldn't connect to server."
                print(Fore.RED + msg + Fore.RESET)
                log_lines.append(msg + "\n")
                break
    except KeyboardInterrupt:
        interrupted = True
        msg = "\n[!] Scan interrupted by user (Ctrl+C)."
        print(Fore.RED + msg + Fore.RESET)
        log_lines.append(msg + "\n")

    elapsed_time = time.time() - start_time

    print(Fore.CYAN + "\n" + "-" * 50 + Fore.RESET)
    if interrupted:
        print(Fore.YELLOW + f" Scan aborted after {elapsed_time:.2f} seconds." + Fore.RESET)
        log_lines.append(f"\nScan aborted after {elapsed_time:.2f} seconds.\n")
    else:
        print(Fore.CYAN + f" Scan completed in {elapsed_time:.2f} seconds." + Fore.RESET)
    
    if open_ports:
        summary = f" Open ports found: {', '.join(str(p) for p in open_ports)}"
        print(Fore.GREEN + summary + Fore.RESET)
        log_lines.append(f"\nSummary: {len(open_ports)} open port(s) found.\n" + summary + "\n")
    else:
        summary = " No open ports found."
        print(Fore.YELLOW + summary + Fore.RESET)
        log_lines.append(f"\nSummary:{summary}\n")
    
    print(Fore.CYAN + "=" * 50 + Fore.RESET)

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.writelines(log_lines)
            abs_path = os.path.abspath(output_file)
            print(Fore.MAGENTA + f"[*] Results saved to: {abs_path}" + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to save results: {e}" + Fore.RESET)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python-based port scanner")
    parser.add_argument("--ip", required=False, help="Target IP or Hostname")
    parser.add_argument("--ports", default=None, help="Port range (e.g. 20-100 or 80,443)")
    parser.add_argument("--all", action="store_true", help="Scans all 65536 ports and shows closed ones")
    parser.add_argument("--output", type=str, default="scan_results.txt", help="Save results to file")
    args = parser.parse_args()
    
    resolved_ip = args.ip if args.ip else local_ip()

    ports = parse_ports(args.ports, args.all)
    scan_ports(resolved_ip, ports, args.output, args.all)
    
    print(resolved_ip)
