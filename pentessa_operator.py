import os
import subprocess
import datetime
import re
import sys

BASE_DIR = "/opt/pentest/scans"


# ==============================
# Run Command Function
# ==============================
def run_command(command, output_file):
    print(f"\n[+] Running: {command}")
    print(f"[+] Output -> {output_file}\n")

    try:
        with open(output_file, "w") as f:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            for line in process.stdout:
                print(line.strip())
                f.write(line)

            process.wait()

    except Exception as e:
        print(f"[!] Error running command: {e}")


# ==============================
# Parse Open Ports
# ==============================
def parse_open_ports(nmap_file):
    open_ports = []

    if not os.path.exists(nmap_file):
        return open_ports

    with open(nmap_file, "r") as f:
        for line in f:
            match = re.match(r"(\d+)/tcp\s+open", line)
            if match:
                open_ports.append(int(match.group(1)))

    return open_ports


# ==============================
# Read Scope Files
# ==============================
def read_scope(file_name):
    if not os.path.exists(file_name):
        print(f"[!] {file_name} not found.")
        return []

    with open(file_name) as f:
        data = [line.strip() for line in f if line.strip()]

    if not data:
        print(f"[!] {file_name} is empty.")
    else:
        print(f"[+] Loaded {len(data)} entries from {file_name}")

    return data


# ==============================
# MAIN
# ==============================
def main():

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT = os.path.join(BASE_DIR, f"scan_{timestamp}")

    dirs = ["nmap", "web", "ssl", "dns", "api", "exploits", "dump"]
    for d in dirs:
        os.makedirs(os.path.join(OUTPUT, d), exist_ok=True)

    print(f"\n[+] Scan folder created: {OUTPUT}\n")

    ips = read_scope("scopeIPs.txt")
    domains = read_scope("scopeDomains.txt")

    # ==============================
    # IP SCANS
    # ==============================
    for ip in ips:
        print(f"\n==============================")
        print(f"[+] Starting scans for IP: {ip}")
        print(f"==============================\n")

        # ----- FAST -----
        run_command(f"nmap -F {ip}", f"{OUTPUT}/nmap/{ip}_fast.txt")
        run_command(f"nmap -sn {ip}", f"{OUTPUT}/nmap/{ip}_ping.txt")

        # ----- MEDIUM -----
        run_command(f"nmap -sV {ip}", f"{OUTPUT}/nmap/{ip}_version.txt")

        # ----- HEAVY -----
        full_tcp_path = f"{OUTPUT}/nmap/{ip}_full_tcp.txt"
        run_command(f"nmap -p- -T4 -sV -sC {ip}", full_tcp_path)

        open_ports = parse_open_ports(full_tcp_path)
        print(f"\n[+] Open ports detected: {open_ports}\n")

        if 500 in open_ports:
            run_command(f"ike-scan -M {ip}", f"{OUTPUT}/dump/{ip}_ikescan.txt")

        run_command(
            f"searchsploit {ip}",
            f"{OUTPUT}/exploits/{ip}_searchsploit.txt"
        )

    # ==============================
    # DOMAIN SCANS
    # ==============================
    for domain in domains:
        print(f"\n==============================")
        print(f"[+] Starting scans for Domain: {domain}")
        print(f"==============================\n")

        # ----- FAST -----
        run_command(f"dig +short {domain}", f"{OUTPUT}/dns/{domain}_dig_short.txt")
        run_command(f"whois {domain}", f"{OUTPUT}/dns/{domain}_whois.txt")
        run_command(f"curl -I https://{domain}", f"{OUTPUT}/web/{domain}_headers.txt")

        # ----- MEDIUM -----
        run_command(f"sslscan {domain}", f"{OUTPUT}/ssl/{domain}_sslscan.txt")
        run_command(f"amass enum -passive -d {domain}", f"{OUTPUT}/dns/{domain}_amass.txt")
        run_command(f"dnsrecon -d {domain}", f"{OUTPUT}/dns/{domain}_dnsrecon.txt")

        # ----- HEAVY -----
        run_command(f"nikto -h https://{domain}", f"{OUTPUT}/web/{domain}_nikto.txt")

        run_command(
            f"ffuf -u https://{domain}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            f"{OUTPUT}/api/{domain}_ffuf.txt"
        )

        run_command(f"testssl.sh {domain}", f"{OUTPUT}/ssl/{domain}_testssl.txt")

    print("\n[+] ALL SCANS COMPLETE\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Partial results saved.\n")
        sys.exit(0)