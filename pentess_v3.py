#!/usr/bin/env python3
"""
pentessa_operator_v3.py

Adds the missing Nmap scans you listed (bulk, -iL based) on top of v2.
- Writes all raw outputs to a timestamped folder under --base-dir.
- Still runs the per-target toolchain (nikto/ffuf/sslscan/testssl/etc.) like v2.

⚠️ Use ONLY on targets you are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional, Dict, List, Tuple

DEFAULT_BASE_DIR = "/opt/pentest/scans"

# ---------------------------
# Helpers
# ---------------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def ensure_dirs(root: Path, subdirs: Iterable[str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for d in subdirs:
        (root / d).mkdir(parents=True, exist_ok=True)

def read_scope(path: Path) -> List[str]:
    if not path.exists():
        return []
    items: List[str] = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(line)
    return items

def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:180]

def run_cmd(cmd: str, out_file: Path, timeout: int = 3600) -> Dict:
    """
    Runs a shell command, streams stdout/stderr to file, returns metadata.
    """
    out_file.parent.mkdir(parents=True, exist_ok=True)
    started = dt.datetime.utcnow().isoformat() + "Z"
    meta = {"command": cmd, "started_utc": started, "exit_code": None, "timed_out": False, "error": None, "output_file": str(out_file)}

    with out_file.open("w", encoding="utf-8", errors="ignore") as f:
        f.write(f"# CMD: {cmd}\n# STARTED_UTC: {started}\n\n")
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                for line in proc.stdout or []:
                    f.write(line)
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                meta["timed_out"] = True
                proc.kill()
            meta["exit_code"] = proc.returncode
        except Exception as e:
            meta["error"] = str(e)

    return meta

def parse_open_tcp_ports(nmap_file: Path) -> List[int]:
    ports: List[int] = []
    if not nmap_file.exists():
        return ports
    for line in nmap_file.read_text(errors="ignore").splitlines():
        m = re.match(r"(\d+)/tcp\s+open", line)
        if m:
            ports.append(int(m.group(1)))
    return sorted(set(ports))

def looks_like_wordpress(url: str, timeout: int = 10) -> bool:
    try:
        r1 = subprocess.run(
            f"curl -ksS --max-time {timeout} -o /dev/null -I {shlex.quote(url.rstrip('/') + '/wp-login.php')}",
            shell=True, capture_output=True, text=True
        )
        if " 200 " in r1.stdout or " 302 " in r1.stdout or " 301 " in r1.stdout:
            return True
        r2 = subprocess.run(f"curl -ksS --max-time {timeout} {shlex.quote(url)}",
                            shell=True, capture_output=True, text=True)
        if "wp-content" in (r2.stdout or "") or "wp-includes" in (r2.stdout or ""):
            return True
    except Exception:
        pass
    return False

def guess_urls(domain: str, ports: List[int]) -> List[str]:
    urls = [f"https://{domain}", f"http://{domain}"]
    for p in ports:
        if p in (80, 8080, 8000):
            urls.append(f"http://{domain}:{p}")
        if p in (443, 8443, 9443):
            urls.append(f"https://{domain}:{p}")
    seen=set()
    out=[]
    for u in urls:
        if u not in seen:
            out.append(u); seen.add(u)
    return out

def write_list_file(path: Path, items: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")

# ---------------------------
# Nmap bulk scans (your list)
# ---------------------------

def nmap_bulk_scans(root: Path,
                    scope_list: Path,
                    hosts_list: Path,
                    excludefile: Optional[Path],
                    timeouts: Dict[str,int],
                    shodan_api_key: Optional[str],
                    cust_ept_networks: Optional[Path]) -> List[Dict]:
    """
    Runs the Nmap commands you pasted, using -iL list files and -oA outputs.
    """
    artifacts: List[Dict] = []

    excl = ""
    if excludefile and excludefile.exists():
        excl = f" --excludefile {shlex.quote(str(excludefile))}"

    artifacts.append(run_cmd(
        f"sudo nmap -vv -n -sn -PE -iL {shlex.quote(str(scope_list))}{excl} -oA {shlex.quote(str(root/'nmap'/'outfile_pingscan'))}",
        root/"nmap"/"outfile_pingscan.console.txt",
        timeout=timeouts["nmap_ping_bulk"]
    ))

    artifacts.append(run_cmd(
        f"sudo nmap -vv -R -sL -iL {shlex.quote(str(scope_list))}{excl} -oA {shlex.quote(str(root/'nmap'/'outfile_dnsscan'))}",
        root/"nmap"/"outfile_dnsscan.console.txt",
        timeout=timeouts["nmap_dnsscan"]
    ))

    artifacts.append(run_cmd(
        f"sudo nmap --script http-vhosts -p 80,443 -iL {shlex.quote(str(hosts_list))}{excl} -oA {shlex.quote(str(root/'nmap'/'vhosts'))}",
        root/"nmap"/"vhosts.console.txt",
        timeout=timeouts["nmap_vhosts"]
    ))

    artifacts.append(run_cmd(
        f"sudo nmap -vv -n -Pn -sT -sV -T4 -O --randomize-hosts --osscan-limit "
        f'--script "default and discovery" --top-ports 1000 -iL {shlex.quote(str(scope_list))}{excl} '
        f"-oA {shlex.quote(str(root/'nmap'/'outfile_tcp_top1k'))}",
        root/"nmap"/"outfile_tcp_top1k.console.txt",
        timeout=timeouts["nmap_tcp_top1k"]
    ))

    artifacts.append(run_cmd(
        f"sudo nmap -vv -n -Pn -sT -sV -T4 -O --randomize-hosts --osscan-limit "
        f'--script "default and discovery" -p 1-65535 -iL {shlex.quote(str(scope_list))}{excl} '
        f"-oA {shlex.quote(str(root/'nmap'/'outfile_tcp_65535'))}",
        root/"nmap"/"outfile_tcp_65535.console.txt",
        timeout=timeouts["nmap_tcp_65535"]
    ))

    if shodan_api_key:
        artifacts.append(run_cmd(
            f"sudo nmap --script shodan-api -sn -Pn -n -iL {shlex.quote(str(scope_list))}{excl} "
            f"--script-args {shlex.quote('shodan-api.outfile=outfile.csv,shodan-api.apikey=' + shodan_api_key)} "
            f"-oA {shlex.quote(str(root/'nmap'/'outfile_shodan'))}",
            root/"nmap"/"outfile_shodan.console.txt",
            timeout=timeouts["nmap_shodan"]
        ))

    artifacts.append(run_cmd(
        f"sudo nmap -vv -n -Pn -sU -sV -T4 -O --osscan-limit --randomize-hosts --top-ports 1000 "
        f"-iL {shlex.quote(str(scope_list))}{excl} -oA {shlex.quote(str(root/'nmap'/'outfile_udp_top1k'))}",
        root/"nmap"/"outfile_udp_top1k.console.txt",
        timeout=timeouts["nmap_udp_top1k"]
    ))

    if cust_ept_networks and cust_ept_networks.exists():
        artifacts.append(run_cmd(
            f"sudo nmap -P0 -sS -g 53 --top-ports 1000 -iL {shlex.quote(str(cust_ept_networks))} "
            f"-oA {shlex.quote(str(root/'nmap'/'cust_ept_tcp_1k_src53'))}",
            root/"nmap"/"cust_ept_tcp_1k_src53.console.txt",
            timeout=timeouts["nmap_cust_ept"]
        ))

    artifacts.append(run_cmd(
        "nmap --version",
        root/"nmap"/"nmap_version.console.txt",
        timeout=120
    ))

    artifacts.append(run_cmd(
        f"sudo nmap -sV --version-all -iL {shlex.quote(str(scope_list))}{excl} -oA {shlex.quote(str(root/'nmap'/'outfile_version_all'))}",
        root/"nmap"/"outfile_version_all.console.txt",
        timeout=timeouts["nmap_version_all"]
    ))

    return artifacts

# ---------------------------
# Tasks (v2 toolchain)
# ---------------------------

def ip_scan(ip: str, root: Path, timeouts: Dict[str,int]) -> Dict:
    ip_tag = safe_name(ip)
    res = {"target": ip, "type": "ip", "artifacts": []}

    fast = root / "nmap" / f"{ip_tag}_fast.txt"
    ping = root / "nmap" / f"{ip_tag}_ping.txt"
    ver  = root / "nmap" / f"{ip_tag}_version.txt"
    full = root / "nmap" / f"{ip_tag}_full_tcp.txt"

    res["artifacts"].append(run_cmd(f"nmap -F {shlex.quote(ip)}", fast, timeout=timeouts["nmap_fast"]))
    res["artifacts"].append(run_cmd(f"nmap -sn {shlex.quote(ip)}", ping, timeout=timeouts["nmap_ping"]))
    res["artifacts"].append(run_cmd(f"nmap -sV {shlex.quote(ip)}", ver, timeout=timeouts["nmap_version"]))
    res["artifacts"].append(run_cmd(f"nmap -p- -T4 -sV -sC {shlex.quote(ip)}", full, timeout=timeouts["nmap_full"]))

    open_ports = parse_open_tcp_ports(full)
    res["open_tcp_ports"] = open_ports

    if which("ike-scan"):
        res["artifacts"].append(run_cmd(f"ike-scan -M {shlex.quote(ip)}", root/"dump"/f"{ip_tag}_ikescan.txt",
                                        timeout=timeouts["ikescan"]))

    if which("searchsploit"):
        svc_lines = []
        for line in ver.read_text(errors="ignore").splitlines():
            if re.match(r"^\d+/tcp\s+open\s+", line):
                svc_lines.append(line.strip())
        query = " ; ".join(svc_lines)[:800]
        if query:
            res["artifacts"].append(run_cmd(
                f"searchsploit {shlex.quote(query)}",
                root/"exploits"/f"{ip_tag}_searchsploit.txt",
                timeout=timeouts["searchsploit"]
            ))

    tls_ports = [p for p in open_ports if p in (443, 8443, 9443, 465, 993, 995)]
    for p in tls_ports:
        hostport = f"{ip}:{p}"
        if which("sslscan"):
            res["artifacts"].append(run_cmd(
                f"sslscan {shlex.quote(hostport)}",
                root/"ssl"/f"{ip_tag}_{p}_sslscan.txt",
                timeout=timeouts["sslscan"]
            ))
        if which("testssl.sh"):
            res["artifacts"].append(run_cmd(
                f"testssl.sh {shlex.quote(hostport)}",
                root/"ssl"/f"{ip_tag}_{p}_testssl.txt",
                timeout=timeouts["testssl"]
            ))

    return res

def domain_scan(domain: str, root: Path, timeouts: Dict[str,int]) -> Dict:
    dtag = safe_name(domain)
    res = {"target": domain, "type": "domain", "artifacts": [], "urls": []}

    res["artifacts"].append(run_cmd(f"dig +short {shlex.quote(domain)}", root/"dns"/f"{dtag}_dig_short.txt",
                                    timeout=timeouts["dig"]))
    res["artifacts"].append(run_cmd(f"whois {shlex.quote(domain)}", root/"dns"/f"{dtag}_whois.txt",
                                    timeout=timeouts["whois"]))

    if which("amass"):
        res["artifacts"].append(run_cmd(f"amass enum -passive -d {shlex.quote(domain)}", root/"dns"/f"{dtag}_amass.txt",
                                        timeout=timeouts["amass"]))
    if which("dnsrecon"):
        res["artifacts"].append(run_cmd(f"dnsrecon -d {shlex.quote(domain)}", root/"dns"/f"{dtag}_dnsrecon.txt",
                                        timeout=timeouts["dnsrecon"]))

    res["artifacts"].append(run_cmd(f"curl -ksS -I https://{shlex.quote(domain)}", root/"web"/f"{dtag}_headers_https.txt",
                                    timeout=timeouts["curl"]))
    res["artifacts"].append(run_cmd(f"curl -ksS -I http://{shlex.quote(domain)}", root/"web"/f"{dtag}_headers_http.txt",
                                    timeout=timeouts["curl"]))

    res["artifacts"].append(run_cmd(f"curl -ksS -X OPTIONS -i https://{shlex.quote(domain)}/", root/"web"/f"{dtag}_options_https.txt",
                                    timeout=timeouts["curl"]))
    res["artifacts"].append(run_cmd(f"curl -ksS -X TRACE -i https://{shlex.quote(domain)}/", root/"web"/f"{dtag}_trace_https.txt",
                                    timeout=timeouts["curl"]))

    if which("sslscan"):
        res["artifacts"].append(run_cmd(f"sslscan {shlex.quote(domain)}", root/"ssl"/f"{dtag}_sslscan.txt",
                                        timeout=timeouts["sslscan"]))
    if which("testssl.sh"):
        res["artifacts"].append(run_cmd(f"testssl.sh {shlex.quote(domain)}", root/"ssl"/f"{dtag}_testssl.txt",
                                        timeout=timeouts["testssl"]))

    if which("nikto"):
        res["artifacts"].append(run_cmd(f"nikto -h https://{shlex.quote(domain)}", root/"web"/f"{dtag}_nikto_https.txt",
                                        timeout=timeouts["nikto"]))
        res["artifacts"].append(run_cmd(f"nikto -h http://{shlex.quote(domain)}", root/"web"/f"{dtag}_nikto_http.txt",
                                        timeout=timeouts["nikto"]))

    if which("ffuf"):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        res["artifacts"].append(run_cmd(
            f"ffuf -ac -t 40 -u https://{shlex.quote(domain)}/FUZZ -w {shlex.quote(wordlist)}",
            root/"api"/f"{dtag}_ffuf_https.txt",
            timeout=timeouts["ffuf"]
        ))
        res["artifacts"].append(run_cmd(
            f"ffuf -ac -t 40 -u http://{shlex.quote(domain)}/FUZZ -w {shlex.quote(wordlist)}",
            root/"api"/f"{dtag}_ffuf_http.txt",
            timeout=timeouts["ffuf"]
        ))
    elif which("dirb"):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        res["artifacts"].append(run_cmd(
            f"dirb https://{shlex.quote(domain)}/ {shlex.quote(wordlist)}",
            root/"api"/f"{dtag}_dirb_https.txt",
            timeout=timeouts["dirb"]
        ))

    urls = guess_urls(domain, ports=[])
    res["urls"] = urls
    if which("wpscan"):
        for url in urls:
            if looks_like_wordpress(url):
                res["artifacts"].append(run_cmd(
                    f"wpscan --url {shlex.quote(url)} --random-user-agent --disable-tls-checks",
                    root/"web"/f"{dtag}_wpscan_{safe_name(url)}.txt",
                    timeout=timeouts["wpscan"]
                ))
                break

    if which("eyewitness"):
        url_file = root/"web"/f"{dtag}_urls.txt"
        url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        res["artifacts"].append(run_cmd(
            f"eyewitness -f {shlex.quote(str(url_file))} --web -d {shlex.quote(str(root/'web'/f'{dtag}_eyewitness'))}",
            root/"web"/f"{dtag}_eyewitness_run.txt",
            timeout=timeouts["eyewitness"]
        ))

    return res

# ---------------------------
# Main
# ---------------------------

def build_timeouts(args) -> Dict[str,int]:
    return {
        "nmap_fast": args.nmap_fast_timeout,
        "nmap_ping": args.nmap_ping_timeout,
        "nmap_version": args.nmap_version_timeout,
        "nmap_full": args.nmap_full_timeout,

        "nmap_ping_bulk": args.nmap_ping_bulk_timeout,
        "nmap_dnsscan": args.nmap_dnsscan_timeout,
        "nmap_vhosts": args.nmap_vhosts_timeout,
        "nmap_tcp_top1k": args.nmap_tcp_top1k_timeout,
        "nmap_tcp_65535": args.nmap_tcp_65535_timeout,
        "nmap_udp_top1k": args.nmap_udp_top1k_timeout,
        "nmap_shodan": args.nmap_shodan_timeout,
        "nmap_cust_ept": args.nmap_cust_ept_timeout,
        "nmap_version_all": args.nmap_version_all_timeout,

        "ikescan": 900,
        "searchsploit": 900,
        "dig": 120,
        "whois": 300,
        "amass": 1800,
        "dnsrecon": 900,
        "curl": 60,
        "sslscan": 900,
        "testssl": 3600,
        "nikto": 3600,
        "ffuf": 1800,
        "dirb": 1800,
        "wpscan": 3600,
        "eyewitness": 3600,
    }

def dependency_report() -> Dict[str, Optional[str]]:
    tools = [
        "nmap","dig","whois","curl",
        "sslscan","testssl.sh","nikto","ffuf","dirb","dnsrecon","amass","wpscan","ike-scan","searchsploit","eyewitness"
    ]
    return {t: which(t) for t in tools}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope-ips", default="scopeIPs.txt")
    ap.add_argument("--scope-domains", default="scopeDomains.txt")
    ap.add_argument("--exclude-file", default="", help="Optional exclusion list file for nmap --excludefile")
    ap.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    ap.add_argument("--workers", type=int, default=3, help="parallel targets (keep low to avoid noisy scans)")
    ap.add_argument("--run-bulk-nmap", action="store_true", help="Run the full list-based Nmap pipeline you pasted")

    ap.add_argument("--shodan-api-key", default="", help="Optional: enable nmap shodan-api NSE using this key (do not hardcode)")
    ap.add_argument("--cust-ept-networks", default="", help="Optional: file path for cust_ept_networks.txt (source-port 53 scan)")

    ap.add_argument("--nmap-fast-timeout", type=int, default=600)
    ap.add_argument("--nmap-ping-timeout", type=int, default=300)
    ap.add_argument("--nmap-version-timeout", type=int, default=900)
    ap.add_argument("--nmap-full-timeout", type=int, default=5400)

    ap.add_argument("--nmap-ping-bulk-timeout", type=int, default=1800)
    ap.add_argument("--nmap-dnsscan-timeout", type=int, default=1800)
    ap.add_argument("--nmap-vhosts-timeout", type=int, default=3600)
    ap.add_argument("--nmap-tcp-top1k-timeout", type=int, default=7200)
    ap.add_argument("--nmap-tcp-65535-timeout", type=int, default=21600)
    ap.add_argument("--nmap-udp-top1k-timeout", type=int, default=14400)
    ap.add_argument("--nmap-shodan-timeout", type=int, default=3600)
    ap.add_argument("--nmap-cust-ept-timeout", type=int, default=7200)
    ap.add_argument("--nmap-version-all-timeout", type=int, default=7200)

    args = ap.parse_args()

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = Path(args.base_dir) / f"scan_{timestamp}"
    ensure_dirs(out_root, ["nmap","web","ssl","dns","api","exploits","dump","meta"])

    ips = read_scope(Path(args.scope_ips))
    domains = read_scope(Path(args.scope_domains))

    scope_list = out_root/"meta"/"scope.txt"
    hosts_list = out_root/"meta"/"hosts.txt"
    write_list_file(scope_list, ips)
    write_list_file(hosts_list, sorted(set(ips + domains)))

    excludefile = Path(args.exclude_file) if args.exclude_file else None
    shodan_key = args.shodan_api_key.strip() or None
    cust_ept = Path(args.cust_ept_networks) if args.cust_ept_networks else None

    meta = {
        "started_local": dt.datetime.now().isoformat(),
        "output_root": str(out_root),
        "scope_ips_count": len(ips),
        "scope_domains_count": len(domains),
        "deps": dependency_report(),
        "list_files": {"scope_list": str(scope_list), "hosts_list": str(hosts_list)},
        "notes": [
            "This runner executes automatable CLI checks. Manual checks (Burp Pro/ZAP interactive, auth testing, business logic) are not executed here.",
            "Bulk Nmap scans (your enterprise pipeline) only run if you pass --run-bulk-nmap.",
            "Shodan NSE only runs if you pass --shodan-api-key.",
            "The flag 'nmap --version-all' is not valid; we run '-sV --version-all' instead."
        ],
    }
    (out_root/"meta"/"run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    timeouts = build_timeouts(args)
    results: List[Dict] = []

    bulk_artifacts: List[Dict] = []
    if args.run_bulk_nmap:
        bulk_artifacts = nmap_bulk_scans(
            out_root,
            scope_list=scope_list,
            hosts_list=hosts_list,
            excludefile=excludefile,
            timeouts=timeouts,
            shodan_api_key=shodan_key,
            cust_ept_networks=cust_ept
        )
    results.append({"type": "bulk_nmap", "enabled": bool(args.run_bulk_nmap), "artifacts": bulk_artifacts})

    jobs: List[Tuple[str,str]] = [("ip", ip) for ip in ips] + [("domain", d) for d in domains]

    def do(job):
        kind, target = job
        if kind == "ip":
            return ip_scan(target, out_root, timeouts)
        return domain_scan(target, out_root, timeouts)

    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = [ex.submit(do, j) for j in jobs]
        for fut in cf.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"type":"error","error":str(e)})

    (out_root/"meta"/"results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] Done. Results in: {out_root}")
    print(f"[+] Summary: {out_root/'meta'/'results.json'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
