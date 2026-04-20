#!/usr/bin/env python3
import argparse
import json
import subprocess
import urllib.request
import sys
import os
import glob
import shutil
import re
import requests
import signal
from datetime import datetime
from traceback import print_tb
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from pathlib import Path


print("""
 ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
███║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
╚██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
         All Bug Bounty Recon Tools In One v1.0.0
                By: FAres @0xProf
""")

CURRENT_VERSION = "v1.0.0"
VERSION_URL = "https://raw.githubusercontent.com/0xProfr2/1recon/main/version.txt"
TOOL_URL = "https://raw.githubusercontent.com/0xProfr2/1recon/main/1recon.py"

def check_for_updates():
    print("[*] Checking for updates...")
    try:
        with urllib.request.urlopen(VERSION_URL, timeout=5) as response:
            latest_version = response.read().decode().strip()
        if latest_version != CURRENT_VERSION:
            print(f"[!] New version available: {latest_version}")
            print(f"[*] Current version: {CURRENT_VERSION}")
            answer = input("[?] Do you want to update? (y/n): ")
            if answer.lower() == "y":
                print("[*] Downloading update...")
                urllib.request.urlretrieve(TOOL_URL, "1recon.py")
                print("[+] Update downloaded successfully! Please restart.")
                sys.exit(0)
        else:
            print(f"[+] Already up to date ({CURRENT_VERSION})")
    except Exception as ex:
        print(f"[-] Could not check for updates: {ex}")

check_for_updates()

# Parser
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", dest="domain", required=True, help="Target to Scan")
parser.add_argument("-s", "--subs", dest="subs", action="store_true", help="recon on subdomains only")
parser.add_argument("-p", "--path", dest="paths", action="store_true", help="recon on paths only")
parser.add_argument("-o", "--output", dest="output", default="report.json", metavar="FILE", help="output file")
args = parser.parse_args()


class Tools:
    def __init__(self, check, command, install, use_redirect=False, use_tee=False):
        self.check = check
        self.command = command
        self.install = install
        self.use_tee = use_tee
        self.use_redirect = use_redirect

    def is_installed(self):
        return shutil.which(self.check) is not None

    def install_tool(self):
        if not self.is_installed():
            print(f"[-] {self.check} isn't installed, installing it...")
            subprocess.call(self.install, shell=True)

    def run(self, output, domain=None, input=None, timeout=600): 
        if self.use_tee:
            cmd = f"{self.command.format(domain=domain, input=input)} | tee {output}"
        elif self.use_redirect:
            cmd = f"{self.command.format(domain=domain, input=input)} > {output}"
        else:
            cmd = self.command.format(domain=domain, input=input, output=output)

        print(f"[*] Running {self.check} ...")
        try:
            
            subprocess.run(cmd, shell=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"[!] Tool {self.check} timed out. Skipping...")
        except Exception as e:
            print(f"[-] Error running {self.check}: {e}")

# API KEYS & PATHS
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(dotenv_path=ENV_PATH) 

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
PDCP_API_KEY = os.getenv("PDCP_API_KEY", "")


subfinder = Tools("subfinder",
                  "subfinder -d {domain} -all --recursive -o {output}",
                  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
assetfinder = Tools("assetfinder",
                    "assetfinder --subs-only {domain}",
                    "go install github.com/tomnomnom/assetfinder@latest", use_redirect=True)

subenum = Tools("subenum.sh",
                "subenum.sh -d {domain} -u wayback,crt,abuseipdb,Findomain,Subfinder,Amass,Assetfinder -o {output}",
                "git clone https://github.com/bing0o/SubEnum")

sublist3r = Tools("sublist3r",
                  "sublist3r -d {domain} -o {output}",
                  "pip install sublist3r")
amass = Tools("amass",
              "amass enum -passive -d {domain} -o {output}",
              "go install -v github.com/owasp-amass/amass/v4/...@master")

findomain = Tools("findomain",
                  "findomain -t {domain} -u {output}",
                  "cargo install findomain")

chaos = Tools("chaos",
              f"export PDCP_API_KEY={PDCP_API_KEY} && chaos -d {{domain}} -o {{output}}",
              "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest")

github_subdomains = Tools("github-subdomains",
                          f"github-subdomains -d {{domain}} -t {GITHUB_TOKEN} -o {{output}}",
                          "go install github.com/gwen001/github-subdomains@latest")

magicrecon = Tools("magicrecon.sh",
                   "magicrecon.sh -l targets.txt --all",
                   "git clone https://github.com/nardholio/magicrecon")

dnscan = Tools("dnscan.py",
               "python3 dnscan/dnscan.py -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million110000.txt",
               "git clone https://github.com/rbsec/dnscan", use_tee=True)

httpx = Tools("httpx",
              "httpx -l {input} -status-code -title -content-length -follow-redirects -web-server -o {output}",
              "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")

httpx200 = Tools("httpx",
                 "httpx -l {input} -status-code -title -content-length -follow-redirects -web-server -mc 200 -o {output}",
                 "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")

nmap = Tools("nmap",
             "nmap -iL {input} -sV -p- -sC -Pn --open -o {output}",
             "sudo apt install nmap -y")

asnmap = Tools("asnmap",
               "asnmap -d {domain} -o {output}",
               "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")

whois_tool = Tools("whois",
                   "whois -h whois.radb.net {domain}",
                   "sudo apt install whois -y", use_redirect=True)

dnsx = Tools("dnsx",
             "dnsx -silent -resp-only -ptr -l {input} -o {output}",
             "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

httpx_tech = Tools("httpx",
                   "httpx -l {input} -tech-detect -o {output}",
                   "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")

wafw00f = Tools("wafw00f",
                "wafw00f -i {input} -o {output}",
                "pip install wafw00f --break-system-packages")

waybackurls = Tools("waybackurls",
                    "cat {input} | waybackurls",
                    "go install github.com/tomnomnom/waybackurls@latest",
                    use_redirect=True)

waymore = Tools("waymore",
                "waymore -i {input} -mode U -l 1000 -from 2021 -oU {output}",
                "pip install waymore --break-system-packages")

gau = Tools("gau",
            "cat {input} | gau --threads 200",
            "go install github.com/lc/gau/v2/cmd/gau@latest",
            use_redirect=True)

gauplus = Tools("gauplus",
                "gauplus -t 200 -random-agent < {input}",
                "go install github.com/bp0lr/gauplus@latest",
                use_redirect=True)

hakrawler = Tools("hakrawler",
                  "cat {input} | hakrawler -subs -u -insecure",
                  "go install github.com/hakluke/hakrawler@latest",
                  use_redirect=True)

katana = Tools("katana",
               "katana -list {input} -o {output}",
               "go install github.com/projectdiscovery/katana/cmd/katana@latest")

gospider = Tools("gospider",
                 "gospider -S {input} -t 20 -d 3 --js --sitemap --robots -o {output}",
                 "go install github.com/jaeles-project/gospider@latest")

paramspider = Tools("paramspider",
                    "paramspider -l {input} -s -o {output} --exclude css,png,svg",
                    "pip install paramspider --break-system-packages")

ffuf = Tools("ffuf",
             "ffuf -u https://{domain}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o {output} -mc 200,204,301,302,307,308,401,403,500 -v",
             "go install github.com/ffuf/ffuf/v2@latest")

dirsearch = Tools("dirsearch", "dirsearch -u https://{domain} -e conf,config,bak,backup,sql,old,db,asp,py,rb,php,cache,csv,html,inc,jar,js,json,jsp,lock,log,rar,zip,txt,env,ini --full-url --delay=10 --timeout=30 --random-agent -t 50 -w /usr/share/seclists/Discovery/Web-Content/combined_words.txt -o {output}",
                  "pip install dirsearch --break-system-packages")

feroxbuster = Tools("feroxbuster",
                    "feroxbuster -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o {output}",
                    "sudo apt install feroxbuster -y")

# Results Dictionary
results = {"target": args.domain,
           "date": datetime.now().isoformat(),
           "Subdomains": [],
           "Ports": [],
           "Alive_Domains": [],
           "Infrastructure": [],
           "Technologies": [],
           "Waf": [],
           "Endpoints": [],
           "Dirs": []
           }


def merge_and_deduplicate(output_file="allsubs.txt"):
    print("[*] Merging and removing duplicates...")
    all_subs = set()
    for file in glob.glob("subs*.txt"):
        if os.path.exists(file):
            with open(file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line: all_subs.add(line)
    with open(output_file, "w") as f:
        for sub in sorted(all_subs): f.write(sub + "\n")
    return output_file

def download_resolvers():
    if not os.path.exists("resolvers.txt"):
        print("[*] Downloading resolvers.txt...")
        urllib.request.urlretrieve("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", "resolvers.txt")

def merge_urls():
    print("[*] Merging all URLs...")
    all_urls = set()
    for file in glob.glob("wb*.txt") + ["wm.txt", "gau.txt", "gaup.txt", "hk.txt", "ktn.txt", "gs.txt", "ps.txt"]:
        if os.path.exists(file):
            with open(file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line: all_urls.add(line)
    with open("allurls.txt", "w") as f:
        for url in sorted(all_urls): f.write(url + "\n")

def merge_dirs():
    print("[*] Merging directory results...")
    all_dirs = set()
    for file in ["ffuf.txt", "dirsearch.txt", "feroxbuster.txt"]:
        if os.path.exists(file):
            with open(file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line: all_dirs.add(line)
    with open("alldirs.txt", "w") as f:
        for d in sorted(all_dirs): f.write(d + "\n")

def send_telegram_msg(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": f"🚀 [1Recon Notification]\n\n{message}"}

    try:
        requests.post(url, data=payload, timeout=10)
    except Exception as e: 
        print(f"[!] Failed to send Telegram notification: {e}")

def signal_handler(sig, frame):
    print("\n[!] Emergency Stop! Killing all tasks...")
    os.killpg(os.getpgrp(), signal.SIGTERM)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# --- [Fix: Helper to Count Lines Safely] ---
def count_lines(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return len(f.readlines())
    return 0

# ===== Execution Engine =====
try:
    os.setpgrp() 
    print(f"[+] Starting Recon on {args.domain}")

    # Step 1: Subdomain Only
    if args.domain and args.subs:
        print("[*] Running Subdomain Enumeration Only")
        sub_tools = [(subfinder, "subs_subfinder.txt"),
                     (assetfinder, "subs_assetfinder.txt"),
                     (subenum, "subs_subenum.txt"),
                     (sublist3r, "subs_sublist3r.txt"),
                     (findomain, "subs_findomain.txt"),
                     (chaos, "subs_chaos.txt"),
                     (github_subdomains, "subs_github.txt"),
                     (amass, "subs_amass.txt")]
        download_resolvers()
        with ThreadPoolExecutor(max_workers=2) as executor:
            for tool_obj, out_name in sub_tools:
                tool_obj.install_tool()
                executor.submit(tool_obj.run, domain=args.domain, output=out_name)
        
        merge_and_deduplicate("allsubs.txt")
        count = count_lines("allsubs.txt") 
        send_telegram_msg(f"✅ Subdomain Enumeration Finished!\nTarget: {args.domain}\nFound: {count} Subdomains.")
        sys.exit(0)

    # Step 2: Paths Only
    elif args.domain and args.paths:
        print("[*] Running Path Enumeration Only")
        ffuf.run(domain=args.domain, output="ffuf.txt")
        dirsearch.run(domain=args.domain, output="dirsearch.txt")
        merge_dirs()
        # Fix: Run URL tools
        waybackurls.run(input="allsubs.txt", output="wb1.txt")
        merge_urls()
        
        dir_count = count_lines("alldirs.txt")
        url_count = count_lines("allurls.txt")
        send_telegram_msg(f"✅ Path Enumeration Finished!\nTarget: {args.domain}\nFound: {dir_count} Directories, {url_count} URLs.")
        sys.exit(0)
    
    # Step 3: Full Recon
    else:
        # Step 1
        sub_tools = [(subfinder, "subs_subfinder.txt"), (assetfinder, "subs_assetfinder.txt"), (subenum, "subs_subenum.txt"), (sublist3r, "subs_sublist3r.txt"), (amass, "subs_amass.txt"), (findomain, "subs_findomain.txt"), (chaos, "subs_chaos.txt"), (github_subdomains, "subs_github.txt")]
        download_resolvers()
        with ThreadPoolExecutor(max_workers=4) as executor:
            for tool_obj, out_name in sub_tools:
                tool_obj.install_tool()
                executor.submit(tool_obj.run, domain=args.domain, output=out_name)
        
        merge_and_deduplicate("allsubs.txt")
        sub_count = count_lines("allsubs.txt")
        send_telegram_msg(f"✅ Step 1 Finished!\nTarget: {args.domain}\nFound: {sub_count} Subdomains.")

        # Step 2: Alive
        httpx.run(input="allsubs.txt", output="all_httpx.txt")
        httpx200.run(input="allsubs.txt", output="httpx200.txt")
        alive_count = count_lines("httpx200.txt")
        send_telegram_msg(f"Found: {alive_count} Alive Domains.")

        # Step 3: Nmap
        nmap.run(input="allsubs.txt", output="nmap.txt", timeout=3600) 
        send_telegram_msg(f"✅ Step 3: Port Scanning Finished.")

        # Step 4: Infra
        asnmap.run(domain=args.domain, output="asnmap.txt")
        whois_tool.run(domain=args.domain, output="whois.txt")
        dnsx.run(input="allsubs.txt", output="dnsx.txt")
        infra_count = count_lines("asnmap.txt")
        send_telegram_msg(f"✅ Step 4: Infrastructure Finished. Found {infra_count} entries.")

        # Steps 5-8 (Sequential)
        httpx_tech.run(input="httpx200.txt", output="technologies.txt")
        wafw00f.run(input="httpx200.txt", output="wafs.txt")
        
        waybackurls.run(input="allsubs.txt", output="wb1.txt")
        waymore.run(input="httpx200.txt", output="wm.txt")
        gau.run(input="allsubs.txt", output="gau.txt")
        katana.run(input="httpx200.txt", output="ktn.txt")
        paramspider.run(input="httpx200.txt", output="ps.txt")
        merge_urls()
        
        ffuf.run(domain=args.domain, output="ffuf.txt")
        dirsearch.run(domain=args.domain, output="dirsearch.txt")
        merge_dirs()

        # --- [Fix: Safe Results Collection] ---
        for key, filename in [("Subdomains", "allsubs.txt"), ("Alive_Domains", "httpx200.txt"), ("Ports", "nmap.txt"), ("Infrastructure", "asnmap.txt"), ("Technologies", "technologies.txt"), ("Waf", "wafs.txt"), ("Endpoints", "allurls.txt"), ("Dirs", "alldirs.txt")]:
            if os.path.exists(filename):
                with open(filename) as f: results[key] = f.read().splitlines()

        send_telegram_msg(f"🏁 Recon Complete for {args.domain}!\nResults saved to {args.output}")

except KeyboardInterrupt:
    print("\n[!] Stopped by user. Saving results...")
finally:
    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to {args.output}")
