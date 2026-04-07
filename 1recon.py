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
from datetime import datetime
from traceback import print_tb
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv


print("""
 ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
███║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
╚██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
print(f"        All Bug Bounty Recon Tools In One {CURRENT_VERSION}")
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
                urllib.request.urlretrieve(TOOL_URL, "Recon.py")
                print("[+] Update downloaded successfully!")
                print("[*] Please restart the tool.")
                sys.exit(0)
        else:
            print(f"[+] Already up to date ({CURRENT_VERSION})")

    except Exception as e:
        print(f"[-] Could not check for updates: {e}")
    except KeyboardInterrupt:
        print("\n Good Bye")
        sys.exit(0)


check_for_updates()

# Parser Options
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", dest="domain", required=True, help="Target to Scan")
parser.add_argument("-s", "--subs", dest="subs", help="recon on subdomains only")
parser.add_argument("-p", "--path", dest="paths", help="recon on paths only")
parser.add_argument("-o", "--output", dest="output", default="report.json", metavar="FILE", help="output file")
args = parser.parse_args()


# Tools Class
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

    def run(self, output, domain=None, input=None):
        if self.use_tee:
            cmd = f"{self.command.format(domain=domain, input=input)} | tee {output}"
        elif self.use_redirect:
            cmd = f"{self.command.format(domain=domain, input=input)} > {output}"
        else:
            cmd = self.command.format(domain=domain, input=input, output=output)

        print(f"[*] Running {self.check}...")
        subprocess.call(cmd, shell=True)

# ============ API KEYS ============
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
PDCP_API_KEY = os.getenv("PDCP_API_KEY", "")

# ============ TOOL DEFINITIONS ============

# ============ PASSIVE SCAN ============
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

# ============ ACTIVE SCAN ============
hakrevdns = Tools(
    check="hakrevdns",
    command="hakrevdns -d {domain} -R resolvers.txt",
    install="go install github.com/hakluke/hakrevdns@latest",
    use_redirect=True
)

magicrecon = Tools(
    check="magicrecon.sh",
    command="magicrecon.sh -l targets.txt --all",
    install="git clone https://github.com/nardholio/magicrecon"
)

dnscan = Tools(
    check="dnscan.py",
    command="python3 dnscan/dnscan.py -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million110000.txt",
    install="git clone https://github.com/rbsec/dnscan",
    use_tee=True
)

# ============ STEP 2 - ALIVE DOMAINS CHECK ============
httpx = Tools(
    check="httpx",
    command="httpx -l {input} -status-code -title -content-length -follow-redirects -web-server -o {output}",
    install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

httpx200 = Tools(
    check="httpx",
    command="httpx -l {input} -status-code -title -content-length -follow-redirects -web-server -mc 200 -o {output}",
    install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

# ============ STEP 3 - PORT SCANNING ============
nmap = Tools(
    check="nmap",
    command="nmap -iL {input} -sV -p- -sC -Pn --open -o {output}",
    install="sudo apt install nmap -y"
)

# ============ STEP 4 - INFRASTRUCTURE DISCOVERY ============
asnmap = Tools(
    check="asnmap",
    command="asnmap -d {domain} -o {output}",
    install="go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
)

whois_tool = Tools(
    check="whois",
    command="whois -h whois.radb.net {domain}",
    install="sudo apt install whois -y",
    use_redirect=True
)

dnsx = Tools(
    check="dnsx",
    command="dnsx -silent -resp-only -ptr -l {input} -o {output}",
    install="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
)

# ============ STEP 5 - KNOW TECHNOLOGIES ============
httpx_tech = Tools(
    check="httpx",
    command="httpx -l {input} -tech-detect -o {output}",
    install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

# ============ STEP 6 - KNOW WAFS ============
wafw00f = Tools(
    check="wafw00f",
    command="wafw00f -i {input} -o {output}",
    install="pip install wafw00f --break-system-packages"
)

# ============ STEP 7 - GATHER URLS & ENDPOINTS ============
waybackurls = Tools(
    check="waybackurls",
    command="cat {input} | waybackurls",
    install="go install github.com/tomnomnom/waybackurls@latest",
    use_redirect=True
)

waymore = Tools(
    check="waymore",
    command="waymore -i {input} -mode U -l 1000 -from 2021 -oU {output}",
    install="pip install waymore --break-system-packages"
)

gau = Tools(
    check="gau",
    command="cat {input} | gau --threads 200",
    install="go install github.com/lc/gau/v2/cmd/gau@latest",
    use_redirect=True
)

gauplus = Tools(
    check="gauplus",
    command="gauplus -t 200 -random-agent < {input}",
    install="go install github.com/bp0lr/gauplus@latest",
    use_redirect=True
)

hakrawler = Tools(
    check="hakrawler",
    command="cat {input} | hakrawler -subs -u -insecure",
    install="go install github.com/hakluke/hakrawler@latest",
    use_redirect=True
)

katana = Tools(
    check="katana",
    command="katana -list {input} -o {output}",
    install="go install github.com/projectdiscovery/katana/cmd/katana@latest"
)

gospider = Tools(
    check="gospider",
    command="gospider -S {input} -t 20 -d 3 --js --sitemap --robots -o {output}",
    install="go install github.com/jaeles-project/gospider@latest"
)

paramspider = Tools(
    check="paramspider",
    command="paramspider -l {input} -s -o {output} --exclude css,png,svg",
    install="pip install paramspider --break-system-packages"
)

# ============ STEP 8 - DIRECTORY & FILE DISCOVERY ============
ffuf = Tools(
    check="ffuf",
    command="ffuf -u https://{domain}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o {output} -mc 200,204,301,302,307,308,401,403,500 -v",
    install="go install github.com/ffuf/ffuf/v2@latest"
)

dirsearch = Tools(
    check="dirsearch",
    command="dirsearch -u https://{domain} -e conf,config,bak,backup,sql,old,db,asp,py,rb,php,cache,csv,html,inc,jar,js,json,jsp,lock,log,rar,zip,txt,env,ini --full-url --delay=10 --timeout=30 --random-agent -t 50 -w /usr/share/seclists/Discovery/Web-Content/combined_words.txt -o {output}",
    install="pip install dirsearch --break-system-packages"
)

feroxbuster = Tools(
    check="feroxbuster",
    command="feroxbuster -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o {output}",
    install="sudo apt install feroxbuster -y"
)

# Results Dictionary
results = {
    "target": args.domain,
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


# Functions
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
    print(f"[+] Found {len(all_subs)} unique subdomains -> {output_file}")
    return output_file


def download_resolvers():
    if not os.path.exists("resolvers.txt"):
        print("[*] Downloading resolvers.txt...")
        urllib.request.urlretrieve("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt","resolvers.txt")
    else:
        print("[+] resolvers.txt already exists")


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


def extract_juicy_urls(input_file, output_file):
    print("[*] Extracting juicy URLs for Bug Hunting...")
    regex = r".*?[\?\&][a-zA-Z0-9_]+\=.*"
    juicy = set()
    if os.path.exists(input_file):
        with open(input_file, 'r') as f:
            for line in f:
                if re.match(regex, line): juicy.add(line.strip())
        with open(output_file, 'w') as f:
            f.write("\n".join(juicy))
    print(f"[+] Found {len(juicy)} URLs with parameters -> {output_file}")


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
        return # Skip if not configured
        
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"🚀 [1Recon Notification]\n\n{message}",
        "parse_mode": "Markdown"
    }
    
    try:
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        print(f"[!] Failed to send Telegram notification: {e}")

# --- Execution Engine ---
try:
    print(f"[+] Starting Recon on {args.domain}")

    # Step 1: Subdomain Enumeration (Parallel Execution)
    print("[*] Step 1: Subs Enumeration (Multi-threaded)")
    sub_tools = [
        (subfinder, "subs_subfinder.txt"), (assetfinder, "subs_assetfinder.txt"),
        (subenum, "subs_subenum.txt"), (sublist3r, "subs_sublist3r.txt"),
        (amass, "subs_amass.txt"), (findomain, "subs_findomain.txt"),
        (chaos, "subs_chaos.txt"), (github_subdomains, "subs_github.txt")
    ]

    download_resolvers()

    # run subdomain tools in one time to save time
    with ThreadPoolExecutor(max_workers=4) as executor:
        for tool_obj, out_name in sub_tools:
            tool_obj.install_tool()
            executor.submit(tool_obj.run, domain=args.domain, output=out_name)

    # الأدوات اللي بتحتاج تعامل خاص أو ملفات معينة بتكمل هنا
    hakrevdns.run(domain=args.domain, output="subs_hakrevdns.txt")
    dnscan.run(domain=args.domain, output="subs_dnscan.txt")

    allsubs = merge_and_deduplicate("allsubs.txt")
    print("[+] Step 1 Finished!")
    send_telegram_msg(f"✅ Step 1 Finished!\nTarget: {args.domain}\nFound: {len(allsubs)} Subdomains.")

    # Steps 2 to 8 (Sequential)
    print("[*] Step 2: Alive Domains")
    httpx.run(input="allsubs.txt", output="all_httpx.txt")
    httpx200.run(input="allsubs.txt", output="httpx200.txt")
    print("[+] Step 2 Finished!")
    send_telegram_msg(f"✅ Step 2 Finished!\nTarget: {args.domain}\nFound: {len(httpx200)} Alive Domains.")
    
    print("[*] Step 3: Port Scanning")
    nmap.run(input="allsubs.txt", output="nmap.txt")
    print("[+] Step 3 Finished!")
    send_telegram_msg(f"✅ Step 3 Finished!\nTarget: {args.domain}\nFound: {len(nmap)} Ports.")

    print("[*] Step 4: Infrastructure Discovery")
    asnmap.run(domain=args.domain, output="asnmap.txt")
    whois_tool.run(domain=args.domain, output="whois.txt")
    dnsx.run(input="allsubs.txt", output="dnsx.txt")
    print("[+] Step 4 Finished!")
    send_telegram_msg(f"✅ Step 4 Finished!\nTarget: {args.domain}\nFound: {len(asnmap)} ASNs, {len(whois_tool)} Whois Records, {len(dnsx)} PTR Records.")

    print("[*] Step 5: Know Technologies")
    httpx_tech.run(input="httpx200.txt", output="technologies.txt")
    print("[+] Step 5 Finished!")
    send_telegram_msg(f"✅ Step 5 Finished!\nTarget: {args.domain}\nFound: {len(httpx_tech)} Technologies.")

    print("[*] Step 6: Know WAFs")
    wafw00f.run(input="httpx200.txt", output="wafs.txt")
    print("[+] Step 6 Finished!")
    send_telegram_msg(f"✅ Step 6 Finished!\nTarget: {args.domain}\nFound: {len(wafw00f)} WAFs.")

    print("[*] Step 7: Gather URLs & Endpoints")
    waybackurls.run(input="allsubs.txt", output="wb1.txt")
    waymore.run(input="httpx200.txt", output="wm.txt")
    gau.run(input="allsubs.txt", output="gau.txt")
    katana.run(input="httpx200.txt", output="ktn.txt")
    paramspider.run(input="httpx200.txt", output="ps.txt")
    merge_urls()
    print("[+] Step 7 Finished!")
    send_telegram_msg(f"✅ Step 7 Finished!\nTarget: {args.domain}\nFound: {len(gau)} URLs.")


    print("[*] Step 8: Directory Discovery")
    ffuf.run(domain=args.domain, output="ffuf.txt")
    dirsearch.run(domain=args.domain, output="dirsearch.txt")
    merge_dirs()
    print("[+] Step 8 Finished!")
    send_telegram_msg(f"✅ Step 8 Finished!\nTarget: {args.domain}\nFound: {len(ffuf) + len(dirsearch)} Directories.")


    # Final Result Collection
    for key, filename in [
        ("Subdomains", "allsubs.txt"), ("Alive_Domains", "httpx200.txt"),
        ("Ports", "nmap.txt"), ("Infrastructure", "asnmap.txt"),
        ("Technologies", "technologies.txt"), ("Waf", "wafs.txt"),
        ("Endpoints", "allurls.txt"), ("Dirs", "alldirs.txt")
    ]:
        if os.path.exists(filename):
            with open(filename) as f: results[key] = f.read().splitlines()

except KeyboardInterrupt:
    print("\n[!] Recon stopped by user. Saving results...")
finally:
    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to {args.output}")
    send_telegram_msg(f"🏁 Recon Complete for {args.domain}!\nResults saved to {args.output}")