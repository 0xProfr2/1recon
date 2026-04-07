# 🚀 1Recon v1.0.0 - Advanced Multi-Threaded Recon Framework

**1Recon** is an all-in-one automation tool designed for **Red Teamers** and **Bug Hunters**. It streamlines the reconnaissance phase by integrating industry-standard tools into a high-performance, multi-threaded pipeline.

## ✨ Features

- **Multi-threaded Subdomain Enumeration:** Runs multiple tools (Subfinder, Amass, Assetfinder, etc.) simultaneously.
- **Alive Domain Checker:** Integrated with HTTPX for rapid status checking.
- **Port Scanning**: Using Nmap to scan open ports, run scripts and bypass waf
- **Smart URL Filtering:** Automatically extracts "Juicy" URLs with parameters for injection testing (SQLi, XSS, SSRF, IDOR).
- **Infrastructure Discovery:** ASN mapping, WHOIS, and DNS records.
- **Technology & WAF Detection:** Identify backend stacks and firewalls instantly.
- **🛡️ Secure Configuration:** Uses `.env` files to protect your API keys and sensitive tokens.

## 🗺️ Roadmap (Coming Soon)

- [ ] **Telegram Bot Integration:** Get real-time status updates and final reports directly to your phone.
- [ ] **Nuclei Integration:** Auto-scan for known vulnerabilities after discovery.
- [ ] **Visual Dashboard:** Generate HTML reports for better data visualization.

## ⚙️ Installation & Setup

1. **Clone the Repo:**

```bash
git clone https://github.com/0xProfr2/1recon.git
cd 1recon

sudo cp 1recon.py /usr/local/bin/1recon
# أعطه صلاحية التنفيذ
sudo chmod +x /usr/local/bin/1recon
```
## ## 🚀 Usage Guide

To start a full reconnaissance mission, use the following command:

```bash
1recon -d <target_domain> -o <output_file>
```

## 🛠️ Available Options
- **-d --domain** The target domain to scan (e.g., example.com ).
- **-o --outputName** of the final JSON report fileNoreport.json.
- **-h --helpShow the** help message and exit.

