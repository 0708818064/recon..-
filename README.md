# RECONQUEST
### Enterprise-Grade Cybersecurity Reconnaissance & Security Assessment Platform for Ubuntu Linux

```text
  ____  _____ ____ ___  _   _  ___  _   _ _____ ____ _____ 
 |  _ \| ____/ ___/ _ \| \ | |/ _ \| | | | ____/ ___|_   _|
 | |_) |  _|| |  | | | |  \| | | | | | | |  _| \___ \ | |  
 |  _ <| |__| |__| |_| | |\  | |_| | |_| | |___ ___) || |  
 |_| \_\_____\____\___/|_| \_|\__\_\\___/|_____|____/ |_|  
   CYBERSECURITY RECONNAISSANCE & SECURITY ASSESSMENT
```

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20Linux-E95420?style=flat&logo=ubuntu)](https://ubuntu.com/)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=flat&logo=python)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-000000?style=flat&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-059669.svg)](LICENSE)
[![Theme](https://img.shields.io/badge/Theme-Black%20%26%20Emerald%20Green-10b981)](reconquest/static/css/style.css)

---

## 1. Executive Summary

**RECONQUEST** is an interactive, game-style cybersecurity reconnaissance and security assessment toolkit engineered specifically for Ubuntu Linux. Built with a sleek, high-contrast **Black & Emerald Green cybersecurity UI**, it empowers security engineers, penetration testers, and security students to conduct authorized assessments by clicking numbered tactical missions or pressing keyboard shortcuts `[1]` through `[11]`, eliminating the need to memorize complex terminal command-line syntax.

The platform integrates **real cybersecurity tools** directly on the host system. It does **not** simulate scans, mock output, or fabricate findings.

### Primary Engineering Objectives
- **Zero Fabrication**: All discoveries, banner grasps, DNS queries, and vulnerability findings originate from verified external Linux binaries (`nmap`, `subfinder`, `httpx`, `nuclei`, `katana`, `amass`, `aircrack-ng`, `wifite`, `airgeddon`, `dig`, `whois`, etc.).
- **Strict Scope Boundaries**: Prohibits out-of-scope testing through an integrated Rules of Engagement (RoE) Scope Manager that validates FQDNs, IPv4/IPv6 addresses, CIDR ranges, and Wi-Fi BSSIDs.
- **Central Tool Registry & Detection**: Automatically checks `PATH` and non-standard directories (`~/go/bin`, `~/.local/bin`, `/opt/`, `/usr/sbin/`). Provides copyable verified installation commands and real-time health checks without running arbitrary shell scripts.
- **Process Isolation & Defense**: Executes commands using argument arrays (`shell=False`) with process group isolation, output buffer limits, and automatic timeouts to prevent runaway processes.
- **Gamified Campaign Progression**: Features an integrated operator level system, mission checklists, and achievement badges that award Experience Points (XP) for authorized testing and verification.
- **Multi-Format Reporting**: Generates standalone executive HTML reports, machine-readable JSON data, and tabular CSV files.

---

## 2. Platform Architecture

### Main Tactical Menu Structure
```text
RECONQUEST
Cybersecurity Reconnaissance and Security Assessment

[1] Web Reconnaissance
[2] Wi-Fi Security Testing
[3] Full Reconnaissance Campaign
[4] Tool Manager and Installation Center
[5] Target and Scope Manager
[6] Scan History
[7] Results and Reports
[8] Learning Center
[9] Progress and Achievements
[10] System Diagnostics
[11] Settings
[0] Exit / Info
```

### Modular Project Layout
```text
reconquest/
├── app.py                      # Application factory and CLI runner
├── config.py                   # Environment, security limits, and directory setup
├── requirements.txt            # Python dependencies (Flask, SQLAlchemy, WTForms, etc.)
├── README.md                   # Complete architectural and operational manual
│
├── core/
│   ├── tool_manager.py         # Central tool detection & verification registry
│   ├── installation_manager.py # Ubuntu package & build prerequisites manager
│   ├── scope_manager.py        # Scope validation & boundary enforcement engine
│   ├── command_builder.py      # Sanitized argument array builder (shell=False)
│   ├── process_manager.py      # Subprocess group isolation, timeouts, and streaming
│   ├── job_manager.py          # Background task coordinator & output parsers
│   └── logging_config.py       # JSON audit trail and structured logger
│
├── modules/
│   ├── web_recon/
│   │   ├── __init__.py
│   │   └── service.py          # Subfinder, Amass, Nmap, httpx, Nuclei, dig
│   └── wifi_security/
│       ├── __init__.py
│       └── service.py          # Adapter diagnostics, beacon scan, terminal launchers
│
├── database/
│   ├── db.py                   # SQLAlchemy database initialization
│   └── models.py               # Models for Users, Targets, Scans, Missions, Achievements
│
├── reports/
│   ├── html_report.py          # Styled standalone HTML assessment generator
│   ├── json_report.py          # Structured JSON data export
│   └── csv_report.py           # Tabular CSV export
│
├── templates/                  # Modern Black & Green Jinja2 templates
│   ├── base.html               # Layout with XP bar, numbered shortcuts, notifications
│   ├── dashboard.html          # Main Tactical Selector
│   ├── web_recon.html          # Subdomain, port, tech, and vuln assessment
│   ├── wifi_security.html      # Adapter diagnostics & wireless lab
│   ├── tool_manager.html       # Tool installation center with copy/verify workflow
│   ├── scope_manager.html      # Scope definition & audit view
│   ├── scan_history.html       # Searchable history & terminal inspection
│   ├── results.html            # Deliverables dashboard
│   ├── learning.html           # Gamified cybersecurity missions
│   ├── achievements.html       # Accolades and rank progression
│   ├── diagnostics.html        # Ubuntu system environment health
│   └── settings.html           # Runtime limits and operator settings
│
├── static/
│   ├── css/style.css           # Professional Black & Green enterprise stylesheet
│   └── js/app.js               # Numbered keyboard navigation & live stream poller
│
└── tests/                      # Automated test suite (Pytest)
    ├── test_tool_manager.py
    ├── test_installation_manager.py
    ├── test_scope_manager.py
    ├── test_command_builder.py
    ├── test_web_recon.py
    └── test_wifi_security.py
```

---

## 3. Supported Cybersecurity Tools

| Tool | Category | Primary Purpose | Packaging Method |
| :--- | :--- | :--- | :--- |
| **Nmap** | Web Recon | Host discovery, port scanning, service versioning | Ubuntu APT (`nmap`) |
| **Subfinder** | Web Recon | Passive subdomain discovery via public sources | Go Binary (`projectdiscovery/subfinder`) |
| **Amass** | Web Recon | In-depth DNS enumeration and ASN mapping | Go / Snap / APT |
| **Assetfinder** | Web Recon | Passive subdomain and domain discovery | Go (`tomnomnom/assetfinder`) |
| **httpx** | Web Recon | HTTP probe, title, status code, and tech grabber | Go (`projectdiscovery/httpx`) |
| **Nuclei** | Web Recon | Community-powered template vulnerability scanner | Go (`projectdiscovery/nuclei`) |
| **Katana** | Web Recon | Next-generation web crawler & endpoint discovery | Go (`projectdiscovery/katana`) |
| **GAU** | Web Recon | Historical URLs from Wayback, AlienVault, etc. | Go (`lc/gau`) |
| **WhatWeb** | Web Recon | Web technology fingerprinting (1700+ plugins) | Ubuntu APT (`whatweb`) |
| **dig** | Web Recon | DNS queries (ANY, A, AAAA, MX, NS, TXT) | Ubuntu APT (`dnsutils`) |
| **whois** | Web Recon | Domain registration, registrar, nameserver info | Ubuntu APT (`whois`) |
| **curl** | Web Recon | HTTP response inspection and SSL verification | Ubuntu APT (`curl`) |
| **Aircrack-ng** | Wi-Fi | 802.11 WEP/WPA key auditing and capture verify | Ubuntu APT (`aircrack-ng`) |
| **Airmon-ng** | Wi-Fi | Wireless interface monitor mode management | Ubuntu APT (`aircrack-ng`) |
| **Airodump-ng** | Wi-Fi | 802.11 beacon observation and packet capture | Ubuntu APT (`aircrack-ng`) |
| **Aireplay-ng** | Wi-Fi | Frame injection testing | Ubuntu APT (`aircrack-ng`) |
| **Airdecap-ng** | Wi-Fi | Decrypt wireless captures with known key | Ubuntu APT (`aircrack-ng`) |
| **Airgeddon** | Wi-Fi | Interactive wireless security auditing framework | Official Git repository |
| **Wifite** | Wi-Fi | Automated wireless auditing tool | Ubuntu APT / Git |
| **iw / rfkill** | Wi-Fi | Linux wireless hardware and radio block diagnostics | Ubuntu APT (`iw`, `rfkill`) |
| **nmcli** | Wi-Fi | NetworkManager airspace discovery | Ubuntu APT (`network-manager`) |
| **tshark** | Wi-Fi | Terminal-based packet analysis & dissection | Ubuntu APT (`tshark`) |

---

## 4. Installation & Setup on Ubuntu Linux

### Prerequisites
Make sure Python 3.10+, pip, and venv are installed:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

### Step 1: Clone or Navigate to Project
```bash
git clone git@github.com:0708818064/recon..-.git
cd recon..-
```

### Step 2: Initialize Python Virtual Environment
```bash
python3 -m venv reconquest/venv
source reconquest/venv/bin/activate
pip install --upgrade pip
pip install -r reconquest/requirements.txt
```

### Step 3: Install External Security Tools (As Needed)
You can inspect what tools are missing directly in the web UI under **[4] Tool Manager**, or install them via terminal:

```bash
# Core Web Recon Utilities
sudo apt install -y nmap dnsutils curl whois whatweb

# Wireless Security Utilities
sudo apt install -y aircrack-ng iw rfkill network-manager tshark macchanger

# ProjectDiscovery Go Tools (if Golang is installed)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## 5. Running the Application

Start the local server with your virtual environment active:
```bash
cd reconquest
source venv/bin/activate
python3 app.py
```

The application starts on the localhost loopback interface:
```text
  ____  _____ ____ ___  _   _  ___  _   _ _____ ____ _____ 
 |  _ \| ____/ ___/ _ \| \ | |/ _ \| | | | ____/ ___|_   _|
 | |_) |  _|| |  | | | |  \| | | | | | | |  _| \___ \ | |  
 |  _ <| |__| |__| |_| | |\  | |_| | |_| | |___ ___) || |  
 |_| \_\_____\____\___/|_| \_|\__\_\\___/|_____|____/ |_|  
   CYBERSECURITY RECONNAISSANCE & SECURITY ASSESSMENT
    
[*] Bound securely to 127.0.0.1:5000
[*] Press Ctrl+C in this terminal to exit.
```

Open **`http://127.0.0.1:5000`** in your browser.

---

## 6. How to Use the UI

### 1. Scope Authorization (First Step)
Before scanning, navigate to **[5] Target and Scope Manager**.
1. Enter your target (e.g., `scanme.nmap.org` or `192.168.1.0/24`).
2. Add authorization notes.
3. Click **Add to Scope**. Any attempt to scan targets not registered in scope will be automatically rejected.

### 2. Web Reconnaissance Missions
Navigate to **[1] Web Reconnaissance**.
1. Choose an operation tab: `[2] Subdomain Discovery`, `[3] DNS Intelligence`, `[4] Live Host Discovery`, `[5] Port & Service Scan`, `[7] URL Crawling`, or `[10] Vulnerability Scan`.
2. Enter your authorized target.
3. Click **Verify Scope** to validate authorization.
4. Preview the exact argument array by clicking **Preview Command**.
5. Click **Execute Reconnaissance** to stream real-time output in the integrated console.
6. Cancel execution at any time by clicking **Stop Operation**.

### 3. Wi-Fi Security Lab
Navigate to **[2] Wi-Fi Security Lab**.
- **Adapter Diagnostics**: Inspect physical wireless interfaces, monitor mode capability, and `rfkill` blocks.
- **Airspace Discovery**: Catalog visible 802.11 access points (SSID, BSSID, channel, signal strength, encryption).
- **Interactive Frameworks (Airgeddon & Wifite)**: Launches in a local native terminal (`gnome-terminal`, `xterm`, etc.) with authentic Ubuntu `sudo` prompts. The web interface never asks for or stores root passwords.

### 4. Results & Reports
Navigate to **[7] Results and Reports**.
- View structured findings for any completed assessment.
- Export to standalone **HTML Report**, **JSON**, or **CSV**.

---

## 7. Automated Testing

RECONQUEST includes a comprehensive automated test suite built with `pytest`:
```bash
cd reconquest
source venv/bin/activate
pytest tests/ -v
```

All 19 test cases verify:
- Tool detection across directories and version regex parsing
- Scope boundary enforcement, IPv4/IPv6 validation, and CIDR math
- Argument injection prevention (blocking `;`, `&`, `|`, `` ` ``, `$`, `>`, `<`)
- Real tool output parsing (Nmap open ports, Subfinder hostnames, httpx titles, nmcli BSSIDs)
- Environmental diagnostics extraction

---

## 8. Security & Ethical RoE Notice

> **LEGAL NOTICE**:
> RECONQUEST is designed strictly for authorized penetration testing, security auditing, and educational research in controlled labs where explicit written permission has been obtained. Scanning or testing third-party networks or systems without authorization is illegal under the Computer Fraud and Abuse Act (CFAA) and international cyber laws.
