"""
RECONQUEST - Central Tool Manager & Detection Engine
Provides detection, health checks, version discovery, and installation registries
for all supported cybersecurity tools on Ubuntu Linux.
"""

import os
import shutil
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ToolInfo:
    name: str
    display_name: str
    category: str  # 'web_recon', 'wifi_security', 'utility'
    purpose: str
    status: str = 'MISSING'  # READY, MISSING, DEPENDENCY_MISSING, NOT_COMPATIBLE, NEEDS_CONFIGURATION, ERROR
    version: Optional[str] = None
    path: Optional[str] = None
    requires_root: bool = False
    dependencies: List[str] = field(default_factory=list)
    installation_methods: List[Dict[str, str]] = field(default_factory=list)
    verification_command: str = ""
    official_url: str = ""
    notes: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'display_name': self.display_name,
            'category': self.category,
            'purpose': self.purpose,
            'status': self.status,
            'version': self.version,
            'path': self.path,
            'requires_root': self.requires_root,
            'dependencies': self.dependencies,
            'installation_methods': self.installation_methods,
            'verification_command': self.verification_command,
            'official_url': self.official_url,
            'notes': self.notes,
            'error_message': self.error_message
        }


class ToolManager:
    """Central registry and verification manager for all external security tools."""

    EXTRA_SEARCH_PATHS = [
        "/usr/bin",
        "/usr/local/bin",
        "/usr/sbin",
        "/sbin",
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/.local/bin"),
        "/opt/airgeddon",
        "/usr/share/airgeddon",
        "/opt/wifite2",
    ]

    TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
        # ================= MODULE A: WEB RECON TOOLS =================
        "nmap": {
            "display_name": "Nmap Network Scanner",
            "category": "web_recon",
            "purpose": "Authorized host, port, and network service discovery.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "nmap --version",
            "version_regex": r"Nmap version ([0-9\.]+)",
            "official_url": "https://nmap.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y nmap",
                    "description": "Recommended Ubuntu package repository installation."
                }
            ],
            "notes": "SYN stealth scans (-sS) require root; connect scans (-sT) do not."
        },
        "subfinder": {
            "display_name": "Subfinder",
            "category": "web_recon",
            "purpose": "Passive subdomain discovery using public internet sources.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "subfinder -version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/projectdiscovery/subfinder",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                    "description": "Install using Go compiler (places binary in ~/go/bin)."
                },
                {
                    "method": "binary",
                    "command": "curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep browser_download_url | grep linux_amd64.zip | cut -d '\"' -f 4 | wget -qi - && unzip -q subfinder*.zip subfinder && sudo mv subfinder /usr/local/bin/",
                    "description": "Download precompiled release binary."
                }
            ],
            "notes": "Passive tool; queries public sources without contacting target server directly."
        },
        "amass": {
            "display_name": "OWASP Amass",
            "category": "web_recon",
            "purpose": "In-depth DNS enumeration, network mapping, and external asset discovery.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "amass version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/owasp-amass/amass",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install -v github.com/owasp-amass/amass/v4/...@master",
                    "description": "Install OWASP Amass v4 using Go."
                },
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y amass",
                    "description": "Ubuntu package (if available in universe)."
                }
            ],
            "notes": "Performs intensive DNS enumeration and ASN correlation."
        },
        "assetfinder": {
            "display_name": "Assetfinder",
            "category": "web_recon",
            "purpose": "Fast discovery of subdomains and domains related to a given target.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "assetfinder -h",
            "version_regex": None,
            "official_url": "https://github.com/tomnomnom/assetfinder",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install github.com/tomnomnom/assetfinder@latest",
                    "description": "Install using Go."
                }
            ],
            "notes": "Fast passive search across crt.sh, certspotter, and public archives."
        },
        "httpx": {
            "display_name": "httpx HTTP Toolkit",
            "category": "web_recon",
            "purpose": "Multi-purpose HTTP probing, title extraction, and technology discovery.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "httpx -version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/projectdiscovery/httpx",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "description": "Install using Go."
                }
            ],
            "notes": "Probes ports 80/443, extracts HTTP status, titles, web servers, and TLS info."
        },
        "nuclei": {
            "display_name": "Nuclei Vulnerability Scanner",
            "category": "web_recon",
            "purpose": "Fast and customizable vulnerability scanning based on community templates.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "nuclei -version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/projectdiscovery/nuclei",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "description": "Install using Go."
                }
            ],
            "notes": "Requires template updates: 'nuclei -update-templates'. Authorized targets only!"
        },
        "katana": {
            "display_name": "Katana Web Crawler",
            "category": "web_recon",
            "purpose": "Next-generation crawling and endpoint discovery.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "katana -version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/projectdiscovery/katana",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                    "description": "Install Katana crawler using Go."
                }
            ],
            "notes": "Supports headless crawling, JavaScript execution, and deep link parsing."
        },
        "gau": {
            "display_name": "GetAllUrls (GAU)",
            "category": "web_recon",
            "purpose": "Fetch known URLs from Wayback Machine, Common Crawl, and AlienVault.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "gau -version",
            "version_regex": r"([0-9\.]+)",
            "official_url": "https://github.com/lc/gau",
            "installation_methods": [
                {
                    "method": "go",
                    "command": "go install github.com/lc/gau/v2/cmd/gau@latest",
                    "description": "Install GAU using Go."
                }
            ],
            "notes": "Retrieves historical URL paths without actively spidering the live application."
        },
        "whatweb": {
            "display_name": "WhatWeb",
            "category": "web_recon",
            "purpose": "Next generation web scanner identifying CMS, JS libraries, and web servers.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "whatweb --version",
            "version_regex": r"WhatWeb version ([0-9\.]+)",
            "official_url": "https://github.com/urbanadventurer/WhatWeb",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y whatweb",
                    "description": "Install WhatWeb via APT."
                }
            ],
            "notes": "Recognizes over 1,700 technologies, headers, and meta tags."
        },
        "dig": {
            "display_name": "Domain Information Groper (dig)",
            "category": "web_recon",
            "purpose": "Flexible DNS probe for querying A, AAAA, MX, NS, TXT, and SOA records.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "dig -v",
            "version_regex": r"DiG ([0-9\.\-A-Za-z]+)",
            "official_url": "https://www.isc.org/bind/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y dnsutils",
                    "description": "Install standard DNS utilities on Ubuntu."
                }
            ],
            "notes": "Standard DNS query tool provided in the bind9-dnsutils package."
        },
        "whois": {
            "display_name": "Whois Client",
            "category": "web_recon",
            "purpose": "Query domain registrar, registrant details, name servers, and expiry dates.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "whois --version",
            "version_regex": r"whois ([0-9\.]+)",
            "official_url": "https://github.com/rfc1036/whois",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y whois",
                    "description": "Install Whois utility via APT."
                }
            ],
            "notes": "Queries international WHOIS registry databases."
        },
        "curl": {
            "display_name": "cURL HTTP Client",
            "category": "web_recon",
            "purpose": "Command line tool for HTTP header inspection and web requests.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "curl --version",
            "version_regex": r"curl ([0-9\.]+)",
            "official_url": "https://curl.se/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y curl",
                    "description": "Install cURL package via APT."
                }
            ],
            "notes": "Essential utility for header fetching and SSL certificate inspection."
        },
        "wafw00f": {
            "display_name": "WAFW00F",
            "category": "web_recon",
            "purpose": "Identify and fingerprint Web Application Firewalls (WAF) guarding a target.",
            "requires_root": False,
            "dependencies": ["python3-pip"],
            "verification_command": "wafw00f --version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/EnableSecurity/wafw00f",
            "installation_methods": [
                {
                    "method": "pipx",
                    "command": "pipx install wafw00f || sudo apt install -y wafw00f",
                    "description": "Install using pipx (isolated Python environment) or APT."
                }
            ],
            "notes": "Tests HTTP behaviors to identify Cloudflare, AWS WAF, Akamai, etc."
        },

        # ================= MODULE B: WI-FI SECURITY TOOLS =================
        "aircrack-ng": {
            "display_name": "Aircrack-ng",
            "category": "wifi_security",
            "purpose": "802.11 WEP and WPA/WPA2-PSK key analyzing and testing tool.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "aircrack-ng --help",
            "version_regex": r"Aircrack-ng ([0-9\.]+)",
            "official_url": "https://www.aircrack-ng.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y aircrack-ng",
                    "description": "Standard aircrack-ng suite package on Ubuntu."
                }
            ],
            "notes": "Key auditing suite for captured four-way handshakes and PMKID."
        },
        "airmon-ng": {
            "display_name": "Airmon-ng",
            "category": "wifi_security",
            "purpose": "Enable and disable monitor mode on wireless network interfaces.",
            "requires_root": True,
            "dependencies": ["aircrack-ng"],
            "verification_command": "airmon-ng --help",
            "version_regex": None,
            "official_url": "https://www.aircrack-ng.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y aircrack-ng",
                    "description": "Included with the aircrack-ng package."
                }
            ],
            "notes": "Requires root privileges to stop interfering processes and change interface modes."
        },
        "airodump-ng": {
            "display_name": "Airodump-ng",
            "category": "wifi_security",
            "purpose": "802.11 packet capture, beacon observation, and wireless discovery.",
            "requires_root": True,
            "dependencies": ["aircrack-ng"],
            "verification_command": "airodump-ng --help",
            "version_regex": None,
            "official_url": "https://www.aircrack-ng.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y aircrack-ng",
                    "description": "Included with the aircrack-ng package."
                }
            ],
            "notes": "Captures raw 802.11 frames. Requires an adapter in monitor mode."
        },
        "aireplay-ng": {
            "display_name": "Aireplay-ng",
            "category": "wifi_security",
            "purpose": "Generate wireless traffic and test frame injection support.",
            "requires_root": True,
            "dependencies": ["aircrack-ng"],
            "verification_command": "aireplay-ng --help",
            "version_regex": None,
            "official_url": "https://www.aircrack-ng.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y aircrack-ng",
                    "description": "Included with the aircrack-ng package."
                }
            ],
            "notes": "Tests whether your wireless card is capable of packet injection."
        },
        "airdecap-ng": {
            "display_name": "Airdecap-ng",
            "category": "wifi_security",
            "purpose": "Decrypt WEP/WPA/WPA2 capture files once the key is known.",
            "requires_root": False,
            "dependencies": ["aircrack-ng"],
            "verification_command": "airdecap-ng --help",
            "version_regex": None,
            "official_url": "https://www.aircrack-ng.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y aircrack-ng",
                    "description": "Included with the aircrack-ng package."
                }
            ],
            "notes": "Useful for educational inspection of decapsulated wireless packets."
        },
        "airgeddon": {
            "display_name": "Airgeddon Wireless Auditing Framework",
            "category": "wifi_security",
            "purpose": "Multi-use bash script framework for Linux wireless security auditing.",
            "requires_root": True,
            "dependencies": ["bash", "aircrack-ng", "iw", "xterm"],
            "verification_command": "airgeddon --version",
            "version_regex": r"v([0-9\.]+)",
            "official_url": "https://github.com/v1s1t0r1sh3r3/airgeddon",
            "installation_methods": [
                {
                    "method": "git",
                    "command": "git clone --depth 1 https://github.com/v1s1t0r1sh3r3/airgeddon.git /opt/airgeddon && sudo ln -sf /opt/airgeddon/airgeddon.sh /usr/local/bin/airgeddon",
                    "description": "Clone official Git repository to /opt and create launcher link."
                }
            ],
            "notes": "Interactive terminal application. RECONQUEST launches it in an authorized local terminal window."
        },
        "wifite": {
            "display_name": "Wifite2 Automated Wireless Auditor",
            "category": "wifi_security",
            "purpose": "Automated wireless auditor for WEP, WPA-PSK, WPS, and PMKID security testing.",
            "requires_root": True,
            "dependencies": ["aircrack-ng", "iw", "python3"],
            "verification_command": "wifite --help",
            "version_regex": r"wifite v([0-9\.]+)",
            "official_url": "https://github.com/derv82/wifite2",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y wifite",
                    "description": "Install wifite package via APT (if available in Ubuntu universe)."
                },
                {
                    "method": "git",
                    "command": "git clone https://github.com/derv82/wifite2.git /opt/wifite2 && cd /opt/wifite2 && sudo python3 setup.py install",
                    "description": "Install latest Wifite2 from official source repository."
                }
            ],
            "notes": "Requires root privileges and a monitor-mode capable Wi-Fi adapter."
        },
        "iw": {
            "display_name": "iw Wireless CLI",
            "category": "wifi_security",
            "purpose": "Inspect wireless devices, capabilities, supported bands, and chipsets.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "iw --version",
            "version_regex": r"iw version ([0-9\.]+)",
            "official_url": "https://wireless.wiki.kernel.org/en/users/documentation/iw",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y iw",
                    "description": "Install standard Linux wireless configuration utility."
                }
            ],
            "notes": "Modern replacement for iwconfig. Used for hardware capability diagnostics."
        },
        "rfkill": {
            "display_name": "rfkill Subsystem Tool",
            "category": "wifi_security",
            "purpose": "Query and manage radio frequency software and hardware kill switches.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "rfkill --version",
            "version_regex": r"rfkill from util-linux ([0-9\.]+)",
            "official_url": "https://git.kernel.org/pub/scm/utils/rfkill/rfkill.git",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y rfkill",
                    "description": "Install rfkill from util-linux package."
                }
            ],
            "notes": "Crucial for verifying whether Wi-Fi adapters are soft-blocked or hard-blocked."
        },
        "nmcli": {
            "display_name": "NetworkManager CLI (nmcli)",
            "category": "wifi_security",
            "purpose": "Control NetworkManager and observe managed Wi-Fi connections and states.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "nmcli --version",
            "version_regex": r"version ([0-9\.]+)",
            "official_url": "https://networkmanager.dev/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y network-manager",
                    "description": "Standard Ubuntu NetworkManager interface."
                }
            ],
            "notes": "Used to inspect current SSID connections and manage interface conflicts."
        },
        "tshark": {
            "display_name": "TShark (Wireshark CLI)",
            "category": "wifi_security",
            "purpose": "Command-line network protocol analyzer for dissecting .pcap and .cap files.",
            "requires_root": False,
            "dependencies": [],
            "verification_command": "tshark --version",
            "version_regex": r"TShark \(Wireshark\) ([0-9\.]+)",
            "official_url": "https://www.wireshark.org/",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y tshark",
                    "description": "Terminal-based Wireshark packet dissection tool."
                }
            ],
            "notes": "Used for structured packet inspection of wireless 802.11 captures."
        },
        "macchanger": {
            "display_name": "GNU MAC Changer",
            "category": "wifi_security",
            "purpose": "View and manipulate MAC addresses of network interfaces for lab privacy.",
            "requires_root": True,
            "dependencies": [],
            "verification_command": "macchanger --version",
            "version_regex": r"GNU MAC Changer ([0-9\.]+)",
            "official_url": "https://github.com/alobbs/macchanger",
            "installation_methods": [
                {
                    "method": "apt",
                    "command": "sudo apt update && sudo apt install -y macchanger",
                    "description": "Install GNU MAC Changer utility via APT."
                }
            ],
            "notes": "Requires root. Useful for randomized MAC address testing in authorized labs."
        }
    }

    @classmethod
    def find_tool_path(cls, tool_name: str) -> Optional[str]:
        """Locate executable binary path by checking PATH and well-known search paths."""
        # Check standard PATH
        found = shutil.which(tool_name)
        if found:
            return found

        # Check alternative common locations
        for base_path in cls.EXTRA_SEARCH_PATHS:
            candidate = os.path.join(base_path, tool_name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            # In case tool is named tool.sh (e.g. airgeddon.sh)
            sh_candidate = os.path.join(base_path, f"{tool_name}.sh")
            if os.path.isfile(sh_candidate) and os.access(sh_candidate, os.X_OK):
                return sh_candidate

        return None

    @classmethod
    def get_tool_version(cls, tool_name: str, path: str) -> Optional[str]:
        """Attempt to extract tool version using safe flags."""
        registry_entry = cls.TOOL_REGISTRY.get(tool_name, {})
        ver_cmd_str = registry_entry.get("verification_command", f"{tool_name} --version")
        ver_regex = registry_entry.get("version_regex")

        try:
            parts = ver_cmd_str.split()
            # Replace tool name with full path
            parts[0] = path
            res = subprocess.run(
                parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            output = res.stdout + "\n" + res.stderr
            if ver_regex:
                match = re.search(ver_regex, output, re.IGNORECASE)
                if match:
                    return match.group(1)
            # Default fallback: check if first line has numbers
            lines = [l.strip() for l in output.splitlines() if l.strip()]
            if lines:
                first_line = lines[0]
                num_match = re.search(r"([0-9]+\.[0-9]+(\.[0-9]+)?)", first_line)
                if num_match:
                    return num_match.group(1)
                return first_line[:30]
        except Exception:
            pass
        return None

    @classmethod
    def check_tool(cls, tool_name: str) -> ToolInfo:
        """Inspect a single tool's operational readiness on the host."""
        if tool_name not in cls.TOOL_REGISTRY:
            return ToolInfo(
                name=tool_name,
                display_name=tool_name,
                category="unknown",
                purpose="Unknown utility",
                status="ERROR",
                error_message="Tool is not registered in RECONQUEST database."
            )

        data = cls.TOOL_REGISTRY[tool_name]
        path = cls.find_tool_path(tool_name)

        if not path:
            return ToolInfo(
                name=tool_name,
                display_name=data["display_name"],
                category=data["category"],
                purpose=data["purpose"],
                status="MISSING",
                requires_root=data.get("requires_root", False),
                dependencies=data.get("dependencies", []),
                installation_methods=data.get("installation_methods", []),
                verification_command=data.get("verification_command", ""),
                official_url=data.get("official_url", ""),
                notes=data.get("notes", "")
            )

        # Check dependencies
        missing_deps = []
        for dep in data.get("dependencies", []):
            if not cls.find_tool_path(dep):
                missing_deps.append(dep)

        if missing_deps:
            return ToolInfo(
                name=tool_name,
                display_name=data["display_name"],
                category=data["category"],
                purpose=data["purpose"],
                status="DEPENDENCY_MISSING",
                path=path,
                requires_root=data.get("requires_root", False),
                dependencies=data.get("dependencies", []),
                installation_methods=data.get("installation_methods", []),
                verification_command=data.get("verification_command", ""),
                official_url=data.get("official_url", ""),
                notes=data.get("notes", ""),
                error_message=f"Missing dependencies: {', '.join(missing_deps)}"
            )

        version = cls.get_tool_version(tool_name, path)

        return ToolInfo(
            name=tool_name,
            display_name=data["display_name"],
            category=data["category"],
            purpose=data["purpose"],
            status="READY",
            path=path,
            version=version,
            requires_root=data.get("requires_root", False),
            dependencies=data.get("dependencies", []),
            installation_methods=data.get("installation_methods", []),
            verification_command=data.get("verification_command", ""),
            official_url=data.get("official_url", ""),
            notes=data.get("notes", "")
        )

    @classmethod
    def check_all_tools(cls) -> Dict[str, ToolInfo]:
        """Check all registered tools and return status dict."""
        results = {}
        for tool_name in cls.TOOL_REGISTRY:
            results[tool_name] = cls.check_tool(tool_name)
        return results

    @classmethod
    def get_tools_by_category(cls, category: str) -> List[ToolInfo]:
        """Return tools filtered by category ('web_recon' or 'wifi_security')."""
        return [
            cls.check_tool(name)
            for name, meta in cls.TOOL_REGISTRY.items()
            if meta.get("category") == category
        ]

    @classmethod
    def is_tool_ready(cls, tool_name: str) -> bool:
        """Quick boolean test if a tool is ready for execution."""
        return cls.check_tool(tool_name).status == "READY"
