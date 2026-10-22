"""
RECONQUEST - Safe Command Builder
Safely constructs argument arrays for subprocess execution.
Strictly disallows shell metacharacters and enforces whitelisted parameters.
"""

import re
from typing import List, Optional, Dict, Any
from .tool_manager import ToolManager


class CommandBuilder:
    """Constructs sanitized command line argument lists without shell interpolation."""

    # Disallow dangerous shell metacharacters in any parameter
    FORBIDDEN_CHARS = re.compile(r'[;&|`$><!\\(\)\{\}\[\]\n\r]')

    @classmethod
    def sanitize_arg(cls, arg: str) -> str:
        """Strip dangerous characters to avoid argument injection."""
        if not isinstance(arg, str):
            arg = str(arg)
        if cls.FORBIDDEN_CHARS.search(arg):
            raise ValueError(f"Dangerous metacharacters detected in argument: {arg}")
        return arg.strip()

    @classmethod
    def get_tool_executable(cls, tool_name: str) -> str:
        """Retrieve verified path for tool, or raise error if missing."""
        path = ToolManager.find_tool_path(tool_name)
        if not path:
            raise FileNotFoundError(f"Tool '{tool_name}' is not installed or not in PATH.")
        return path

    # ================= WEB RECONNAISSANCE COMMANDS =================

    @classmethod
    def build_subfinder(cls, domain: str, silent: bool = True, all_sources: bool = False) -> List[str]:
        exe = cls.get_tool_executable("subfinder")
        clean_domain = cls.sanitize_arg(domain)
        cmd = [exe, "-d", clean_domain]
        if silent:
            cmd.append("-silent")
        if all_sources:
            cmd.append("-all")
        return cmd

    @classmethod
    def build_amass(cls, domain: str, active: bool = False) -> List[str]:
        exe = cls.get_tool_executable("amass")
        clean_domain = cls.sanitize_arg(domain)
        cmd = [exe, "enum", "-d", clean_domain]
        if not active:
            cmd.append("-passive")
        return cmd

    @classmethod
    def build_assetfinder(cls, domain: str, subs_only: bool = True) -> List[str]:
        exe = cls.get_tool_executable("assetfinder")
        clean_domain = cls.sanitize_arg(domain)
        cmd = [exe]
        if subs_only:
            cmd.append("--subs-only")
        cmd.append(clean_domain)
        return cmd

    @classmethod
    def build_httpx(cls, target: str, follow_redirects: bool = True, tech_detect: bool = True) -> List[str]:
        exe = cls.get_tool_executable("httpx")
        clean_target = cls.sanitize_arg(target)
        cmd = [exe, "-u", clean_target, "-status-code", "-title"]
        if follow_redirects:
            cmd.append("-follow-redirects")
        if tech_detect:
            cmd.append("-tech-detect")
        cmd.extend(["-silent", "-no-color"])
        return cmd

    @classmethod
    def build_nmap(cls, target: str, profile: str = "default", ports: Optional[str] = None) -> List[str]:
        exe = cls.get_tool_executable("nmap")
        clean_target = cls.sanitize_arg(target)
        cmd = [exe]

        if profile == "ping":
            cmd.append("-sn")
        elif profile == "fast":
            cmd.extend(["-F", "-sV", "--version-light"])
        elif profile == "service":
            cmd.extend(["-sV", "-sC", "--version-intensity", "5"])
        elif profile == "top100":
            cmd.extend(["--top-ports", "100", "-sV"])
        else: # default
            cmd.extend(["-sV", "-T3"])

        if ports:
            clean_ports = cls.sanitize_arg(ports)
            if re.match(r'^[0-9,\-]+$', clean_ports):
                cmd.extend(["-p", clean_ports])

        cmd.extend(["--open", clean_target])
        return cmd

    @classmethod
    def build_nuclei(cls, target: str, severity: Optional[str] = "info,low,medium", tags: Optional[str] = None) -> List[str]:
        exe = cls.get_tool_executable("nuclei")
        clean_target = cls.sanitize_arg(target)
        cmd = [exe, "-u", clean_target, "-silent", "-no-color"]
        if severity:
            clean_sev = cls.sanitize_arg(severity)
            cmd.extend(["-severity", clean_sev])
        if tags:
            clean_tags = cls.sanitize_arg(tags)
            cmd.extend(["-tags", clean_tags])
        return cmd

    @classmethod
    def build_katana(cls, target: str, depth: int = 2) -> List[str]:
        exe = cls.get_tool_executable("katana")
        clean_target = cls.sanitize_arg(target)
        depth_val = max(1, min(int(depth), 5))
        cmd = [exe, "-u", clean_target, "-depth", str(depth_val), "-silent", "-no-color"]
        return cmd

    @classmethod
    def build_gau(cls, domain: str) -> List[str]:
        exe = cls.get_tool_executable("gau")
        clean_domain = cls.sanitize_arg(domain)
        cmd = [exe, clean_domain, "--threads", "2"]
        return cmd

    @classmethod
    def build_whatweb(cls, target: str, aggression: int = 1) -> List[str]:
        exe = cls.get_tool_executable("whatweb")
        clean_target = cls.sanitize_arg(target)
        level = max(1, min(int(aggression), 3))
        cmd = [exe, f"-a{level}", "--color=never", clean_target]
        return cmd

    @classmethod
    def build_dig(cls, domain: str, record_type: str = "ANY") -> List[str]:
        exe = cls.get_tool_executable("dig")
        clean_domain = cls.sanitize_arg(domain)
        clean_type = cls.sanitize_arg(record_type).upper()
        if clean_type not in ["ANY", "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            clean_type = "A"
        cmd = [exe, "+noall", "+answer", clean_domain, clean_type]
        return cmd

    @classmethod
    def build_whois(cls, domain: str) -> List[str]:
        exe = cls.get_tool_executable("whois")
        clean_domain = cls.sanitize_arg(domain)
        return [exe, clean_domain]

    @classmethod
    def build_curl(cls, url: str) -> List[str]:
        exe = cls.get_tool_executable("curl")
        clean_url = cls.sanitize_arg(url)
        return [exe, "-I", "-s", "-S", "-L", "--max-time", "10", clean_url]

    # ================= WI-FI SECURITY COMMANDS =================

    @classmethod
    def build_iw_dev(cls) -> List[str]:
        exe = cls.get_tool_executable("iw")
        return [exe, "dev"]

    @classmethod
    def build_iw_info(cls, interface: str) -> List[str]:
        exe = cls.get_tool_executable("iw")
        clean_iface = cls.sanitize_arg(interface)
        return [exe, "dev", clean_iface, "info"]

    @classmethod
    def build_rfkill(cls) -> List[str]:
        exe = cls.get_tool_executable("rfkill")
        return [exe, "list"]

    @classmethod
    def build_nmcli_wifi(cls) -> List[str]:
        exe = cls.get_tool_executable("nmcli")
        return [exe, "-t", "-f", "SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY", "dev", "wifi", "list"]

    @classmethod
    def build_aircrack_check_cap(cls, cap_file_path: str) -> List[str]:
        exe = cls.get_tool_executable("aircrack-ng")
        clean_path = cls.sanitize_arg(cap_file_path)
        return [exe, "-u", clean_path]

    @classmethod
    def build_tshark_summary(cls, cap_file_path: str) -> List[str]:
        exe = cls.get_tool_executable("tshark")
        clean_path = cls.sanitize_arg(cap_file_path)
        return [exe, "-r", clean_path, "-c", "50", "-T", "fields", "-e", "frame.number", "-e", "wlan.fc.type_subtype", "-e", "wlan.sa", "-e", "wlan.da"]
