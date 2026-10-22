"""
RECONQUEST - Web Reconnaissance Operations
Implements structured workflows for domain intelligence, subdomain discovery,
HTTP service inspection, port scanning, and vulnerability assessments.
"""

from typing import Dict, Any, List, Optional
from core.tool_manager import ToolManager
from core.scope_manager import ScopeManager
from core.command_builder import CommandBuilder
from core.job_manager import JobManager
from core.process_manager import ProcessManager


class WebReconService:
    """Coordinates Module A operations with scope verification and safe job execution."""

    @classmethod
    def run_subdomain_discovery(cls, app, domain: str, tool_choice: str = "subfinder") -> Dict[str, Any]:
        """Discover subdomains for an authorized domain."""
        # 1. Scope Verification
        in_scope, reason = ScopeManager.is_in_scope(domain)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        # 2. Tool Readiness Check
        if not ToolManager.is_tool_ready(tool_choice):
            return {
                "success": False,
                "error": f"Tool '{tool_choice}' is not ready. Visit Tool Manager to install it.",
                "tool_missing": True,
                "tool_name": tool_choice
            }

        # 3. Build Command
        if tool_choice == "amass":
            cmd = CommandBuilder.build_amass(domain, active=False)
        elif tool_choice == "assetfinder":
            cmd = CommandBuilder.build_assetfinder(domain, subs_only=True)
        else: # subfinder default
            cmd = CommandBuilder.build_subfinder(domain, silent=True)

        # 4. Launch Job
        job_id = JobManager.start_scan_job(app, tool_choice, domain, cmd, scan_type="web_recon")
        return {
            "success": True,
            "job_id": job_id,
            "tool_name": tool_choice,
            "target": domain,
            "command": " ".join(cmd),
            "message": f"Subdomain discovery launched on {domain} using {tool_choice}."
        }

    @classmethod
    def run_http_probing(cls, app, target: str) -> Dict[str, Any]:
        """Run httpx against target to identify live web services and banners."""
        in_scope, reason = ScopeManager.is_in_scope(target)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        if not ToolManager.is_tool_ready("httpx"):
            return {
                "success": False,
                "error": "httpx is not installed. Visit Tool Manager to install it.",
                "tool_missing": True,
                "tool_name": "httpx"
            }

        cmd = CommandBuilder.build_httpx(target, follow_redirects=True, tech_detect=True)
        job_id = JobManager.start_scan_job(app, "httpx", target, cmd, scan_type="web_recon")
        return {
            "success": True,
            "job_id": job_id,
            "tool_name": "httpx",
            "target": target,
            "command": " ".join(cmd),
            "message": f"httpx service probe launched for {target}."
        }

    @classmethod
    def run_port_scan(cls, app, target: str, profile: str = "default", ports: Optional[str] = None) -> Dict[str, Any]:
        """Execute authorized port discovery via Nmap."""
        in_scope, reason = ScopeManager.is_in_scope(target)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        if not ToolManager.is_tool_ready("nmap"):
            return {
                "success": False,
                "error": "Nmap is not installed. Install with: sudo apt install nmap",
                "tool_missing": True,
                "tool_name": "nmap"
            }

        cmd = CommandBuilder.build_nmap(target, profile=profile, ports=ports)
        job_id = JobManager.start_scan_job(app, "nmap", target, cmd, scan_type="web_recon")
        return {
            "success": True,
            "job_id": job_id,
            "tool_name": "nmap",
            "target": target,
            "command": " ".join(cmd),
            "message": f"Nmap port scan ({profile}) launched on {target}."
        }

    @classmethod
    def run_vulnerability_scan(cls, app, target: str, severity: str = "info,low,medium") -> Dict[str, Any]:
        """Execute template-based vulnerability assessment via Nuclei."""
        in_scope, reason = ScopeManager.is_in_scope(target)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        if not ToolManager.is_tool_ready("nuclei"):
            return {
                "success": False,
                "error": "Nuclei is not installed. Visit Tool Manager to install it.",
                "tool_missing": True,
                "tool_name": "nuclei"
            }

        cmd = CommandBuilder.build_nuclei(target, severity=severity)
        job_id = JobManager.start_scan_job(app, "nuclei", target, cmd, scan_type="web_recon")
        return {
            "success": True,
            "job_id": job_id,
            "tool_name": "nuclei",
            "target": target,
            "command": " ".join(cmd),
            "message": f"Nuclei vulnerability scan launched on {target} ({severity})."
        }

    @classmethod
    def run_dns_query(cls, domain: str, record_type: str = "ANY") -> Dict[str, Any]:
        """Perform quick synchronous DNS lookup using dig."""
        in_scope, reason = ScopeManager.is_in_scope(domain)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        if not ToolManager.is_tool_ready("dig"):
            return {"success": False, "error": "dig utility is not installed (dnsutils package)."}

        cmd = CommandBuilder.build_dig(domain, record_type)
        res = ProcessManager.run_sync(cmd, timeout=10)
        return {
            "success": res.success,
            "domain": domain,
            "record_type": record_type,
            "output": res.stdout,
            "error": res.stderr
        }

    @classmethod
    def run_whois_query(cls, domain: str) -> Dict[str, Any]:
        """Perform quick WHOIS query."""
        in_scope, reason = ScopeManager.is_in_scope(domain)
        if not in_scope:
            return {"success": False, "error": f"Scope violation: {reason}"}

        if not ToolManager.is_tool_ready("whois"):
            return {
                "success": False,
                "error": "whois is not installed on system.",
                "tool_missing": True,
                "tool_name": "whois"
            }

        cmd = CommandBuilder.build_whois(domain)
        res = ProcessManager.run_sync(cmd, timeout=10)
        return {
            "success": res.success,
            "domain": domain,
            "output": res.stdout,
            "error": res.stderr
        }
