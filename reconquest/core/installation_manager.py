"""
RECONQUEST - Installation Manager
Manages guidance, prerequisite checks, and safe installation verification
for cybersecurity tools on Ubuntu Linux.
"""

import shutil
import subprocess
from typing import Dict, Any, List
from .tool_manager import ToolManager, ToolInfo


class InstallationManager:
    """Provides validated installation instructions and verification mechanisms."""

    @classmethod
    def get_environment_diagnostics(cls) -> Dict[str, Any]:
        """Diagnose build tools, package managers, and runtime environments."""
        return {
            "apt": {
                "available": shutil.which("apt") is not None,
                "path": shutil.which("apt")
            },
            "go": {
                "available": shutil.which("go") is not None,
                "path": shutil.which("go"),
                "version": cls._run_quick_cmd(["go", "version"]) if shutil.which("go") else None
            },
            "git": {
                "available": shutil.which("git") is not None,
                "path": shutil.which("git"),
                "version": cls._run_quick_cmd(["git", "--version"]) if shutil.which("git") else None
            },
            "pipx": {
                "available": shutil.which("pipx") is not None,
                "path": shutil.which("pipx")
            },
            "python3": {
                "available": shutil.which("python3") is not None,
                "path": shutil.which("python3"),
                "version": cls._run_quick_cmd(["python3", "--version"])
            }
        }

    @staticmethod
    def _run_quick_cmd(cmd_list: List[str]) -> str:
        try:
            res = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            return (res.stdout or res.stderr).splitlines()[0].strip()
        except Exception:
            return "Unknown"

    @classmethod
    def get_instructions(cls, tool_name: str) -> Dict[str, Any]:
        """Retrieve complete installation dossier for a specific tool."""
        tool_info = ToolManager.check_tool(tool_name)
        env = cls.get_environment_diagnostics()

        prereqs = []
        # Check if recommended method requires Go or Git or APT
        methods = tool_info.installation_methods
        rec_method = methods[0] if methods else {"method": "apt", "command": "sudo apt install " + tool_name}

        if rec_method.get("method") == "go" and not env["go"]["available"]:
            prereqs.append("Golang is required. Install with: sudo apt install -y golang-go")
        if rec_method.get("method") == "git" and not env["git"]["available"]:
            prereqs.append("Git is required. Install with: sudo apt install -y git")
        if rec_method.get("method") == "pipx" and not env["pipx"]["available"]:
            prereqs.append("pipx is recommended for Python CLI tools: sudo apt install -y pipx && pipx ensurepath")

        return {
            "tool_name": tool_name,
            "display_name": tool_info.display_name,
            "category": tool_info.category,
            "purpose": tool_info.purpose,
            "status": tool_info.status,
            "current_version": tool_info.version,
            "current_path": tool_info.path,
            "requires_root": tool_info.requires_root,
            "recommended_command": rec_method.get("command"),
            "recommended_method": rec_method.get("method"),
            "all_methods": methods,
            "verification_command": tool_info.verification_command,
            "prerequisites": prereqs,
            "official_url": tool_info.official_url,
            "notes": tool_info.notes
        }

    @classmethod
    def verify_tool_after_install(cls, tool_name: str) -> Dict[str, Any]:
        """Check status after the operator reports having installed the tool."""
        info = ToolManager.check_tool(tool_name)
        return {
            "tool_name": tool_name,
            "is_ready": info.status == "READY",
            "status": info.status,
            "version": info.version,
            "path": info.path,
            "error_message": info.error_message
        }
