"""
RECONQUEST - Wi-Fi Security Testing Service
Implements adapter diagnostics, wireless discovery, capture analysis, and terminal launchers.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional

from core.tool_manager import ToolManager
from core.scope_manager import ScopeManager
from core.command_builder import CommandBuilder
from core.process_manager import ProcessManager
from core.job_manager import JobManager
from core.logging_config import log_audit_event


class WiFiSecurityService:
    """Coordinates wireless diagnostics, visible network discovery, and lab assessments."""

    @classmethod
    def get_adapter_diagnostics(cls) -> Dict[str, Any]:
        """Inspect system wireless interfaces, drivers, physical chipsets, and rfkill status."""
        diag: Dict[str, Any] = {
            "interfaces": [],
            "rfkill_blocks": [],
            "has_wireless": False,
            "has_monitor_support": False,
            "summary": ""
        }

        # 1. Check rfkill
        if ToolManager.is_tool_ready("rfkill"):
            res = ProcessManager.run_sync(["rfkill", "list"])
            if res.success:
                blocks = []
                cur_block = {}
                for line in res.stdout.splitlines():
                    line = line.strip()
                    m = re.match(r'^(\d+):\s+([^:]+):\s+(.+)$', line)
                    if m:
                        if cur_block:
                            blocks.append(cur_block)
                        cur_block = {"id": m.group(1), "type": m.group(2), "device": m.group(3), "soft_blocked": False, "hard_blocked": False}
                    elif "Soft blocked: yes" in line:
                        cur_block["soft_blocked"] = True
                    elif "Hard blocked: yes" in line:
                        cur_block["hard_blocked"] = True
                if cur_block:
                    blocks.append(cur_block)
                diag["rfkill_blocks"] = blocks

        # 2. Check iw dev
        if ToolManager.is_tool_ready("iw"):
            res = ProcessManager.run_sync(["iw", "dev"])
            if res.success:
                interfaces = []
                cur_iface = None
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Interface"):
                        if cur_iface:
                            interfaces.append(cur_iface)
                        name = line.split()[1]
                        cur_iface = {
                            "name": name,
                            "type": "managed",
                            "addr": "Unknown",
                            "channel": "Unknown",
                            "driver": "Unknown",
                            "supports_monitor": False
                        }
                    elif cur_iface and line.startswith("type"):
                        cur_iface["type"] = line.split()[1]
                    elif cur_iface and line.startswith("addr"):
                        cur_iface["addr"] = line.split()[1]
                    elif cur_iface and line.startswith("channel"):
                        cur_iface["channel"] = line

                if cur_iface:
                    interfaces.append(cur_iface)

                # Check monitor mode capabilities via iw phy
                phy_res = ProcessManager.run_sync(["iw", "phy"])
                if phy_res.success and "* monitor" in phy_res.stdout:
                    diag["has_monitor_support"] = True
                    for iface in interfaces:
                        iface["supports_monitor"] = True

                diag["interfaces"] = interfaces
                diag["has_wireless"] = len(interfaces) > 0

        # Also fallback check /sys/class/net
        if not diag["interfaces"]:
            try:
                for iface in os.listdir("/sys/class/net"):
                    wireless_path = os.path.join("/sys/class/net", iface, "wireless")
                    if os.path.isdir(wireless_path):
                        diag["interfaces"].append({
                            "name": iface,
                            "type": "managed",
                            "addr": "N/A",
                            "channel": "N/A",
                            "driver": "Generic Linux Wireless",
                            "supports_monitor": False
                        })
                        diag["has_wireless"] = True
            except Exception:
                pass

        if diag["has_wireless"]:
            diag["summary"] = f"Detected {len(diag['interfaces'])} wireless interface(s)."
        else:
            diag["summary"] = "No physical wireless interfaces detected (common on virtual machines or servers without USB Wi-Fi adapter)."

        return diag

    @classmethod
    def discover_networks(cls, app) -> Dict[str, Any]:
        """Perform scan for visible Wi-Fi access points using nmcli or iw."""
        if not ToolManager.is_tool_ready("nmcli"):
            return {
                "success": False,
                "error": "NetworkManager CLI (nmcli) is not installed."
            }

        cmd = CommandBuilder.build_nmcli_wifi()
        job_id = JobManager.start_scan_job(app, "nmcli", "Local Airspace", cmd, scan_type="wifi_security")
        return {
            "success": True,
            "job_id": job_id,
            "tool_name": "nmcli",
            "target": "Local Airspace",
            "command": " ".join(cmd),
            "message": "Wireless discovery scan launched. Observing beacon frames..."
        }

    @classmethod
    def inspect_capture_file(cls, filepath: str) -> Dict[str, Any]:
        """Inspect and validate an authorized packet capture file (.cap / .pcap)."""
        if not os.path.exists(filepath):
            return {"success": False, "error": f"File does not exist: {filepath}"}

        results: Dict[str, Any] = {
            "filepath": filepath,
            "filesize_bytes": os.path.getsize(filepath),
            "aircrack_inspection": "",
            "tshark_summary": []
        }

        # Aircrack-ng analysis
        if ToolManager.is_tool_ready("aircrack-ng"):
            cmd = CommandBuilder.build_aircrack_check_cap(filepath)
            res = ProcessManager.run_sync(cmd, timeout=15)
            results["aircrack_inspection"] = res.stdout or res.stderr

        # Tshark analysis
        if ToolManager.is_tool_ready("tshark"):
            cmd = CommandBuilder.build_tshark_summary(filepath)
            res = ProcessManager.run_sync(cmd, timeout=15)
            if res.success:
                lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                results["tshark_summary"] = lines[:30]

        return {"success": True, "data": results}

    @classmethod
    def launch_interactive_terminal(cls, tool_name: str, interface: Optional[str] = None) -> Dict[str, Any]:
        """Launch interactive wireless tools (Airgeddon / Wifite) in an authorized local Linux terminal."""
        tool_info = ToolManager.check_tool(tool_name)
        if tool_info.status != "READY":
            return {
                "success": False,
                "error": f"{tool_name} is not installed or ready on this system.",
                "tool_missing": True
            }

        # Find available terminal emulator on Ubuntu
        terminals = ["gnome-terminal", "x-terminal-emulator", "xterm", "konsole", "terminator", "xfce4-terminal"]
        chosen_term = None
        for t in terminals:
            if shutil.which(t):
                chosen_term = t
                break

        if not chosen_term:
            return {
                "success": False,
                "error": "No GUI terminal emulator found on this system (e.g. gnome-terminal, xterm). Please run the command in your terminal directly.",
                "terminal_command": f"sudo {tool_info.path}"
            }

        # Build terminal launch command
        # Notice: Ubuntu will prompt for sudo in the terminal window itself!
        tool_cmd = tool_info.path
        if interface and tool_name == "wifite":
            tool_cmd = f"{tool_cmd} -i {interface}"

        if chosen_term == "gnome-terminal":
            launch_args = ["gnome-terminal", "--", "sudo", tool_info.path]
        elif chosen_term == "xterm":
            launch_args = ["xterm", "-geometry", "100x30", "-e", f"sudo {tool_cmd}"]
        else:
            launch_args = [chosen_term, "-e", f"sudo {tool_cmd}"]

        try:
            subprocess.Popen(launch_args)
            log_audit_event(
                action="TERMINAL_TOOL_LAUNCH",
                tool=tool_name,
                status="launched",
                details={"terminal": chosen_term, "command": " ".join(launch_args)}
            )
            return {
                "success": True,
                "message": f"Successfully launched {tool_name} in local {chosen_term} window.",
                "terminal": chosen_term,
                "command": f"sudo {tool_cmd}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to open terminal window: {str(e)}",
                "fallback_command": f"sudo {tool_cmd}"
            }
