"""
RECONQUEST - Job Manager & Scan Orchestrator
Coordinates background jobs, persists scan results to the database, parses output,
and triggers gamification rewards upon mission or scan completion.
"""

import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from database.db import db
from database.models import ScanResult, User, Achievement, UserAchievement
from .process_manager import ProcessManager, ManagedProcess
from .logging_config import get_audit_logger


class JobManager:
    """Orchestrates scan jobs, database persistence, output parsing, and reward triggers."""

    _poller_started = False
    _lock = threading.Lock()

    @classmethod
    def start_scan_job(cls, app, tool_name: str, target: str, command: list, scan_type: str = "web_recon") -> str:
        """Create a database ScanResult record and launch the managed subprocess."""
        with app.app_context():
            scan_rec = ScanResult(
                scan_type=scan_type,
                tool_name=tool_name,
                target=target,
                command_executed=" ".join(command),
                status="running",
                started_at=datetime.now(timezone.utc)
            )
            db.session.add(scan_rec)
            db.session.commit()
            scan_id = scan_rec.id

        job_id = ProcessManager.start_job(
            command=command,
            tool_name=tool_name,
            target=target,
            timeout=300
        )

        # Start asynchronous persistence listener
        threading.Thread(
            target=cls._monitor_and_persist,
            args=(app, job_id, scan_id, tool_name, target),
            daemon=True
        ).start()

        return job_id

    @classmethod
    def _monitor_and_persist(cls, app, job_id: str, scan_id: int, tool_name: str, target: str):
        """Wait until job completes, parse its output, update database, and award XP."""
        job = ProcessManager.get_job(job_id)
        if not job:
            return

        while job.status in ["pending", "running"]:
            time.sleep(1)

        job_data = job.get_output()
        raw_out = job_data["stdout"]
        err_out = job_data["stderr"]

        # Parse output into structured JSON based on tool
        parsed_data = cls.parse_tool_output(tool_name, raw_out, err_out)

        with app.app_context():
            scan_rec = ScanResult.query.get(scan_id)
            if scan_rec:
                scan_rec.status = job.status
                scan_rec.raw_output = raw_out
                scan_rec.error_output = err_out
                scan_rec.set_parsed_results(parsed_data)
                scan_rec.duration_seconds = job.duration_seconds
                scan_rec.completed_at = job.completed_at or datetime.now(timezone.utc)
                db.session.commit()

                # Trigger XP / Gamification check if completed successfully
                if job.status == "completed":
                    cls._award_gamification(tool_name, scan_rec)

    @classmethod
    def parse_tool_output(cls, tool_name: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Convert raw terminal output from real cybersecurity tools into clean structured data."""
        parsed: Dict[str, Any] = {"items": [], "count": 0, "summary": ""}

        if not stdout:
            parsed["summary"] = "No standard output returned."
            return parsed

        lines = [line.strip() for line in stdout.splitlines() if line.strip()]

        if tool_name in ["subfinder", "assetfinder", "amass"]:
            # Lines are discovered subdomains / hostnames
            subdomains = []
            for l in lines:
                if "." in l and " " not in l and not l.startswith("["):
                    subdomains.append(l)
            parsed["items"] = sorted(list(set(subdomains)))
            parsed["count"] = len(parsed["items"])
            parsed["summary"] = f"Discovered {len(parsed['items'])} unique hostnames."

        elif tool_name == "httpx":
            # httpx output: URL [STATUS] [TITLE] [TECH]
            items = []
            for l in lines:
                match = re.search(r'^(https?://[^\s]+)(?:\s+\[(\d+)\])?(?:\s+\[(.*?)\])?', l)
                if match:
                    url, status, title = match.groups()
                    items.append({
                        "url": url,
                        "status_code": status or "200",
                        "title": title or "N/A"
                    })
                else:
                    items.append({"url": l, "status_code": "unknown", "title": ""})
            parsed["items"] = items
            parsed["count"] = len(items)
            parsed["summary"] = f"Identified {len(items)} live HTTP/HTTPS services."

        elif tool_name == "nmap":
            # Extract open ports and service details
            open_ports = []
            for l in lines:
                if "/tcp" in l or "/udp" in l:
                    parts = l.split()
                    if len(parts) >= 3 and parts[1] == "open":
                        open_ports.append({
                            "port": parts[0],
                            "state": parts[1],
                            "service": parts[2],
                            "version": " ".join(parts[3:]) if len(parts) > 3 else "unknown"
                        })
            parsed["items"] = open_ports
            parsed["count"] = len(open_ports)
            parsed["summary"] = f"Found {len(open_ports)} open listening ports."

        elif tool_name == "nuclei":
            # Nuclei output: [template-id] [protocol] [severity] url
            vulns = []
            for l in lines:
                match = re.search(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)', l)
                if match:
                    tid, proto, sev, target_url = match.groups()
                    vulns.append({
                        "template_id": tid,
                        "protocol": proto,
                        "severity": sev.upper(),
                        "url": target_url
                    })
            parsed["items"] = vulns
            parsed["count"] = len(vulns)
            parsed["summary"] = f"Generated {len(vulns)} template detections."

        elif tool_name == "dig":
            answers = []
            for l in lines:
                if not l.startswith(";") and len(l.split()) >= 4:
                    answers.append(l)
            parsed["items"] = answers
            parsed["count"] = len(answers)
            parsed["summary"] = f"Retrieved {len(answers)} DNS resource records."

        elif tool_name == "nmcli":
            # nmcli -t -f SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list
            networks = []
            for l in lines:
                # Match SSID, BSSID (with colons/escapes), channel, freq, rate, signal, security
                bssid_match = re.search(r'([0-9A-Fa-f]{2}(?:\\?:[0-9A-Fa-f]{2}){5})', l)
                if bssid_match:
                    raw_bssid = bssid_match.group(1).replace(r'\:', ':')
                    prefix = l[:bssid_match.start()].rstrip(':')
                    suffix = l[bssid_match.end():].lstrip(':')
                    suffix_parts = suffix.split(':')
                    
                    networks.append({
                        "ssid": prefix or "<Hidden>",
                        "bssid": raw_bssid,
                        "channel": suffix_parts[0] if len(suffix_parts) > 0 else "N/A",
                        "freq": suffix_parts[1] if len(suffix_parts) > 1 else "N/A",
                        "signal": (suffix_parts[3] + "%") if len(suffix_parts) > 3 else "N/A",
                        "security": suffix_parts[4] if len(suffix_parts) > 4 else "Open"
                    })
            parsed["items"] = networks
            parsed["count"] = len(networks)
            parsed["summary"] = f"Discovered {len(networks)} visible wireless access points."

        else:
            parsed["items"] = lines
            parsed["count"] = len(lines)
            parsed["summary"] = f"Completed command with {len(lines)} lines of output."

        return parsed

    @classmethod
    def _award_gamification(cls, tool_name: str, scan_rec: ScanResult):
        """Award operator XP points and unlock milestone achievements."""
        user = User.query.first()
        if not user:
            return

        # Award base XP for completing a real scan
        user.add_xp(25)

        # Check and unlock achievements
        achievements_to_check = {
            "subfinder": "SUBDOMAIN_MASTER",
            "assetfinder": "SUBDOMAIN_MASTER",
            "nmap": "PORT_SCANNER",
            "httpx": "HTTP_PROBER",
            "nuclei": "VULN_HUNTER",
            "nmcli": "WIFI_OBSERVER",
            "aircrack-ng": "CAPTURE_ANALYST"
        }

        # First blood
        cls._grant_achievement(user, "FIRST_BLOOD")

        if tool_name in achievements_to_check:
            cls._grant_achievement(user, achievements_to_check[tool_name])

        db.session.commit()

    @classmethod
    def _grant_achievement(cls, user: User, ach_code: str):
        ach = Achievement.query.filter_by(code=ach_code).first()
        if not ach:
            return

        existing = UserAchievement.query.filter_by(user_id=user.id, achievement_id=ach.id).first()
        if not existing:
            ua = UserAchievement(user_id=user.id, achievement_id=ach.id)
            user.add_xp(ach.xp_reward)
            db.session.add(ua)
            get_audit_logger().info(f"ACHIEVEMENT UNLOCKED: {ach.name} (+{ach.xp_reward} XP)")
