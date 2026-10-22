"""
RECONQUEST - JSON Report Generator
"""

import json
from typing import Dict, Any
from database.models import ScanResult


class JsonReportGenerator:
    """Generates structured JSON export files for scan results and audits."""

    @classmethod
    def generate_scan_json(cls, scan_result: ScanResult) -> str:
        data = {
            "reconquest_version": "2.0",
            "report_type": "security_reconnaissance_assessment",
            "scan_id": scan_result.id,
            "scan_type": scan_result.scan_type,
            "tool_name": scan_result.tool_name,
            "target": scan_result.target,
            "command": scan_result.command_executed,
            "status": scan_result.status,
            "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
            "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "duration_seconds": scan_result.duration_seconds,
            "findings": scan_result.get_parsed_results(),
            "raw_output": scan_result.raw_output
        }
        return json.dumps(data, indent=2)
