"""
RECONQUEST - CSV Report Generator
Exports tabular results for easy spreadsheet inspection.
"""

import io
import csv
from database.models import ScanResult


class CsvReportGenerator:
    """Generates CSV text for discovered items, open ports, services, or subdomains."""

    @classmethod
    def generate_scan_csv(cls, scan_result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        parsed = scan_result.get_parsed_results()
        items = parsed.get("items", [])

        if scan_result.tool_name in ["subfinder", "assetfinder", "amass"]:
            writer.writerow(["Index", "Discovered Hostname", "Target Domain", "Tool"])
            for idx, host in enumerate(items, 1):
                writer.writerow([idx, host, scan_result.target, scan_result.tool_name])

        elif scan_result.tool_name == "httpx":
            writer.writerow(["Index", "URL", "Status Code", "Title"])
            for idx, item in enumerate(items, 1):
                if isinstance(item, dict):
                    writer.writerow([idx, item.get("url"), item.get("status_code"), item.get("title")])
                else:
                    writer.writerow([idx, str(item), "", ""])

        elif scan_result.tool_name == "nmap":
            writer.writerow(["Port", "State", "Service", "Version", "Target Host"])
            for item in items:
                if isinstance(item, dict):
                    writer.writerow([item.get("port"), item.get("state"), item.get("service"), item.get("version"), scan_result.target])

        elif scan_result.tool_name == "nuclei":
            writer.writerow(["Template ID", "Severity", "Protocol", "Affected URL"])
            for item in items:
                if isinstance(item, dict):
                    writer.writerow([item.get("template_id"), item.get("severity"), item.get("protocol"), item.get("url")])

        elif scan_result.tool_name == "nmcli":
            writer.writerow(["SSID", "BSSID", "Channel", "Frequency", "Signal", "Security"])
            for item in items:
                if isinstance(item, dict):
                    writer.writerow([item.get("ssid"), item.get("bssid"), item.get("channel"), item.get("freq"), item.get("signal"), item.get("security")])

        else:
            writer.writerow(["Line Number", "Output Content"])
            for idx, line in enumerate(items, 1):
                writer.writerow([idx, str(line)])

        return output.getvalue()
