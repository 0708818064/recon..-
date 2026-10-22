"""
RECONQUEST - HTML Report Generator
Generates stand-alone, styled security assessment reports for stakeholders.
"""

from datetime import datetime, timezone
from database.models import ScanResult


class HtmlReportGenerator:
    """Generates complete standalone HTML assessment summaries."""

    @classmethod
    def generate_scan_html(cls, scan_result: ScanResult) -> str:
        parsed = scan_result.get_parsed_results()
        items = parsed.get("items", [])
        summary = parsed.get("summary", "Assessment completed.")

        rows_html = ""
        if scan_result.tool_name in ["subfinder", "assetfinder", "amass"]:
            header_html = "<tr><th>#</th><th>Discovered Hostname</th><th>Domain</th></tr>"
            for i, host in enumerate(items, 1):
                rows_html += f"<tr><td>{i}</td><td><code>{host}</code></td><td>{scan_result.target}</td></tr>"

        elif scan_result.tool_name == "httpx":
            header_html = "<tr><th>#</th><th>Target URL</th><th>Status Code</th><th>Page Title</th></tr>"
            for i, it in enumerate(items, 1):
                if isinstance(it, dict):
                    status_class = "badge-success" if it.get("status_code", "").startswith("2") else "badge-warning"
                    rows_html += f"<tr><td>{i}</td><td><a href='{it.get('url')}' target='_blank'>{it.get('url')}</a></td><td><span class='badge {status_class}'>{it.get('status_code')}</span></td><td>{it.get('title')}</td></tr>"

        elif scan_result.tool_name == "nmap":
            header_html = "<tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>"
            for it in items:
                if isinstance(it, dict):
                    rows_html += f"<tr><td><strong>{it.get('port')}</strong></td><td><span class='badge badge-open'>{it.get('state')}</span></td><td>{it.get('service')}</td><td>{it.get('version')}</td></tr>"

        elif scan_result.tool_name == "nuclei":
            header_html = "<tr><th>Template ID</th><th>Severity</th><th>Protocol</th><th>Asset URL</th></tr>"
            for it in items:
                if isinstance(it, dict):
                    sev = it.get('severity', 'INFO')
                    sev_class = f"badge-{sev.lower()}"
                    rows_html += f"<tr><td><code>{it.get('template_id')}</code></td><td><span class='badge {sev_class}'>{sev}</span></td><td>{it.get('protocol')}</td><td>{it.get('url')}</td></tr>"

        elif scan_result.tool_name == "nmcli":
            header_html = "<tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Security Protocol</th></tr>"
            for it in items:
                if isinstance(it, dict):
                    rows_html += f"<tr><td><strong>{it.get('ssid')}</strong></td><td><code>{it.get('bssid')}</code></td><td>{it.get('channel')}</td><td>{it.get('signal')}</td><td>{it.get('security')}</td></tr>"

        else:
            header_html = "<tr><th>Line</th><th>Terminal Output</th></tr>"
            for i, line in enumerate(items, 1):
                rows_html += f"<tr><td>{i}</td><td><pre>{line}</pre></td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RECONQUEST Assessment Report - {scan_result.target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #030712;
            color: #f8fafc;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #0f172a;
            border-radius: 10px;
            border: 1px solid #1e293b;
            padding: 35px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.6);
        }}
        h1 {{ color: #10b981; margin-top: 0; display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid #1e293b; padding-bottom: 12px; }}
        .header-meta {{ font-size: 13px; color: #94a3b8; margin-bottom: 20px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .meta-card {{ background: #0a0f1d; border: 1px solid #1e293b; padding: 15px; border-radius: 6px; }}
        .meta-label {{ font-size: 11px; color: #10b981; font-weight: bold; text-transform: uppercase; }}
        .meta-value {{ font-size: 18px; font-weight: bold; color: #ffffff; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ background: #0a0f1d; color: #10b981; text-transform: uppercase; font-size: 12px; font-weight: bold; }}
        tr:hover {{ background: rgba(16, 185, 129, 0.08); }}
        code {{ background: #030712; padding: 3px 6px; border-radius: 4px; font-family: monospace; color: #34d399; font-weight: bold; border: 1px solid #1e293b; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #10b981; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-open {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #10b981; }}
        .badge-info {{ background: rgba(45, 212, 191, 0.15); color: #2dd4bf; border: 1px solid #0d9488; }}
        .badge-low {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; }}
        .badge-high {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.25); color: #fca5a5; }}
        .raw-box {{ background: #030712; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #34d399; border: 1px solid #1e293b; overflow-x: auto; max-height: 400px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>
            <span>RECONQUEST SECURITY REPORT</span>
            <span style="font-size: 14px; color: #6ee7b7; font-weight: normal;">Target: {scan_result.target}</span>
        </h1>
        <div class="header-meta">
            Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Tool: {scan_result.tool_name.upper()} | Type: {scan_result.scan_type}
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Status</div>
                <div class="meta-value">{scan_result.status.upper()}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Duration</div>
                <div class="meta-value">{round(scan_result.duration_seconds, 2)}s</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Findings Count</div>
                <div class="meta-value">{len(items)}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Execution Mode</div>
                <div class="meta-value">Subprocess Isolated</div>
            </div>
        </div>

        <h3>Execution Summary</h3>
        <p style="color: #9ca3af;">{summary}</p>

        <h3>Structured Findings</h3>
        <table>
            <thead>{header_html}</thead>
            <tbody>{rows_html if rows_html else "<tr><td colspan='4'>No findings detected.</td></tr>"}</tbody>
        </table>

        <h3>Command Executed</h3>
        <code>{scan_result.command_executed}</code>

        <h3>Raw Terminal Stream</h3>
        <pre class="raw-box">{scan_result.raw_output if scan_result.raw_output else "No terminal stream captured."}</pre>
    </div>
</body>
</html>"""
        return html
