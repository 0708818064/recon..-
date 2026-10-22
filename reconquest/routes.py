"""
RECONQUEST - Route Controller & REST API
Blueprint handling all UI pages and asynchronous reconnaissance APIs.
"""

from flask import Blueprint, render_template, request, jsonify, current_app, Response
from database.db import db
from database.models import User, Target, ScanResult, Mission, Achievement, UserAchievement
from core.tool_manager import ToolManager
from core.installation_manager import InstallationManager
from core.scope_manager import ScopeManager
from core.command_builder import CommandBuilder
from core.process_manager import ProcessManager
from core.job_manager import JobManager
from modules.web_recon.service import WebReconService
from modules.wifi_security.service import WiFiSecurityService
from reports.html_report import HtmlReportGenerator
from reports.json_report import JsonReportGenerator
from reports.csv_report import CsvReportGenerator

bp = Blueprint('routes', __name__)


def get_current_user():
    return User.query.first()


# =========================================================================
# WEB UI VIEW ROUTES
# =========================================================================

@bp.route('/')
@bp.route('/dashboard')
def dashboard():
    user = get_current_user()
    return render_template('dashboard.html', active_page='dashboard', user=user)


@bp.route('/web_recon')
def web_recon():
    user = get_current_user()
    return render_template('web_recon.html', active_page='web_recon', user=user)


@bp.route('/wifi_security')
def wifi_security():
    user = get_current_user()
    return render_template('wifi_security.html', active_page='wifi_security', user=user)


@bp.route('/tool_manager')
def tool_manager():
    user = get_current_user()
    tools = ToolManager.check_all_tools()
    return render_template('tool_manager.html', active_page='tool_manager', user=user, tools=tools)


@bp.route('/scope_manager')
def scope_manager():
    user = get_current_user()
    targets = ScopeManager.get_all_targets()
    return render_template('scope_manager.html', active_page='scope_manager', user=user, targets=targets)


@bp.route('/scan_history')
def scan_history():
    user = get_current_user()
    scans = ScanResult.query.order_by(ScanResult.started_at.desc()).all()
    return render_template('scan_history.html', active_page='scan_history', user=user, scans=scans)


@bp.route('/results')
def results():
    user = get_current_user()
    scans = ScanResult.query.order_by(ScanResult.started_at.desc()).all()
    return render_template('results.html', active_page='results', user=user, scans=scans)


@bp.route('/learning')
def learning():
    user = get_current_user()
    missions = Mission.query.all()
    return render_template('learning.html', active_page='learning', user=user, missions=missions)


@bp.route('/achievements')
def achievements():
    user = get_current_user()
    achievements_list = Achievement.query.all()
    unlocked_ids = [ua.achievement_id for ua in user.achievements] if user else []
    return render_template('achievements.html', active_page='achievements', user=user, achievements=achievements_list, unlocked_ids=unlocked_ids)


@bp.route('/diagnostics')
def diagnostics():
    user = get_current_user()
    env = InstallationManager.get_environment_diagnostics()
    return render_template('diagnostics.html', active_page='diagnostics', user=user, env=env)


@bp.route('/settings')
def settings():
    user = get_current_user()
    return render_template('settings.html', active_page='settings', user=user)


@bp.route('/reports/<int:scan_id>/export')
def export_scan_report(scan_id):
    fmt = request.args.get('format', 'html').lower()
    scan = ScanResult.query.get_or_404(scan_id)

    if fmt == 'json':
        return Response(
            JsonReportGenerator.generate_scan_json(scan),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename=reconquest_scan_{scan.id}.json'}
        )
    elif fmt == 'csv':
        return Response(
            CsvReportGenerator.generate_scan_csv(scan),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename=reconquest_scan_{scan.id}.csv'}
        )
    else: # HTML
        return HtmlReportGenerator.generate_scan_html(scan)


# =========================================================================
# ASYNCHRONOUS REST API ENDPOINTS
# =========================================================================

@bp.route('/api/tools/all')
def api_all_tools():
    tools = ToolManager.check_all_tools()
    return jsonify({k: v.to_dict() for k, v in tools.items()})


@bp.route('/api/tools/status/<tool_name>')
def api_tool_status(tool_name):
    info = ToolManager.check_tool(tool_name)
    return jsonify({'success': True, 'tool': info.to_dict()})


@bp.route('/api/tools/instructions/<tool_name>')
def api_tool_instructions(tool_name):
    inst = InstallationManager.get_instructions(tool_name)
    return jsonify({'success': True, 'data': inst})


@bp.route('/api/tools/verify/<tool_name>', methods=['POST'])
def api_tool_verify(tool_name):
    res = InstallationManager.verify_tool_after_install(tool_name)
    return jsonify({'success': True, 'data': res})


@bp.route('/api/scope/check', methods=['POST'])
def api_scope_check():
    data = request.get_json() or {}
    target = data.get('target', '')
    in_scope, reason = ScopeManager.is_in_scope(target)
    return jsonify({'in_scope': in_scope, 'message': reason})


@bp.route('/api/scope/add', methods=['POST'])
def api_scope_add():
    data = request.get_json() or {}
    target_type = data.get('target_type', 'domain')
    value = data.get('value', '')
    notes = data.get('notes', '')
    ok, msg, _ = ScopeManager.add_target(target_type, value, notes)
    return jsonify({'success': ok, 'message': msg if ok else None, 'error': msg if not ok else None})


@bp.route('/api/scope/remove/<int:target_id>', methods=['POST'])
def api_scope_remove(target_id):
    ok = ScopeManager.remove_target(target_id)
    return jsonify({'success': ok})


@bp.route('/api/scan/preview', methods=['POST'])
def api_scan_preview():
    data = request.get_json() or {}
    target = data.get('target', '')
    tool = data.get('tool', 'subfinder')
    sub = data.get('sub', 'subdomain')

    try:
        if tool == 'subfinder':
            cmd = CommandBuilder.build_subfinder(target)
            is_passive = True
        elif tool == 'amass':
            cmd = CommandBuilder.build_amass(target, active=False)
            is_passive = True
        elif tool == 'assetfinder':
            cmd = CommandBuilder.build_assetfinder(target)
            is_passive = True
        elif tool == 'httpx':
            cmd = CommandBuilder.build_httpx(target)
            is_passive = False
        elif tool == 'nmap':
            cmd = CommandBuilder.build_nmap(target)
            is_passive = False
        elif tool == 'nuclei':
            cmd = CommandBuilder.build_nuclei(target)
            is_passive = False
        elif tool == 'katana':
            cmd = CommandBuilder.build_katana(target)
            is_passive = False
        elif tool == 'dig':
            cmd = CommandBuilder.build_dig(target)
            is_passive = True
        else:
            return jsonify({'success': False, 'error': f'Unsupported preview for {tool}'})

        return jsonify({'success': True, 'command': ' '.join(cmd), 'is_passive': is_passive})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@bp.route('/api/scan/launch', methods=['POST'])
def api_scan_launch():
    data = request.get_json() or {}
    target = data.get('target', '')
    tool = data.get('tool', 'subfinder')
    sub = data.get('sub', 'subdomain')
    params = data.get('params', {})

    app = current_app._get_current_object()

    if sub == 'subdomain':
        res = WebReconService.run_subdomain_discovery(app, target, tool_choice=tool)
    elif sub == 'httpx':
        res = WebReconService.run_http_probing(app, target)
    elif sub == 'nmap':
        res = WebReconService.run_port_scan(app, target, profile=params.get('profile', 'default'), ports=params.get('ports'))
    elif sub == 'nuclei':
        res = WebReconService.run_vulnerability_scan(app, target, severity=params.get('severity', 'info,low,medium'))
    elif sub == 'dns':
        res = WebReconService.run_dns_query(target, record_type=params.get('record_type', 'ANY'))
        if res.get('success'):
            # Also record in ScanResult
            scan_rec = ScanResult(
                scan_type="web_recon",
                tool_name="dig",
                target=target,
                command_executed=f"dig +noall +answer {target} {params.get('record_type', 'ANY')}",
                status="completed",
                raw_output=res.get('output', ''),
                error_output=res.get('error', '')
            )
            scan_rec.set_parsed_results(JobManager.parse_tool_output("dig", res.get('output', ''), ''))
            db.session.add(scan_rec)
            db.session.commit()
            return jsonify({'success': True, 'message': f'DNS query completed for {target}.', 'job_id': None, 'output': res.get('output')})
    else:
        return jsonify({'success': False, 'error': f'Unknown operation: {sub}'})

    return jsonify(res)


@bp.route('/api/scan/status/<job_id>')
def api_scan_status(job_id):
    job = ProcessManager.get_job(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'})
    return jsonify({'success': True, 'data': job.get_output()})


@bp.route('/api/scan/cancel/<job_id>', methods=['POST'])
def api_scan_cancel(job_id):
    ok = ProcessManager.cancel_job(job_id)
    return jsonify({'success': ok})


@bp.route('/api/scan/raw/<int:scan_id>')
def api_scan_raw(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify({
        'success': True,
        'scan_id': scan.id,
        'tool_name': scan.tool_name,
        'raw_output': scan.raw_output,
        'error_output': scan.error_output
    })


@bp.route('/api/wifi/diagnostics')
def api_wifi_diagnostics():
    data = WiFiSecurityService.get_adapter_diagnostics()
    return jsonify({'success': True, 'data': data})


@bp.route('/api/wifi/discover', methods=['POST'])
def api_wifi_discover():
    app = current_app._get_current_object()
    res = WiFiSecurityService.discover_networks(app)
    return jsonify(res)


@bp.route('/api/wifi/launch_terminal', methods=['POST'])
def api_wifi_launch_terminal():
    data = request.get_json() or {}
    tool = data.get('tool', 'airgeddon')
    res = WiFiSecurityService.launch_interactive_terminal(tool)
    return jsonify(res)


@bp.route('/api/wifi/inspect_capture', methods=['POST'])
def api_wifi_inspect_capture():
    data = request.get_json() or {}
    path = data.get('filepath', '')
    res = WiFiSecurityService.inspect_capture_file(path)
    return jsonify(res)


@bp.route('/api/user/stats')
def api_user_stats():
    user = get_current_user()
    if not user:
        return jsonify({'success': False})
    return jsonify({
        'success': True,
        'user': {
            'username': user.username,
            'xp_points': user.xp_points,
            'level': user.level
        }
    })


@bp.route('/api/user/update_callsign', methods=['POST'])
def api_user_update_callsign():
    data = request.get_json() or {}
    new_name = data.get('username', '').strip()
    if not new_name:
        return jsonify({'success': False, 'error': 'Name cannot be empty'})
    user = get_current_user()
    if user:
        user.username = new_name
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'User not found'})
