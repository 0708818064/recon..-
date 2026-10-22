"""
RECONQUEST - Database Models
Defines all SQLAlchemy models for scans, targets, gamification, and audit trails.
"""

import json
from datetime import datetime, timezone
from .db import db


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, default='Operator')
    xp_points = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    settings_json = db.Column(db.Text, default='{}')

    # Relationships
    scan_results = db.relationship('ScanResult', backref='user', lazy=True, cascade='all, delete-orphan')
    targets = db.relationship('Target', backref='user', lazy=True, cascade='all, delete-orphan')
    achievements = db.relationship('UserAchievement', backref='user', lazy=True, cascade='all, delete-orphan')
    missions = db.relationship('MissionProgress', backref='user', lazy=True, cascade='all, delete-orphan')

    def add_xp(self, points):
        """Add XP and recalculate level (100 XP per level)."""
        self.xp_points += points
        new_level = (self.xp_points // 100) + 1
        level_up = new_level > self.level
        self.level = new_level
        return level_up


class Target(db.Model):
    __tablename__ = 'targets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    target_type = db.Column(db.String(30), nullable=False)  # domain, ip, cidr, wifi_ssid, wifi_bssid
    value = db.Column(db.String(255), nullable=False, index=True)
    scope_status = db.Column(db.String(20), default='in_scope')  # in_scope, out_of_scope
    authorized_by = db.Column(db.String(100), default='Local Operator')
    notes = db.Column(db.Text, default='')
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'target_type': self.target_type,
            'value': self.value,
            'scope_status': self.scope_status,
            'authorized_by': self.authorized_by,
            'notes': self.notes,
            'added_at': self.added_at.isoformat() if self.added_at else None
        }


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    scan_type = db.Column(db.String(50), nullable=False)  # web_recon, wifi_security, campaign
    tool_name = db.Column(db.String(50), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, index=True)
    command_executed = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), default='pending')  # pending, running, completed, failed, cancelled
    raw_output = db.Column(db.Text, default='')
    error_output = db.Column(db.Text, default='')
    parsed_results_json = db.Column(db.Text, default='{}')
    duration_seconds = db.Column(db.Float, default=0.0)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    def get_parsed_results(self):
        try:
            return json.loads(self.parsed_results_json or '{}')
        except Exception:
            return {}

    def set_parsed_results(self, data):
        self.parsed_results_json = json.dumps(data)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'tool_name': self.tool_name,
            'target': self.target,
            'command_executed': self.command_executed,
            'status': self.status,
            'duration_seconds': round(self.duration_seconds, 2) if self.duration_seconds else 0.0,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'parsed_results': self.get_parsed_results(),
            'raw_output': self.raw_output[:2000] if self.raw_output else ''
        }


class Achievement(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(50), default='trophy')
    xp_reward = db.Column(db.Integer, default=50)
    category = db.Column(db.String(50), default='general')

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'xp_reward': self.xp_reward,
            'category': self.category
        }


class UserAchievement(db.Model):
    __tablename__ = 'user_achievements'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievements.id'), nullable=False)
    earned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    achievement = db.relationship('Achievement', lazy=True)


class Mission(db.Model):
    __tablename__ = 'missions'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='web_recon')
    difficulty = db.Column(db.String(20), default='Beginner')  # Beginner, Intermediate, Advanced
    xp_reward = db.Column(db.Integer, default=100)
    steps_json = db.Column(db.Text, default='[]')
    hints = db.Column(db.Text, default='')

    def get_steps(self):
        try:
            return json.loads(self.steps_json or '[]')
        except Exception:
            return []

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'difficulty': self.difficulty,
            'xp_reward': self.xp_reward,
            'steps': self.get_steps(),
            'hints': self.hints
        }


class MissionProgress(db.Model):
    __tablename__ = 'mission_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mission_id = db.Column(db.Integer, db.ForeignKey('missions.id'), nullable=False)
    status = db.Column(db.String(20), default='in_progress')  # in_progress, completed
    current_step = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)

    mission = db.relationship('Mission', lazy=True)


class ToolStatus(db.Model):
    __tablename__ = 'tool_status'
    id = db.Column(db.Integer, primary_key=True)
    tool_name = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(30), default='MISSING')
    version = db.Column(db.String(50), nullable=True)
    path = db.Column(db.String(255), nullable=True)
    last_checked = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    error_message = db.Column(db.Text, nullable=True)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    tool = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(30), default='completed')
    operator = db.Column(db.String(80), default='Local Operator')
    details_json = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'target': self.target,
            'tool': self.tool,
            'status': self.status,
            'operator': self.operator,
            'details': json.loads(self.details_json or '{}'),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


def seed_defaults():
    """Populate default user, achievements, and missions if they don't exist."""
    # Ensure default user
    if not User.query.first():
        default_user = User(username='Commander', xp_points=0, level=1)
        db.session.add(default_user)
        db.session.commit()

    # Default Achievements
    achievements_data = [
        ('FIRST_BLOOD', 'Recon Beginner', 'Complete your very first reconnaissance operation.', 'compass', 50, 'web_recon'),
        ('SUBDOMAIN_MASTER', 'Subdomain Explorer', 'Successfully perform passive subdomain discovery on an authorized target.', 'network-wired', 75, 'web_recon'),
        ('PORT_SCANNER', 'Port & Service Scout', 'Complete an authorized port scan using Nmap.', 'satellite-dish', 100, 'web_recon'),
        ('HTTP_PROBER', 'Web Analyst', 'Identify live HTTP services and headers using httpx.', 'globe', 75, 'web_recon'),
        ('VULN_HUNTER', 'Vulnerability Analyst', 'Review an authorized security template scan using Nuclei.', 'shield-halved', 150, 'web_recon'),
        ('WIFI_DIAG', 'Wireless Explorer', 'Complete hardware and driver diagnostics for local wireless interfaces.', 'wifi', 75, 'wifi_security'),
        ('WIFI_OBSERVER', 'Airwave Scout', 'Discover and catalog visible authorized wireless networks.', 'broadcast-tower', 100, 'wifi_security'),
        ('CAPTURE_ANALYST', 'Wi-Fi Analyst', 'Perform security inspection on a wireless capture file.', 'file-waveform', 125, 'wifi_security'),
        ('TOOL_COLLECTOR', 'Tool Master', 'Detect and configure at least 5 ready cybersecurity tools in Tool Manager.', 'wrench', 150, 'system'),
        ('SCOPE_GUARDIAN', 'Scope Guardian', 'Define an authorized testing scope and enforce boundaries.', 'crosshairs', 50, 'system'),
    ]

    for code, name, desc, icon, xp, cat in achievements_data:
        if not Achievement.query.filter_by(code=code).first():
            ach = Achievement(code=code, name=name, description=desc, icon=icon, xp_reward=xp, category=cat)
            db.session.add(ach)

    # Default Missions
    missions_data = [
        ('MISSION_DOM_INTEL', 'Operation Passive Orbit', 'Gather passive domain intelligence and whois/DNS records for an authorized target.', 'web_recon', 'Beginner', 100,
         json.dumps(['Define Target Scope', 'Execute WHOIS query', 'Perform DNS record query', 'Review intelligence report']),
         'Always verify your target is in the authorized scope list before gathering intelligence.'),
        
        ('MISSION_SUB_DISCOVERY', 'Operation Shadow Map', 'Map out all accessible subdomains using passive discovery techniques.', 'web_recon', 'Beginner', 120,
         json.dumps(['Set Target Domain', 'Run Subfinder or Assetfinder', 'Analyze discovered hosts', 'Verify live endpoints']),
         'Passive discovery relies on public certificate transparency logs and search engines without touching the target server directly.'),
         
        ('MISSION_HTTP_PROBING', 'Operation Lighthouse', 'Scan target hostnames to discover live HTTP/HTTPS services, headers, and technologies.', 'web_recon', 'Intermediate', 150,
         json.dumps(['Select subdomains', 'Run httpx probing', 'Fingerprint tech stacks', 'Export service map']),
         'httpx probes open web ports to retrieve HTTP response status codes and server banners.'),

        ('MISSION_SERVICE_SCAN', 'Operation Port Sentinel', 'Execute authorized port discovery using Nmap to identify active listening services.', 'web_recon', 'Intermediate', 200,
         json.dumps(['Verify authorization', 'Run Nmap service scan', 'Identify service versions', 'Flag potential risks']),
         'Ensure active scanning is explicitly permitted in your scope policy.'),

        ('MISSION_VULN_ASSESS', 'Operation Cyber Sentry', 'Scan authorized web services with Nuclei security templates to detect vulnerabilities.', 'web_recon', 'Advanced', 250,
         json.dumps(['Load live targets', 'Select severity levels', 'Execute Nuclei scan', 'Review remediation guidance']),
         'Nuclei uses YAML templates to test for known CVEs and misconfigurations safely without destructive payloads.'),

        ('MISSION_WIFI_DIAG', 'Operation Spectrum Check', 'Analyze your wireless adapter capabilities, monitor mode support, and rfkill status.', 'wifi_security', 'Beginner', 80,
         json.dumps(['Inspect wireless interfaces', 'Check driver and chipset', 'Verify monitor mode support', 'Review rfkill states']),
         'Some internal Wi-Fi chipsets do not support packet injection; USB adapters like Alfa AWUS036ACH are commonly used.'),

        ('MISSION_WIFI_DISCOVERY', 'Operation Air Recon', 'Discover visible wireless networks, SSIDs, BSSIDs, frequencies, and encryption types.', 'wifi_security', 'Intermediate', 150,
         json.dumps(['Select wireless interface', 'Scan visible 2.4/5GHz networks', 'Analyze security protocols', 'Record authorized lab BSSID']),
         'Passive beacon frame scanning observes broadcast packets without transmitting data.'),
    ]

    for code, name, desc, cat, diff, xp, steps, hints in missions_data:
        if not Mission.query.filter_by(code=code).first():
            m = Mission(code=code, name=name, description=desc, category=cat, difficulty=diff, xp_reward=xp, steps_json=steps, hints=hints)
            db.session.add(m)

    db.session.commit()
