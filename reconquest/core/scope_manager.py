"""
RECONQUEST - Scope Manager
Enforces strict boundaries, target scope validation, and authorization controls.
"""

import re
import ipaddress
from typing import Tuple, List, Dict, Any, Optional
from database.db import db
from database.models import Target
from core.logging_config import log_audit_event


class ScopeManager:
    """Manages target boundaries and validates authorization for reconnaissance tasks."""

    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    BSSID_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    @classmethod
    def sanitize_input(cls, raw: str) -> str:
        """Strip protocols, trailing slashes, and paths from target input."""
        cleaned = raw.strip()
        cleaned = re.sub(r'^https?://', '', cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.split('/')[0]  # remove paths

        # Handle bracketed IPv6 with port e.g. [2001:db8::1]:8080
        if cleaned.startswith('[') and ']' in cleaned:
            bracket_content = cleaned[1:cleaned.index(']')]
            return bracket_content.strip()

        # Only strip port for IPv4 or hostname (single colon)
        if cleaned.count(':') == 1 and not re.match(r'^[0-9a-fA-F:]+$', cleaned):
            cleaned = cleaned.split(':')[0]

        return cleaned.strip()

    @classmethod
    def validate_domain(cls, domain: str) -> Tuple[bool, str]:
        """Validate if target matches domain syntax."""
        cleaned = cls.sanitize_input(domain)
        if not cleaned:
            return False, "Target cannot be empty."
        if len(cleaned) > 253:
            return False, "Domain exceeds maximum length of 253 characters."
        if not cls.DOMAIN_REGEX.match(cleaned):
            return False, f"'{cleaned}' is not a valid fully qualified domain name."
        return True, cleaned

    @classmethod
    def validate_ip(cls, ip_str: str) -> Tuple[bool, str]:
        """Validate single IPv4 or IPv6 address."""
        cleaned = cls.sanitize_input(ip_str)
        try:
            ipaddress.ip_address(cleaned)
            return True, cleaned
        except ValueError:
            return False, f"'{cleaned}' is not a valid IP address."

    @classmethod
    def validate_cidr(cls, cidr_str: str) -> Tuple[bool, str]:
        """Validate CIDR network range."""
        cleaned = cidr_str.strip()
        try:
            ipaddress.ip_network(cleaned, strict=False)
            return True, cleaned
        except ValueError:
            return False, f"'{cleaned}' is not a valid CIDR network range."

    @classmethod
    def validate_wifi_target(cls, target: str, target_type: str = 'wifi_bssid') -> Tuple[bool, str]:
        """Validate SSID or BSSID."""
        cleaned = target.strip()
        if target_type == 'wifi_bssid':
            if not cls.BSSID_REGEX.match(cleaned):
                return False, f"'{cleaned}' is not a valid MAC/BSSID address (e.g. 00:11:22:33:44:55)."
            return True, cleaned.upper()
        else:
            # SSID
            if not cleaned or len(cleaned) > 32:
                return False, "SSID must be between 1 and 32 characters."
            return True, cleaned

    @classmethod
    def add_target(cls, target_type: str, value: str, notes: str = "", authorized_by: str = "Local Operator") -> Tuple[bool, str, Optional[Target]]:
        """Add a target to the authorized scope database."""
        # Sanitize and validate based on type
        val = value.strip()
        if target_type == 'domain':
            valid, res = cls.validate_domain(val)
        elif target_type == 'ip':
            valid, res = cls.validate_ip(val)
        elif target_type == 'cidr':
            valid, res = cls.validate_cidr(val)
        elif target_type in ['wifi_bssid', 'wifi_ssid']:
            valid, res = cls.validate_wifi_target(val, target_type)
        else:
            return False, f"Unsupported target type: {target_type}", None

        if not valid:
            return False, res, None

        # Check for duplicate
        existing = Target.query.filter_by(value=res).first()
        if existing:
            return False, f"Target '{res}' is already registered in scope.", existing

        target = Target(
            target_type=target_type,
            value=res,
            scope_status='in_scope',
            authorized_by=authorized_by,
            notes=notes
        )
        db.session.add(target)
        db.session.commit()

        log_audit_event(
            action="TARGET_SCOPE_ADDED",
            target=res,
            status="authorized",
            details={"target_type": target_type, "authorized_by": authorized_by, "notes": notes}
        )

        return True, f"Target '{res}' successfully added to in-scope registry.", target

    @classmethod
    def remove_target(cls, target_id: int) -> bool:
        """Remove target from scope list."""
        target = Target.query.get(target_id)
        if target:
            val = target.value
            db.session.delete(target)
            db.session.commit()
            log_audit_event(
                action="TARGET_SCOPE_REMOVED",
                target=val,
                status="revoked"
            )
            return True
        return False

    @classmethod
    def get_all_targets(cls, target_type: Optional[str] = None) -> List[Target]:
        """Fetch all targets in scope."""
        q = Target.query.filter_by(scope_status='in_scope')
        if target_type:
            q = q.filter_by(target_type=target_type)
        return q.order_by(Target.added_at.desc()).all()

    @classmethod
    def is_in_scope(cls, target_val: str) -> Tuple[bool, str]:
        """Check whether a given target is strictly authorized by existing scope entries."""
        cleaned = cls.sanitize_input(target_val)
        if not cleaned:
            return False, "No target provided."

        # 1. Direct exact match
        direct = Target.query.filter_by(value=cleaned, scope_status='in_scope').first()
        if direct:
            return True, f"Target '{cleaned}' matches in-scope entry #{direct.id}."

        # 2. Domain / Subdomain hierarchy check
        all_domains = Target.query.filter_by(target_type='domain', scope_status='in_scope').all()
        for d in all_domains:
            # If target ends with .parent_domain
            if cleaned == d.value or cleaned.endswith(f".{d.value}"):
                return True, f"Target '{cleaned}' is an authorized subdomain under scope domain '{d.value}'."

        # 3. IP / CIDR check
        try:
            target_ip = ipaddress.ip_address(cleaned)
            all_cidrs = Target.query.filter_by(target_type='cidr', scope_status='in_scope').all()
            for c in all_cidrs:
                net = ipaddress.ip_network(c.value, strict=False)
                if target_ip in net:
                    return True, f"Target IP '{cleaned}' is within authorized network range '{c.value}'."
        except ValueError:
            pass

        # 4. WiFi BSSID check
        all_bssids = Target.query.filter_by(target_type='wifi_bssid', scope_status='in_scope').all()
        for b in all_bssids:
            if cleaned.upper() == b.value.upper():
                return True, f"Wi-Fi AP '{cleaned}' is authorized for testing."

        return False, f"Target '{cleaned}' is NOT present in the approved scope list. Please add it to Target Manager first."
