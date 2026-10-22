"""
RECONQUEST - Logging Configuration
Structured logging with standard and audit logs.
"""

import os
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines."""
    def format(self, record):
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if hasattr(record, "audit_data"):
            log_obj["audit"] = record.audit_data
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logging(app=None, log_dir=None):
    """Set up loggers for the application, audits, and scans."""
    if log_dir is None:
        if app:
            log_dir = app.config.get('LOGS_DIR')
        else:
            log_dir = Path(__file__).resolve().parent.parent / 'instance' / 'logs'
            
    os.makedirs(log_dir, exist_ok=True)
    
    # Root & App Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
        # App log
        app_handler = RotatingFileHandler(
            os.path.join(log_dir, 'reconquest.log'),
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        app_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
        ))
        root_logger.addHandler(app_handler)
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '\033[1;36m[RECONQUEST]\033[0m [%(levelname)s] %(message)s'
        ))
        root_logger.addHandler(console_handler)

    # Dedicated Audit Logger
    audit_logger = logging.getLogger('reconquest.audit')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    
    if not audit_logger.handlers:
        audit_handler = RotatingFileHandler(
            os.path.join(log_dir, 'audit.log'),
            maxBytes=10 * 1024 * 1024,
            backupCount=10
        )
        audit_handler.setFormatter(JsonFormatter())
        audit_logger.addHandler(audit_handler)

    return root_logger, audit_logger


def get_audit_logger():
    """Get the audit logger instance."""
    return logging.getLogger('reconquest.audit')


def log_audit_event(action, user='local_operator', target=None, tool=None, status='initiated', details=None):
    """Helper to record an audit trail entry."""
    audit_logger = get_audit_logger()
    audit_data = {
        "action": action,
        "operator": user,
        "target": target,
        "tool": tool,
        "status": status,
        "details": details or {}
    }
    audit_logger.info(f"AUDIT: {action} on {target or 'system'} via {tool or 'internal'} - {status}", extra={"audit_data": audit_data})
