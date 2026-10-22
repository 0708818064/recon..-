"""
RECONQUEST - Configuration Module
Cybersecurity Reconnaissance and Security Assessment
"""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get('RECONQUEST_SECRET_KEY') or secrets.token_hex(32)
    
    # Database
    INSTANCE_DIR = BASE_DIR / 'instance'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{INSTANCE_DIR / 'reconquest.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Output and storage directories
    REPORTS_DIR = BASE_DIR / 'instance' / 'reports'
    CAPTURES_DIR = BASE_DIR / 'instance' / 'captures'
    LOGS_DIR = BASE_DIR / 'instance' / 'logs'
    
    # Process & Execution limits
    SUBPROCESS_TIMEOUT_SECONDS = int(os.environ.get('RECONQUEST_TIMEOUT', 300))
    MAX_OUTPUT_SIZE_BYTES = int(os.environ.get('RECONQUEST_MAX_OUTPUT', 10 * 1024 * 1024)) # 10MB
    MAX_CONCURRENT_JOBS = 4
    
    # Host binding security
    HOST = '127.0.0.1'
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = False
    TESTING = False
    
    # CSRF & Session Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    @classmethod
    def init_app(cls, app):
        """Ensure necessary runtime directories exist."""
        cls.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
