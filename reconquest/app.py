"""
RECONQUEST - Main Application Entrypoint
Cybersecurity Reconnaissance and Security Assessment
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from config import config_by_name
from database.db import init_db
from core.logging_config import setup_logging
from routes import bp as main_bp


def create_app(config_name=None):
    """Application factory for RECONQUEST."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')

    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name['default'])
    app.config.from_object(config_obj)
    config_obj.init_app(app)

    # Initialize structured logging
    setup_logging(app)

    # Enable CSRF Protection
    csrf = CSRFProtect()
    csrf.init_app(app)

    # Expose csrf_token to templates
    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)

    # Initialize Database & seed models
    init_db(app)

    # Register Routes
    app.register_blueprint(main_bp)

    return app


app = create_app()

if __name__ == '__main__':
    host = os.environ.get('RECONQUEST_HOST', '127.0.0.1')
    port = int(os.environ.get('RECONQUEST_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1']

    print(r"""
  ____  _____ ____ ___  _   _  ___  _   _ _____ ____ _____ 
 |  _ \| ____/ ___/ _ \| \ | |/ _ \| | | | ____/ ___|_   _|
 | |_) |  _|| |  | | | |  \| | | | | | | |  _| \___ \ | |  
 |  _ <| |__| |__| |_| | |\  | |_| | |_| | |___ ___) || |  
 |_| \_\_____\____\___/|_| \_|\__\_\\___/|_____|____/ |_|  
   CYBERSECURITY RECONNAISSANCE & SECURITY ASSESSMENT
    """)
    print(f"[*] Bound securely to {host}:{port}")
    print("[*] Press Ctrl+C in this terminal to exit.\n")
    app.run(host=host, port=port, debug=debug)
