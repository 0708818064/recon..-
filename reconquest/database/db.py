"""
RECONQUEST - Database Initialization
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Initialize database with Flask app and create all tables."""
    db.init_app(app)
    with app.app_context():
        # Import models so SQLAlchemy registers them
        from . import models  # noqa: F401
        db.create_all()
        # Seed default gamification and missions
        models.seed_defaults()
