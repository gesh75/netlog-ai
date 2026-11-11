"""Flask Blueprints for the web app (see web/app.py create_app())."""
from ai_log_analyzer.web.blueprints import admin, auth, core

__all__ = ['admin', 'auth', 'core']
