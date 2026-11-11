"""Flask Blueprints for the web app (see web/app.py create_app())."""
from ai_log_analyzer.web.blueprints import admin, analysis, auth, core, llm, rag

__all__ = ['admin', 'analysis', 'auth', 'core', 'llm', 'rag']
