"""Bootstrap package.

Responsible for re-exporting environment loading at application startup.
"""
from app.bootstrap.env import load_backend_dotenv

__all__ = ["load_backend_dotenv"]
