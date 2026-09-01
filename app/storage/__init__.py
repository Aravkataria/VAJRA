# app/storage/__init__.py
from app.storage.db import Database, get_db

__all__ = ["Database", "get_db"]