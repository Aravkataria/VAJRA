# app/services/cache_manager.py

"""
Deterministic, Stage-Aware Caching Layer for VAJRA.

Features:
1. Cache keys incorporate operation/stage:
   hash(operation + input_content_hash + model_version + analyzer_version + config)
2. Safe workspace isolation: Private user findings/patches are never leaked between workspaces.
3. Invalidation:
   - When Model 1 or Model 2 version changes, old model entries are automatically invalidated.
   - When analyzer version changes, old static analysis entries are invalidated.
   - When a workspace is deleted, its user-specific cache entries are immediately purged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional

logger = logging.getLogger("vajra.cache")


class AnalysisCache:
    """
    Thread-safe, stage-aware LRU cache for deterministic VAJRA stages.
    """

    def __init__(self, capacity: int = 1000):
        self._capacity = capacity
        self._lock = threading.Lock()
        # key -> {"data": Any, "workspace_id": Optional[str], "created_at": float}
        self._store: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._workspace_keys: Dict[str, set[str]] = {}

    def compute_key(
        self,
        operation: str,
        input_data: str | bytes | dict | list,
        model_version: str = "",
        analyzer_version: str = "",
        config: Optional[dict] = None,
        workspace_id: Optional[str] = None,
    ) -> str:
        """
        Compute deterministic SHA-256 cache key including stage/operation and versions.
        """
        if isinstance(input_data, (dict, list)):
            serialized_input = json.dumps(input_data, sort_keys=True)
        elif isinstance(input_data, str):
            serialized_input = input_data
        elif isinstance(input_data, bytes):
            serialized_input = input_data.hex()
        else:
            serialized_input = str(input_data)

        config_str = json.dumps(config or {}, sort_keys=True)
        # If workspace-specific isolation is requested, bind workspace_id into the hash
        workspace_tag = f"ws:{workspace_id}" if workspace_id else "global"

        hasher = hashlib.sha256()
        hasher.update(operation.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(workspace_tag.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(model_version.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(analyzer_version.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(config_str.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(serialized_input.encode("utf-8", errors="ignore"))

        return hasher.hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached result if available."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            # Move to end for LRU order
            self._store.move_to_end(key)
            return entry["data"]

    def set(
        self,
        key: str,
        value: Any,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Store result in cache."""
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = {
                "data": value,
                "workspace_id": workspace_id,
            }

            if workspace_id:
                if workspace_id not in self._workspace_keys:
                    self._workspace_keys[workspace_id] = set()
                self._workspace_keys[workspace_id].add(key)

            # Evict oldest entry if capacity exceeded
            if len(self._store) > self._capacity:
                oldest_key, oldest_entry = self._store.popitem(last=False)
                ws = oldest_entry.get("workspace_id")
                if ws and ws in self._workspace_keys:
                    self._workspace_keys[ws].discard(oldest_key)

    def invalidate_workspace(self, workspace_id: str) -> int:
        """
        Purges all cached entries for a given workspace when deleted.
        """
        with self._lock:
            keys = self._workspace_keys.pop(workspace_id, set())
            count = 0
            for k in keys:
                if k in self._store:
                    del self._store[k]
                    count += 1
            return count

    def clear(self) -> None:
        """Clears all cache entries."""
        with self._lock:
            self._store.clear()
            self._workspace_keys.clear()

    def stats(self) -> Dict[str, Any]:
        """Telemetry on cache state."""
        with self._lock:
            return {
                "size": len(self._store),
                "capacity": self._capacity,
                "workspaces_tracked": len(self._workspace_keys),
            }


_cache_instance: Optional[AnalysisCache] = None
_cache_lock = threading.Lock()


def get_cache() -> AnalysisCache:
    global _cache_instance
    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = AnalysisCache()
    return _cache_instance
