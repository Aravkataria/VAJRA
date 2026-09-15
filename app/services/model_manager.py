# app/services/model_manager.py

"""
Dedicated Model Management Layer for VAJRA.

Ensures:
1. Model 1 (Security Analyst) and Model 2 (AI Patch Generator) are loaded ONCE
   at server startup and kept in memory.
2. Shared inference: Single loaded model instances serve multiple concurrent workspaces/users.
3. Completely stateless execution: Models do not retain user-specific or workspace-specific state.
4. Concurrency control: Default concurrency is set to 1 (configurable via VAJRA_MAX_CONCURRENT_INFERENCE)
   to protect against GPU/CPU memory contention and race conditions.
5. Graceful degradation: If AI/Ollama models fail to load or are offline, falls back cleanly
   to deterministic engines without crashing the server.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from app.analysis.analyst import SecurityAnalyst, build_default_analyst
from app.evidence.evidence import Evidence
from app.decision.decision import Decision
from app.model_independence import check_3tier_model_independence
from app.repair.patch import Patch
from app.repair.repairer import RepairAttempt, Repairer, build_default_repairer
from app.verification.verifier import Verifier, build_default_verifier

logger = logging.getLogger("vajra.model_manager")


class ModelManager:
    """
    Singleton server-level resource managing Model 1, Model 2, and Verifier.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._initialized = False
        
        # Concurrency control: Default = 1 for rock-solid memory & GPU safety
        max_concurrency = int(os.environ.get("VAJRA_MAX_CONCURRENT_INFERENCE", "1"))
        self._semaphore = threading.Semaphore(max_concurrency)
        self._max_concurrency = max_concurrency
        self._active_inferences = 0
        self._active_lock = threading.Lock()

        # Model instances (Application-level resources)
        self._analyst: Optional[SecurityAnalyst] = None
        self._repairer: Optional[Repairer] = None
        self._verifier: Optional[Verifier] = None

        # Version & metadata tracking
        self._model1_version: str = os.environ.get("VAJRA_MODEL1_VERSION", "v1.0.0")
        self._model2_version: str = os.environ.get("VAJRA_MODEL2_VERSION", "v1.0.0")
        self._analyzer_version: str = "vajra-ast-0.2.0"
        self._init_timestamp: Optional[float] = None
        self._init_error: Optional[str] = None
        self._status: str = "uninitialized"

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def model1_version(self) -> str:
        return self._model1_version

    @property
    def model2_version(self) -> str:
        return self._model2_version

    @property
    def analyzer_version(self) -> str:
        return self._analyzer_version

    @property
    def analyst(self) -> SecurityAnalyst:
        if not self._initialized or self._analyst is None:
            self.initialize()
        return self._analyst

    @property
    def repairer(self) -> Repairer:
        if not self._initialized or self._repairer is None:
            self.initialize()
        return self._repairer

    @property
    def verifier(self) -> Verifier:
        if not self._initialized or self._verifier is None:
            self.initialize()
        return self._verifier

    def initialize(self) -> None:
        """
        Load Model 1 and Model 2 once into memory.
        Safe to call multiple times (idempotent).
        """
        with self._lock:
            if self._initialized:
                return

            logger.info("Initializing VAJRA ModelManager (Server-Level Shared Models)...")
            start_time = time.time()

            try:
                # 1. Load Model 1: Security Analyst
                logger.info("Loading Model 1: Multilingual AI Security Analyst...")
                self._analyst = build_default_analyst()

                # 2. Load Model 2: AI Patch Generator
                logger.info("Loading Model 2: AI Patch Generator...")
                self._repairer = build_default_repairer()

                # 3. Load Verifier
                logger.info("Loading Verification Sentinel Pipeline...")
                self._verifier = build_default_verifier()

                # 4. Enforce 3-Tier Sovereign Model Independence
                check_3tier_model_independence(self._analyst, self._repairer, self._verifier)

                self._initialized = True
                self._init_timestamp = time.time()
                self._status = "ready"
                duration = self._init_timestamp - start_time
                logger.info("VAJRA ModelManager initialization complete in %.2f seconds.", duration)

            except Exception as exc:
                logger.error("Failed to load full AI model stack: %s. Falling back to deterministic mode.", exc)
                # Graceful degradation to deterministic baseline
                from app.analysis.analyst import SecurityAnalyst
                from app.repair.repairer import Repairer
                self._analyst = SecurityAnalyst()
                self._repairer = Repairer()
                self._verifier = build_default_verifier()
                self._initialized = True
                self._init_timestamp = time.time()
                self._init_error = str(exc)
                self._status = "degraded"

    # =========================================================================
    # SAFE & STATELESS INFERENCE API
    # =========================================================================

    def analyze(self, evidence: Evidence) -> Any:
        """
        Pure, stateless inference through Model 1.
        Does not retain workspace or user state.
        Guarded by concurrency semaphore.
        """
        if not self._initialized:
            self.initialize()

        with self._semaphore:
            with self._active_lock:
                self._active_inferences += 1
            try:
                return self._analyst.analyze(evidence)
            finally:
                with self._active_lock:
                    self._active_inferences -= 1

    def analyze_all(self, evidence_list: List[Evidence]) -> List[Any]:
        """
        Batch stateless analysis through Model 1 under concurrency guard.
        """
        if not self._initialized:
            self.initialize()

        with self._semaphore:
            with self._active_lock:
                self._active_inferences += 1
            try:
                return self._analyst.analyze_all(evidence_list)
            finally:
                with self._active_lock:
                    self._active_inferences -= 1

    def repair_with_trace(
        self,
        decision: Decision,
        workspace_path: Path,
    ) -> Tuple[Optional[Patch], List[RepairAttempt]]:
        """
        Stateless patch synthesis through Model 2 and/or deterministic repairer.
        Strictly reads the specific workspace_path provided, stores nothing in model memory.
        Guarded by concurrency semaphore.
        """
        if not self._initialized:
            self.initialize()

        with self._semaphore:
            with self._active_lock:
                self._active_inferences += 1
            try:
                return self._repairer.repair_with_trace(decision, workspace_path)
            finally:
                with self._active_lock:
                    self._active_inferences -= 1

    def verify_with_stages(self, patch: Patch, workspace_path: Path):
        """
        Stateless verification of proposed patch against workspace.
        """
        if not self._initialized:
            self.initialize()

        return self._verifier.verify_with_stages(patch, workspace_path)

    # =========================================================================
    # STATUS & TELEMETRY
    # =========================================================================

    def get_health_details(self) -> Dict[str, Any]:
        """
        Returns safe operational telemetry for health check endpoints.
        Never exposes sensitive keys, file system paths, or model parameters.
        """
        model1_type = type(self._analyst.model).__name__ if self._analyst else "none"
        model2_types = [type(m).__name__ for m in self._repairer.models] if self._repairer else []

        with self._active_lock:
            active = self._active_inferences

        return {
            "status": self._status,
            "error": self._init_error,
            "model1": {
                "name": "Multilingual AI Security Analyst",
                "version": self._model1_version,
                "implementation": model1_type,
                "loaded": self._analyst is not None,
            },
            "model2": {
                "name": "AI Patch Generator",
                "version": self._model2_version,
                "implementations": model2_types,
                "loaded": self._repairer is not None,
            },
            "concurrency": {
                "max_concurrent": self._max_concurrency,
                "active_inferences": active,
            },
            "analyzer_version": self._analyzer_version,
        }

    def shutdown(self) -> None:
        """Cleanly releases any allocated resources on server shutdown."""
        logger.info("Shutting down VAJRA ModelManager...")
        with self._lock:
            self._initialized = False
            self._analyst = None
            self._repairer = None
            self._verifier = None
            self._status = "stopped"


# Global singleton instance
_model_manager_instance: Optional[ModelManager] = None
_instance_lock = threading.Lock()


def get_model_manager() -> ModelManager:
    global _model_manager_instance
    if _model_manager_instance is None:
        with _instance_lock:
            if _model_manager_instance is None:
                _model_manager_instance = ModelManager()
    return _model_manager_instance
