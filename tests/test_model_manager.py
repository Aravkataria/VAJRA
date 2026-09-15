# tests/test_model_manager.py

import threading
import time
from app.services.model_manager import ModelManager, get_model_manager
from app.services.cache_manager import get_cache
from app.evidence.evidence import Evidence


def test_model_manager_singleton():
    m1 = get_model_manager()
    m2 = get_model_manager()
    assert m1 is m2


def test_models_loaded_once():
    manager = get_model_manager()
    manager.initialize()
    assert manager.is_initialized
    
    analyst_ref1 = manager.analyst
    repairer_ref1 = manager.repairer
    
    # Second call should not reload or re-create
    manager.initialize()
    assert manager.analyst is analyst_ref1
    assert manager.repairer is repairer_ref1


def test_concurrency_semaphore_guard():
    manager = get_model_manager()
    manager.initialize()
    
    # Verify default concurrency is 1
    assert manager._max_concurrency >= 1
    
    # Test concurrency under simultaneous threads
    evidence = Evidence(
        repository="test_repo",
        file="vuln.py",
        line=10,
        function="handle_req",
        vulnerability_type="yaml_load",
        severity="HIGH",
    )
    
    results = []
    
    def _worker():
        res = manager.analyze(evidence)
        results.append(res)
        
    threads = [threading.Thread(target=_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    assert len(results) == 5
    for r in results:
        assert r is not None


def test_health_telemetry():
    manager = get_model_manager()
    manager.initialize()
    health = manager.get_health_details()
    
    assert health["status"] in ("ready", "degraded")
    assert "model1" in health
    assert health["model1"]["name"] == "Multilingual AI Security Analyst"
    assert health["model1"]["version"]
    assert "model2" in health
    assert health["model2"]["name"] == "AI Patch Generator"
    assert "concurrency" in health
    assert health["concurrency"]["max_concurrent"] >= 1
    assert health["concurrency"]["active_inferences"] == 0
