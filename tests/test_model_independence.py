# tests/test_model_independence.py

import logging

from app.analysis.ai_analyst import AIAnalyst
from app.analysis.analyst import SecurityAnalyst
from app.analysis.ollama_provider import OllamaProvider
from app.model_independence import check_model_independence
from app.repair.ai_repair import AIRepairer
from app.repair.deterministic_repair import DeterministicRepairer
from app.repair.ollama_repair_provider import OllamaRepairProvider
from app.repair.repairer import Repairer


def test_warns_when_same_model_used_for_both_stages(caplog):
    analyst = SecurityAnalyst(model=AIAnalyst(OllamaProvider(model="llama3.1")))
    repairer = Repairer([AIRepairer(OllamaRepairProvider(model="llama3.1"))])

    with caplog.at_level(logging.WARNING):
        check_model_independence(analyst, repairer)

    assert any("same model" in record.message for record in caplog.records)


def test_no_warning_when_models_differ(caplog):
    analyst = SecurityAnalyst(model=AIAnalyst(OllamaProvider(model="llama3.1")))
    repairer = Repairer([AIRepairer(OllamaRepairProvider(model="qwen2.5-coder:3b"))])

    with caplog.at_level(logging.WARNING):
        check_model_independence(analyst, repairer)

    assert not caplog.records


def test_no_warning_when_analyst_is_deterministic(caplog):
    # The default analyst has no underlying named model at all -- nothing
    # for the repairer's model to collide with.
    analyst = SecurityAnalyst()
    repairer = Repairer([AIRepairer(OllamaRepairProvider(model="llama3.1"))])

    with caplog.at_level(logging.WARNING):
        check_model_independence(analyst, repairer)

    assert not caplog.records


def test_no_warning_when_repairer_is_deterministic_only(caplog):
    analyst = SecurityAnalyst(model=AIAnalyst(OllamaProvider(model="llama3.1")))
    repairer = Repairer([DeterministicRepairer()])

    with caplog.at_level(logging.WARNING):
        check_model_independence(analyst, repairer)

    assert not caplog.records
