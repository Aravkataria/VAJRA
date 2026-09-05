# tests/test_dataset_synthesizer.py

import json
import tempfile
from pathlib import Path
import pytest

from training.model1_security_analyst.schema import DatasetSampleCategory, TrainingSample
from training.model1_security_analyst.dataset_synthesizer import MultilingualDatasetSynthesizer


def test_seed_dataset_generation():
    synthesizer = MultilingualDatasetSynthesizer()
    samples = synthesizer.generate_seed_dataset()

    assert len(samples) == 8
    categories = {s.category for s in samples}
    assert DatasetSampleCategory.RULE_AND_AI_POSITIVE in categories
    assert DatasetSampleCategory.AI_INDEPENDENT_POSITIVE in categories
    assert DatasetSampleCategory.HARD_NEGATIVE_SAFE in categories
    assert DatasetSampleCategory.DETERMINISTIC_FALSE_POSITIVE in categories
    assert DatasetSampleCategory.MULTI_FILE_TAINT in categories
    assert DatasetSampleCategory.CROSS_LANGUAGE_EQUIVALENTS in categories
    assert DatasetSampleCategory.COMPLEX_CONTEXT_POSITIVE in categories
    assert DatasetSampleCategory.UNCERTAIN_SECURITY_CASE in categories

    # Verify chat format conversion
    chat = samples[0].to_chat_format()
    assert "messages" in chat
    assert len(chat["messages"]) == 3
    assert chat["messages"][0]["role"] == "system"
    assert chat["messages"][1]["role"] == "user"
    assert chat["messages"][2]["role"] == "assistant"


def test_dataset_jsonl_export():
    synthesizer = MultilingualDatasetSynthesizer()
    samples = synthesizer.generate_seed_dataset()

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_file = Path(tmp_dir) / "dataset.jsonl"
        count = synthesizer.export_jsonl(samples, out_file)

        assert count == 8
        assert out_file.exists()

        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 8
        parsed = json.loads(lines[0])
        assert "messages" in parsed
