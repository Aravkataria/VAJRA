# tests/test_kaggle_pipeline.py

import json
import tempfile
from pathlib import Path
import pytest

from training.model1_security_analyst.metrics import EvaluationConfusionMatrix
from kaggle.model1_security_analyst.pipeline_runner import run_17_stage_pipeline


def test_evaluation_confusion_matrix():
    matrix = EvaluationConfusionMatrix(
        dual_confirmed=2,
        rule_only=1,
        ai_only=4,
        missed_by_both=1,
        rule_false_positive=2,
        ai_false_positive=0,
    )

    assert matrix.total_ground_truth_vulnerabilities == 8
    # Missed by rules = ai_only (4) + missed_by_both (1) = 5
    # Independent discovery rate = 4 / 5 = 0.8
    assert matrix.independent_discovery_rate == 0.8
    assert matrix.ai_precision == 1.0
    assert matrix.ai_recall == 6 / 8  # (2 + 4) / 8 = 0.75

    report = matrix.to_report_dict()
    assert "Independent_Discovery_Rate" in report["metrics"]
    assert report["metrics"]["Independent_Discovery_Rate"] == 0.8


def test_17_stage_pipeline_execution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir) / "kaggle_test_out"
        run_17_stage_pipeline(out_dir)

        assert (out_dir / "vajra_model1_train.jsonl").exists()
        assert (out_dir / "model1_export_metadata.json").exists()

        meta = json.loads((out_dir / "model1_export_metadata.json").read_text(encoding="utf-8"))
        assert meta["model_name"] == "vajra-model1-security-analyst-1.5b-scratch"
        assert meta["training_paradigm"] == "trained_from_scratch"
        assert meta["model_roles"]["model_1_finder"] == "trained_from_scratch"
        assert meta["model_roles"]["model_2_fixer"] == "fine_tuned_lora"
        assert meta["model_roles"]["model_3_verifier"] == "trained_from_scratch"
