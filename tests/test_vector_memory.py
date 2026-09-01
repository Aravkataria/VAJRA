# tests/test_vector_memory.py

from app.storage.vector_memory import SoftwareEngineeringMemory


def test_software_engineering_memory_retrieval():
    mem = SoftwareEngineeringMemory()
    mem.add_record(
        record_id="rec-1",
        vulnerability_type="unsafe-eval",
        code_snippet="def execute(user_code):\n    eval(user_code)\n",
        patch_diff="- eval(user_code)\n+ ast.literal_eval(user_code)",
        verified=True,
        reason="PoC confirmed safe",
    )

    results = mem.retrieve_similar_repairs(
        vulnerability_type="unsafe-eval",
        query_code="def run(code):\n    return eval(code)\n",
    )

    assert len(results) == 1
    assert results[0]["record_id"] == "rec-1"
    assert results[0]["verified"] is True