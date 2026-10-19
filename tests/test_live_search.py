import pytest
import re
from hf_space.app import (
    should_search_live_web,
    SEARCH_TRIGGER_REGEX,
    format_web_context_for_prompt,
    ensure_citations_in_reply,
)
from hf_zerogpu_space.app import (
    should_search_live_web as zero_should_search,
    SEARCH_TRIGGER_REGEX as ZERO_SEARCH_REGEX,
    format_web_context_for_prompt as zero_format_web_context,
    ensure_citations_in_reply as zero_ensure_citations,
)


def test_hardware_and_pricing_triggers():
    test_queries = [
        "whats the cost of 1tb ssd?",
        "what is the price of rtx 4090?",
        "how much does a macbook pro cost?",
        "latest benchmarks for ryzen 9000",
        "specs of samsung 990 pro ssd",
        "search the web for python 3.12 release notes",
    ]
    for q in test_queries:
        should_s, clean_q = should_search_live_web(q)
        assert should_s is True, f"Failed on query: {q}"
        assert len(clean_q) > 0

        z_should_s, z_clean_q = zero_should_search(q)
        assert z_should_s is True, f"ZeroGPU search trigger failed on query: {q}"


def test_search_trigger_regex_coverage():
    match_samples = [
        "cost of 1tb ssd",
        "how much is an nvidia gpu",
        "buy a new laptop",
        "ddr5 ram pricing",
        "cve-2024-3094 report",
        "changelog version 2.0",
    ]
    for sample in match_samples:
        assert SEARCH_TRIGGER_REGEX.search(sample) is not None, f"Regex missed: {sample}"
        assert ZERO_SEARCH_REGEX.search(sample) is not None, f"ZeroGPU regex missed: {sample}"


def test_format_web_context_and_citations():
    mock_sources = [
        {
            "title": "Best 1TB SSDs in 2024",
            "url": "https://example.com/best-ssd",
            "snippet": "Prices range from 70 to 120 USD for top NVMe drives.",
            "source": "example.com",
        }
    ]
    formatted = format_web_context_for_prompt(mock_sources, deep_research=False)
    assert "[VAJRA Live Web Retrieval Context]" in formatted
    assert "https://example.com/best-ssd" in formatted
    assert "Source [1]: Best 1TB SSDs in 2024" in formatted

    zero_formatted = zero_format_web_context(mock_sources, deep_research=False)
    assert "[VAJRA Live Web Retrieval Context]" in zero_formatted

    # Ensure citations are added to raw answer
    raw_answer = "The cost of a 1TB SSD ranges from $70 to $120."
    cited_answer = ensure_citations_in_reply(raw_answer, mock_sources)
    assert "### References & Sources" in cited_answer
    assert "[Best 1TB SSDs in 2024](https://example.com/best-ssd)" in cited_answer


def test_currency_symbol_escaping_logic():
    # Emulate the frontend JS regex replacement: text.replace(/\$(\d+(?:,\d{3})*(?:\.\d+)?)/g, "&#36;$1")
    pattern = re.compile(r"\$(\d+(?:,\d{3})*(?:\.\d+)?)")
    raw_text = "Prices typically range from $70 to $150 USD, often exceeding $200 USD per TB."
    escaped = pattern.sub(r"&#36;\1", raw_text)
    assert "$70" not in escaped
    assert "$150" not in escaped
    assert "$200" not in escaped
    assert "&#36;70 to &#36;150 USD" in escaped
    assert "&#36;200 USD" in escaped
