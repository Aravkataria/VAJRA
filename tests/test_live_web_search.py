"""
Test Suite for VAJRA Live Web Retrieval and Grounding Engine.
Tests zero-key internet search, prompt triggers, source formatting, and citation verification.
"""

import pytest
from backend.server import (
    should_search_live_web,
    format_web_context_for_prompt,
    ensure_citations_in_reply,
    vajra_live_web_search,
)

def test_should_search_live_web_triggers():
    # Explicit search trigger
    should_s, q = should_search_live_web("search the web for CVE-2024-3094 xz backdoor")
    assert should_s is True
    assert "CVE-2024-3094" in q

    # Recency trigger
    should_s, q = should_search_live_web("what is the latest stable version of Python?")
    assert should_s is True

    # Entity lookup trigger
    should_s, q = should_search_live_web("who is Linus Torvalds")
    assert should_s is True

    # Security advisory trigger
    should_s, q = should_search_live_web("tell me about the recent OpenSSH zero-day vulnerability report")
    assert should_s is True

def test_should_search_live_web_non_triggers():
    # Pure algorithmic inquiries without recency triggers
    should_s, _ = should_search_live_web("implement quicksort in python")
    assert should_s is False

    should_s, _ = should_search_live_web("def calculate_fibonacci(n):")
    assert should_s is False

    should_s, _ = should_search_live_web("")
    assert should_s is False

def test_format_web_context_for_prompt():
    empty_context = format_web_context_for_prompt([])
    assert empty_context == ""

    sample_sources = [
        {
            "title": "Python 3.13 Release Notes",
            "url": "https://www.python.org/downloads/release/python-3130/",
            "snippet": "Python 3.13.0 is the newest major release...",
            "source": "python.org"
        },
        {
            "title": "Python (programming language) - Wikipedia",
            "url": "https://en.wikipedia.org/wiki/Python_(programming_language)",
            "snippet": "Python is a high-level general-purpose programming language...",
            "source": "Wikipedia"
        }
    ]

    formatted = format_web_context_for_prompt(sample_sources)
    assert "[VAJRA Live Web Retrieval Context]" in formatted
    assert "Source [1]: Python 3.13 Release Notes" in formatted
    assert "https://www.python.org/downloads/release/python-3130/" in formatted
    assert "### References & Sources" in formatted

def test_ensure_citations_in_reply():
    sources = [
        {
            "title": "Python Official",
            "url": "https://www.python.org",
            "snippet": "Official site",
            "source": "python.org"
        }
    ]

    # Reply without citation should have citation appended
    reply = "Python was created by Guido van Rossum."
    cited = ensure_citations_in_reply(reply, sources)
    assert "### References & Sources" in cited
    assert "- [Python Official](https://www.python.org)" in cited

    # Reply that already has link and header should remain unchanged
    reply_already_cited = "Python is at [Python](https://www.python.org).\n\n### References & Sources\n- [Python](https://www.python.org)"
    assert ensure_citations_in_reply(reply_already_cited, sources) == reply_already_cited

def test_vajra_live_web_search_structure():
    # Query with factual public subject
    results = vajra_live_web_search("Python programming language", max_results=2)
    assert isinstance(results, list)
    if results:
        first = results[0]
        assert "title" in first
        assert "url" in first
        assert "snippet" in first
        assert "source" in first
        assert first["url"].startswith("http")
