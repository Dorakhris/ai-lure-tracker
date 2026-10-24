"""
Unit tests for AI Lure Tracker - Filtering and Typosquatting Engine
"""

import pytest
from src.filters.whitelist import DomainWhitelist
from src.filters.typosquat_detector import (
    levenshtein_distance,
    damerau_levenshtein_distance,
    TyposquatDetector
)
from src.filters.brand_matcher import BrandMatcher
from src.models import RawIndicator, IndicatorType


@pytest.fixture
def sample_config():
    return {
        "brands": {
            "openai": {
                "name": "OpenAI / ChatGPT",
                "keywords": ["chatgpt", "openai", "gpt-4"]
            },
            "anthropic": {
                "name": "Anthropic / Claude",
                "keywords": ["claude", "anthropic"]
            },
            "google_ai": {
                "name": "Google AI / Gemini",
                "keywords": ["gemini", "bard"]
            }
        },
        "targeted_packages": [
            {"name": "openai"},
            {"name": "langchain"},
            {"name": "transformers"}
        ],
        "allowlist_domains": [
            "openai.com",
            "chatgpt.com",
            "anthropic.com",
            "claude.ai",
            "google.com"
        ]
    }


def test_whitelist():
    whitelist = DomainWhitelist(["openai.com", "claude.ai"])
    # Legitimate root and subdomains must be allowed
    assert whitelist.is_whitelisted("openai.com") is True
    assert whitelist.is_whitelisted("api.openai.com") is True
    assert whitelist.is_whitelisted("https://auth.openai.com/login") is True
    assert whitelist.is_whitelisted("claude.ai") is True

    # Malicious subdomain tricks must NOT be whitelisted
    assert whitelist.is_whitelisted("openai.com.attacker.top") is False
    assert whitelist.is_whitelisted("fake-openai.com") is False
    assert whitelist.is_whitelisted("chatgpt-installer.top") is False


def test_levenshtein_and_damerau():
    # Substitution
    assert levenshtein_distance("openai", "openaj") == 1
    # Transposition
    assert damerau_levenshtein_distance("openai", "oepnai") == 1
    assert damerau_levenshtein_distance("langchain", "langchin") == 1
    assert damerau_levenshtein_distance("claude", "claudee") == 1


def test_package_typosquat_detector():
    detector = TyposquatDetector(["openai", "langchain", "transformers"], max_distance=2)

    # Typosquats
    res = detector.check_package_typosquat("oepnai")
    assert res is not None
    assert res[0] == "openai"

    res = detector.check_package_typosquat("langchin")
    assert res is not None
    assert res[0] == "langchain"

    # Affix pattern
    res = detector.check_package_typosquat("langchain-core-v2")
    assert res is not None


def test_brand_matcher_filtering(sample_config):
    matcher = BrandMatcher(sample_config)

    # 1. Malicious domain should match
    ind = RawIndicator(
        value="https://chatgpt-desktop-installer.top/setup.exe",
        indicator_type=IndicatorType.URL,
        source="URLhaus"
    )
    filtered = matcher.filter_indicator(ind)
    assert filtered is not None
    assert filtered.matched_brand == "openai"
    assert filtered.lure_category == "fake_installer"

    # 2. Legitimate domain should be whitelisted out
    legit_ind = RawIndicator(
        value="https://chatgpt.com/auth/login",
        indicator_type=IndicatorType.URL,
        source="OpenPhish"
    )
    assert matcher.filter_indicator(legit_ind) is None

    # 3. Unrelated URL should be rejected
    unrelated_ind = RawIndicator(
        value="https://mybank-account-security-update.com",
        indicator_type=IndicatorType.URL,
        source="OpenPhish"
    )
    assert matcher.filter_indicator(unrelated_ind) is None
