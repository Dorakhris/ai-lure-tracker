"""
Unit tests for AI Lure Tracker - Threat Enrichment & Heuristic Scorer
"""

import pytest
from src.models import RawIndicator, EnrichmentData, IndicatorType, ConfidenceLevel
from src.enrichment.heuristic_scorer import ThreatEnrichmentPipeline


@pytest.fixture
def sample_settings():
    return {
        "filtering": {
            "suspicious_tlds": [".top", ".icu", ".buzz", ".xyz", ".lat"]
        },
        "confidence_scoring": {
            "base_score": 40,
            "new_domain_less_than_7_days": 25,
            "new_domain_less_than_14_days": 15,
            "suspicious_tld_match": 15,
            "executable_payload_lure": 30,
            "credential_login_lure": 25,
            "abuse_ch_confirmed": 30,
            "virustotal_malicious_detection": 25,
            "high_threshold": 75,
            "medium_threshold": 50
        }
    }


def test_confidence_scoring_high_threat(sample_settings):
    pipeline = ThreatEnrichmentPipeline(sample_settings)

    # Domain registered 3 days ago with download button and suspicious TLD
    ind = RawIndicator(
        value="chatgpt-free-installer.top",
        indicator_type=IndicatorType.DOMAIN,
        source="CertStream",
        matched_brand="openai",
        lure_category="fake_installer"
    )

    enr = EnrichmentData(
        domain_age_days=3,
        has_download_link=True
    )

    score, level = pipeline.calculate_confidence(ind, enr)
    # Base 40 + age<7d (25) + suspicious TLD (15) + download link (30) = 110 -> clamped to 100
    assert score >= 75
    assert level == ConfidenceLevel.HIGH


def test_malware_attribution(sample_settings):
    pipeline = ThreatEnrichmentPipeline(sample_settings)

    ind = RawIndicator(
        value="https://claude-desktop-win64.top/setup.exe",
        indicator_type=IndicatorType.URL,
        source="URLhaus",
        matched_brand="anthropic",
        lure_category="fake_installer"
    )

    attributed = pipeline.attribute_malware(ind)
    assert attributed in ["LummaC2 Stealer", "Stealc Stealer"]
