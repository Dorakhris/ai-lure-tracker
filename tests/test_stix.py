"""
Unit tests for AI Lure Tracker - STIX 2.1 Exporter
"""

import json
import os
import pytest
from src.models import EnrichedIndicator, EnrichmentData, IndicatorType, ConfidenceLevel
from src.storage.stix_exporter import STIXExporter


def test_stix_bundle_generation(tmp_path):
    exporter = STIXExporter()

    ind = EnrichedIndicator(
        value="chatgpt-pro-installer.top",
        indicator_type=IndicatorType.DOMAIN,
        source="CertStream",
        target_brand="OpenAI / ChatGPT",
        lure_type="fake_installer",
        associated_malware="LummaC2 Stealer",
        confidence_score=95,
        confidence_level=ConfidenceLevel.HIGH,
        mitre_attack=["T1566.002", "T1204.002"],
        enrichment=EnrichmentData(domain_age_days=2, asn="AS12345", registrar="NameSilo")
    )

    out_file = str(tmp_path / "test_stix.json")
    res_path = exporter.export_bundle([ind], output_path=out_file)

    assert os.path.exists(res_path)
    with open(res_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    assert bundle["type"] == "bundle"
    objs = bundle["objects"]
    types = {o["type"] for o in objs}

    assert "identity" in types
    assert "indicator" in types
    assert "malware" in types
    assert "attack-pattern" in types
    assert "relationship" in types

    # Check indicator pattern
    indicator_sdo = next(o for o in objs if o["type"] == "indicator")
    assert "[domain-name:value = 'chatgpt-pro-installer.top']" in indicator_sdo["pattern"]
    assert indicator_sdo["confidence"] == 95
