"""
AI Lure Tracker - STIX 2.1 Exporter
Generates OASIS STIX 2.1 compliant intelligence bundles including Indicators,
Malware, Attack Patterns, and Relationships.
"""

from typing import List, Dict, Any
from datetime import datetime, timezone
import json
import uuid
import os
import logging

from src.models import EnrichedIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.storage.stix")


class STIXExporter:
    def __init__(
        self,
        identity_name: str = "AI Lure Tracker CTI Initiative",
        identity_class: str = "organization"
    ):
        self.identity_name = identity_name
        self.identity_class = identity_class
        # Deterministic identity ID based on name namespace
        self.identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'ailuretracker.local')}"

    def _create_identity_sdo(self) -> Dict[str, Any]:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": self.identity_name,
            "identity_class": self.identity_class,
            "sectors": ["technology", "defense"],
            "contact_information": "cti@ailuretracker.local"
        }

    def _format_stix_pattern(self, indicator: EnrichedIndicator) -> str:
        escaped_val = indicator.value.replace("'", "\\'")
        if indicator.indicator_type == IndicatorType.DOMAIN:
            return f"[domain-name:value = '{escaped_val}']"
        elif indicator.indicator_type == IndicatorType.URL:
            return f"[url:value = '{escaped_val}']"
        elif indicator.indicator_type == IndicatorType.IP:
            return f"[ipv4-addr:value = '{escaped_val}']"
        elif indicator.indicator_type == IndicatorType.HASH_SHA256:
            return f"[file:hashes.'SHA-256' = '{escaped_val}']"
        elif indicator.indicator_type == IndicatorType.HASH_MD5:
            return f"[file:hashes.'MD5' = '{escaped_val}']"
        elif indicator.indicator_type in [IndicatorType.PACKAGE_PYPI, IndicatorType.PACKAGE_NPM]:
            return f"[software:name = '{escaped_val}']"
        return f"[domain-name:value = '{escaped_val}']"

    def export_bundle(self, indicators: List[EnrichedIndicator], output_path: str = "feeds/ai_lures_stix21.json") -> str:
        """
        Builds and saves a full STIX 2.1 bundle from a list of enriched indicators.
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: List[Dict[str, Any]] = [self._create_identity_sdo()]

        malware_cache: Dict[str, str] = {}
        attack_pattern_cache: Dict[str, str] = {}

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for ind in indicators:
            ind_sdo_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ind.value)}"
            pattern = self._format_stix_pattern(ind)

            external_refs = []
            for tech in ind.mitre_attack:
                external_refs.append({
                    "source_name": "mitre-attack",
                    "external_id": tech,
                    "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
                })

            indicator_sdo = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_sdo_id,
                "created_by_ref": self.identity_id,
                "created": ind.first_seen if "Z" in ind.first_seen else f"{ind.first_seen}Z",
                "modified": ind.last_seen if "Z" in ind.last_seen else f"{ind.last_seen}Z",
                "name": f"AI Lure ({ind.target_brand}): {ind.value}",
                "description": f"Malicious infrastructure using {ind.target_brand} as lure. Lure Category: {ind.lure_type}.",
                "indicator_types": ["malicious-activity", "anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": ind.first_seen if "Z" in ind.first_seen else f"{ind.first_seen}Z",
                "confidence": ind.confidence_score,
                "labels": ind.tags,
                "external_references": external_refs,
                "custom_properties": {
                    "x_target_brand": ind.target_brand,
                    "x_lure_type": ind.lure_type,
                    "x_confidence_level": ind.confidence_level.value,
                    "x_asn": ind.enrichment.asn,
                    "x_registrar": ind.enrichment.registrar,
                    "x_domain_age_days": ind.enrichment.domain_age_days
                }
            }
            objects.append(indicator_sdo)

            # SDO for Associated Malware Family
            if ind.associated_malware and ind.associated_malware != "Unattributed AI Lure":
                mal_name = ind.associated_malware
                if mal_name not in malware_cache:
                    mal_sdo_id = f"malware--{uuid.uuid5(uuid.NAMESPACE_DNS, mal_name)}"
                    malware_cache[mal_name] = mal_sdo_id
                    objects.append({
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": mal_sdo_id,
                        "created_by_ref": self.identity_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "name": mal_name,
                        "is_family": True,
                        "malware_types": ["stealer", "trojan"]
                    })
                else:
                    mal_sdo_id = malware_cache[mal_name]

                # Relationship: Indicator -> indicates -> Malware
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created_by_ref": self.identity_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ind_sdo_id,
                    "target_ref": mal_sdo_id
                })

            # SDOs for MITRE ATT&CK Attack Patterns
            for tech in ind.mitre_attack:
                if tech not in attack_pattern_cache:
                    ap_sdo_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, tech)}"
                    attack_pattern_cache[tech] = ap_sdo_id
                    objects.append({
                        "type": "attack-pattern",
                        "spec_version": "2.1",
                        "id": ap_sdo_id,
                        "created_by_ref": self.identity_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "name": f"MITRE ATT&CK {tech}",
                        "external_references": [{
                            "source_name": "mitre-attack",
                            "external_id": tech,
                            "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
                        }]
                    })
                else:
                    ap_sdo_id = attack_pattern_cache[tech]

                # Relationship: Indicator -> indicates -> Attack Pattern
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created_by_ref": self.identity_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ind_sdo_id,
                    "target_ref": ap_sdo_id
                })

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Successfully generated STIX 2.1 bundle with {len(objects)} objects at {output_path}")
        return output_path
