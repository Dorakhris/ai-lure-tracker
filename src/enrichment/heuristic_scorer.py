"""
AI Lure Tracker - Heuristic Scoring & Full Enrichment Pipeline
Orchestrates enrichment providers and computes CTI confidence scores.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import logging

from src.models import (
    RawIndicator,
    EnrichedIndicator,
    EnrichmentData,
    IndicatorType,
    ConfidenceLevel,
)
from src.enrichment.dns_asn import DNSASNEnricher
from src.enrichment.whois_lookup import WhoisEnricher
from src.enrichment.urlscan import UrlscanEnricher
from src.enrichment.virustotal import VirusTotalEnricher
from src.enrichment.shodan_lookup import ShodanEnricher

logger = logging.getLogger("ai_lure_tracker.enrichment.pipeline")


class ThreatEnrichmentPipeline:
    def __init__(self, settings_config: Dict[str, Any]):
        self.settings = settings_config
        self.score_cfg = settings_config.get("confidence_scoring", {})
        self.suspicious_tlds = set(settings_config.get("filtering", {}).get("suspicious_tlds", []))

        self.dns_enricher = DNSASNEnricher()
        self.whois_enricher = WhoisEnricher()
        self.urlscan_enricher = UrlscanEnricher()
        self.vt_enricher = VirusTotalEnricher()
        self.shodan_enricher = ShodanEnricher()

    def calculate_confidence(
        self,
        indicator: RawIndicator,
        enrichment: EnrichmentData
    ) -> (int, ConfidenceLevel):
        """
        Calculates heuristic confidence score (0-100) based on domain age, presence of
        download buttons, login forms, suspicious TLDs, and third-party threat feeds.
        """
        score = self.score_cfg.get("base_score", 40)

        # 1. Domain Age Heuristic
        age = enrichment.domain_age_days
        if age is not None:
            if age <= 7:
                score += self.score_cfg.get("new_domain_less_than_7_days", 25)
            elif age <= 14:
                score += self.score_cfg.get("new_domain_less_than_14_days", 15)
            elif age <= 30:
                score += self.score_cfg.get("new_domain_less_than_30_days", 10)

        # 2. Suspicious TLD check
        val = indicator.value.lower()
        if any(val.endswith(tld) or f"{tld}/" in val for tld in self.suspicious_tlds):
            score += self.score_cfg.get("suspicious_tld_match", 15)

        # 3. Payload Delivery / Download Button
        if enrichment.has_download_link or indicator.lure_category == "fake_installer":
            score += self.score_cfg.get("executable_payload_lure", 30)

        # 4. Credential Harvesting / Login form
        if enrichment.has_login_form or indicator.lure_category == "credential_phish":
            score += self.score_cfg.get("credential_login_lure", 25)

        # 5. External Threat Feed Confirmations
        if indicator.source in ["URLhaus", "ThreatFox", "MalwareBazaar"]:
            score += self.score_cfg.get("abuse_ch_confirmed", 30)

        if enrichment.virustotal_detections >= 2:
            score += self.score_cfg.get("virustotal_malicious_detection", 25)

        # 6. Typosquat package distance
        dist = indicator.raw_metadata.get("levenshtein_distance")
        if dist == 1:
            score += self.score_cfg.get("typosquat_distance_1", 20)
        elif dist == 2:
            score += self.score_cfg.get("typosquat_distance_2", 10)

        score = min(100, max(0, score))

        # Assign confidence level
        high_thresh = self.score_cfg.get("high_threshold", 75)
        med_thresh = self.score_cfg.get("medium_threshold", 50)

        if score >= high_thresh:
            level = ConfidenceLevel.HIGH
        elif score >= med_thresh:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        return score, level

    def attribute_malware(self, indicator: RawIndicator) -> Optional[str]:
        """
        Correlates indicator with common malware families observed delivering fake AI tools.
        """
        # Check source metadata first
        meta_malware = indicator.raw_metadata.get("malware")
        if meta_malware:
            return meta_malware

        sig = indicator.raw_metadata.get("signature")
        if sig:
            return sig

        lure = indicator.lure_category or ""
        val = indicator.value.lower()

        if "installer" in val or "setup" in val or lure == "fake_installer":
            if any(ext in val for ext in [".dmg", "mac", "apple"]):
                return "AMOS Stealer"
            return "LummaC2 Stealer"

        if "free" in val or "crack" in val:
            return "Stealc Stealer"

        if indicator.indicator_type in [IndicatorType.PACKAGE_PYPI, IndicatorType.PACKAGE_NPM]:
            return "Trojanized PyPI/npm Dependency"

        return "Unattributed AI Lure"

    def enrich_indicator(self, indicator: RawIndicator) -> EnrichedIndicator:
        """
        Executes end-to-end enrichment on a filtered raw indicator.
        """
        enrichment = EnrichmentData()
        val = indicator.value.strip()

        # Extract hostname if domain or URL
        host = val
        if "://" in val:
            host = val.split("://")[1].split("/")[0]
        else:
            host = val.split("/")[0]

        # 1. DNS & ASN Lookup (for domains/URLs)
        if indicator.indicator_type in [IndicatorType.DOMAIN, IndicatorType.URL]:
            ips = self.dns_enricher.resolve_ips(host)
            enrichment.resolved_ips = ips
            if ips:
                primary_ip = ips[0]
                asn_info = self.dns_enricher.lookup_asn_and_geo(primary_ip)
                enrichment.asn = asn_info.get("asn")
                enrichment.asn_org = asn_info.get("asn_org")
                enrichment.country = asn_info.get("country")

                # Shodan lookup on IP
                shodan_info = self.shodan_enricher.lookup_ip(primary_ip)
                enrichment.shodan_ports = shodan_info.get("ports", [])

            # 2. WHOIS / RDAP lookup
            age_days, reg_date, registrar = self.whois_enricher.lookup_domain_age(host)
            enrichment.domain_age_days = age_days
            enrichment.registration_date = reg_date
            enrichment.registrar = registrar

            # 3. urlscan.io lookup
            urlscan_info = self.urlscan_enricher.search_domain(host)
            enrichment.urlscan_id = urlscan_info.get("urlscan_id")
            enrichment.urlscan_screenshot_url = urlscan_info.get("screenshot_url")
            enrichment.page_title = urlscan_info.get("page_title")
            if urlscan_info.get("has_download"):
                enrichment.has_download_link = True
            if urlscan_info.get("has_login"):
                enrichment.has_login_form = True

            # 4. VirusTotal lookup
            vt_info = self.vt_enricher.lookup_domain(host)
            enrichment.virustotal_detections = vt_info.get("detections", 0)
            enrichment.virustotal_link = vt_info.get("vt_link")

        # 5. Check URL path patterns for download & login indicators
        if any(ext in val.lower() for ext in [".exe", ".msi", ".dmg", ".zip", ".iso", ".rar"]):
            enrichment.has_download_link = True
        if any(w in val.lower() for w in ["/login", "/auth", "/signin", "/account"]):
            enrichment.has_login_form = True

        # Compute Confidence Score
        confidence_score, confidence_level = self.calculate_confidence(indicator, enrichment)

        # Attribute Malware Family
        malware_family = self.attribute_malware(indicator)

        # Assign MITRE ATT&CK techniques
        mitre_techniques = ["T1566.002", "T1036.005"]  # Phishing: Spearphishing Link, Masquerading
        if enrichment.has_download_link or indicator.lure_category == "fake_installer":
            mitre_techniques.append("T1204.002")  # User Execution: Malicious File
        if indicator.indicator_type in [IndicatorType.PACKAGE_PYPI, IndicatorType.PACKAGE_NPM]:
            mitre_techniques.extend(["T1195.001", "T1059.006"])  # Supply Chain, Python Scripting

        # Compile tags
        tags = ["ai-lure", indicator.matched_brand or "ai-brand"]
        if indicator.lure_category:
            tags.append(indicator.lure_category)
        if malware_family and malware_family != "Unattributed AI Lure":
            tags.append(malware_family.lower().replace(" ", "-"))

        enriched = EnrichedIndicator(
            value=indicator.value,
            indicator_type=indicator.indicator_type,
            source=indicator.source,
            target_brand=indicator.matched_brand or "AI Brand",
            lure_type=indicator.lure_category or "brand_impersonation",
            associated_malware=malware_family,
            first_seen=indicator.first_seen,
            confidence_score=confidence_score,
            confidence_level=confidence_level,
            mitre_attack=mitre_techniques,
            enrichment=enrichment,
            tags=tags,
            tlp="TLP:CLEAR"
        )
        return enriched
