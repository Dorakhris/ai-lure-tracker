"""
AI Lure Tracker - Brand & Lure Filter Engine
Filters raw indicators to isolate malicious AI-themed infrastructure and packages.
"""

from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import re
import idna
import logging

from src.models import RawIndicator, IndicatorType
from src.filters.whitelist import DomainWhitelist
from src.filters.typosquat_detector import TyposquatDetector, damerau_levenshtein_distance

logger = logging.getLogger("ai_lure_tracker.filters.brand_matcher")


class BrandMatcher:
    def __init__(self, targets_config: Dict[str, Any]):
        self.config = targets_config
        self.brands = targets_config.get("brands", {})
        self.allowlist_domains = targets_config.get("allowlist_domains", [])
        self.whitelist = DomainWhitelist(self.allowlist_domains)

        # Extract target packages
        targeted_pkgs_cfg = targets_config.get("targeted_packages", [])
        self.target_packages = [p.get("name") for p in targeted_pkgs_cfg if "name" in p]
        self.typosquat_detector = TyposquatDetector(self.target_packages, max_distance=2)

        # Lure keyword heuristics
        self.installer_keywords = {"download", "installer", "setup", "desktop", "win", "windows", "mac", "pc", "exe", "dmg", "pkg", "client"}
        self.login_keywords = {"login", "signin", "auth", "account", "verify", "portal", "session"}
        self.free_crack_keywords = {"free", "crack", "keygen", "unlimited", "plus-free", "pro-free", "token-gen"}

    @staticmethod
    def extract_domain_and_path(value: str) -> Tuple[str, str]:
        """
        Extracts host and path component from URL or domain string.
        Handles IDN/punycode decoding (e.g., xn--... -> unicode).
        """
        val = value.strip().lower()
        if "://" in val:
            parsed = urlparse(val)
            host = parsed.netloc.split(":")[0]
            path = parsed.path
        else:
            parts = val.split("/", 1)
            host = parts[0].split(":")[0]
            path = "/" + parts[1] if len(parts) > 1 else ""

        # Decode punycode if present
        try:
            if "xn--" in host:
                host = idna.decode(host)
        except Exception:
            pass

        return host, path

    def classify_lure_category(self, target_str: str) -> str:
        tokens = set(re.split(r"[-_./\s\d]+", target_str.lower()))
        if tokens & self.installer_keywords or any(ext in target_str for ext in [".exe", ".msi", ".dmg", ".zip", ".iso"]):
            return "fake_installer"
        if tokens & self.login_keywords:
            return "credential_phish"
        if tokens & self.free_crack_keywords:
            return "free_token_lure"
        return "brand_impersonation"

    def match_brand(self, text: str) -> Optional[Tuple[str, str]]:
        """
        Scans string against brand keywords using strict boundary matching.
        Suppresses false positives like painters (Claude Monet), Polish words (bardzo),
        and universities (Claude Bernard).
        """
        text_clean = text.lower()

        # False positive exclusions
        ignored_claude_contexts = ["monet", "lorrain", "bernard", "claude-carre", "procedes georges claude"]
        if any(ign in text_clean for ign in ignored_claude_contexts):
            return None

        # Exclude Polish words like 'bardzo'
        if "bardzo" in text_clean:
            return None

        for brand_key, brand_info in self.brands.items():
            keywords = brand_info.get("keywords", [])
            for kw in keywords:
                kw_clean = kw.lower()

                # For very short or generic keywords (e.g. 'bard', 'agent'), require explicit delimiter
                if kw_clean == "bard":
                    pattern = r"(^|[^a-z0-9])(google-bard|bard-ai|bard-bot)([^a-z0-9]|$)"
                elif len(kw_clean) <= 4:
                    pattern = r"(^|[^a-z0-9])" + re.escape(kw_clean) + r"([^a-z0-9]|$)"
                else:
                    pattern = r"(^|[^a-z0-9])" + re.escape(kw_clean) + r"([^a-z0-9]|$)"

                if re.search(pattern, text_clean):
                    return (brand_key, kw)
        return None

    def filter_indicator(self, indicator: RawIndicator) -> Optional[RawIndicator]:
        """
        Evaluates a raw indicator.
        Returns the enriched RawIndicator with brand and category if matched and non-whitelisted,
        or None if irrelevant or false positive.
        """
        val = indicator.value.strip()

        # 1. Package Filtering (PyPI / npm)
        if indicator.indicator_type in [IndicatorType.PACKAGE_PYPI, IndicatorType.PACKAGE_NPM]:
            # Exact match is legitimate package
            if val.lower() in self.target_packages:
                return None

            typo_match = self.typosquat_detector.check_package_typosquat(val)
            if typo_match:
                target_lib, dist = typo_match
                indicator.matched_brand = "ai_ecosystem_library"
                indicator.matched_keyword = target_lib
                indicator.lure_category = "typosquat_dependency"
                indicator.raw_metadata["target_library"] = target_lib
                indicator.raw_metadata["levenshtein_distance"] = dist
                return indicator

            # Check if package name contains AI brand keyword
            brand_match = self.match_brand(val)
            if brand_match:
                brand_key, kw = brand_match
                indicator.matched_brand = brand_key
                indicator.matched_keyword = kw
                indicator.lure_category = "lookalike_package"
                return indicator

            return None

        # 2. Hash Filtering (MalwareBazaar)
        if indicator.indicator_type in [IndicatorType.HASH_SHA256, IndicatorType.HASH_MD5]:
            file_name = indicator.raw_metadata.get("file_name", "")
            tags = indicator.raw_metadata.get("tags", [])
            tag_str = " ".join(tags)
            haystack = f"{file_name} {tag_str}"

            brand_match = self.match_brand(haystack)
            if brand_match:
                brand_key, kw = brand_match
                indicator.matched_brand = brand_key
                indicator.matched_keyword = kw
                indicator.lure_category = self.classify_lure_category(haystack)
                return indicator
            return None

        # 3. Domain and URL Filtering
        host, path = self.extract_domain_and_path(val)
        if not host or " " in host or "." not in host:
            return None

        # False positive suppression
        if self.whitelist.is_whitelisted(host):
            return None

        full_target_str = f"{host}{path}"
        brand_match = self.match_brand(full_target_str)

        if brand_match:
            brand_key, kw = brand_match
            indicator.matched_brand = brand_key
            indicator.matched_keyword = kw
            indicator.lure_category = self.classify_lure_category(full_target_str)
            return indicator

        # Check domain typosquats against popular brands (e.g. 'chatgppt.com' or 'oepnai.com')
        domain_labels = host.split(".")
        sld = domain_labels[-2] if len(domain_labels) >= 2 else domain_labels[0]
        for brand_key, brand_info in self.brands.items():
            for kw in brand_info.get("keywords", []):
                if len(kw) >= 5:
                    dist = damerau_levenshtein_distance(sld, kw.lower())
                    if dist == 1:
                        indicator.matched_brand = brand_key
                        indicator.matched_keyword = kw
                        indicator.lure_category = "typosquat_domain"
                        indicator.raw_metadata["levenshtein_distance"] = dist
                        return indicator

        return None

    def filter_batch(self, indicators: List[RawIndicator]) -> List[RawIndicator]:
        """Filters a list of raw indicators, returning only matched AI lures."""
        matched: List[RawIndicator] = []
        for ind in indicators:
            filtered = self.filter_indicator(ind)
            if filtered:
                matched.append(filtered)
        return matched
