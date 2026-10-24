"""
AI Lure Tracker - Whitelist & False Positive Suppression
Ensures legitimate brand domains and reputable services are not flagged as malicious lures.
"""

from typing import List, Set
from urllib.parse import urlparse
import logging

logger = logging.getLogger("ai_lure_tracker.filters.whitelist")


class DomainWhitelist:
    def __init__(self, allowed_domains: List[str]):
        self.allowed_domains: Set[str] = {d.lower().strip() for d in allowed_domains if d.strip()}

    @staticmethod
    def extract_root_domain(netloc: str) -> str:
        """
        Extracts the host without port and strips leading www.
        """
        host = netloc.split(":")[0].lower().strip()
        if host.startswith("www."):
            host = host[4:]
        return host

    def is_whitelisted(self, indicator_value: str) -> bool:
        """
        Checks whether the indicator corresponds to an authentic, whitelisted domain or sub-domain.
        Strict suffix matching ensures 'openai.com' matches 'api.openai.com',
        but NOT 'openai.com.malicious-site.top' or 'fake-openai.com'.
        """
        candidate = indicator_value.lower().strip()
        if "://" in candidate:
            parsed = urlparse(candidate)
            host = self.extract_root_domain(parsed.netloc)
        else:
            host = self.extract_root_domain(candidate.split("/")[0])

        if not host:
            return False

        if host in self.allowed_domains:
            return True

        for allowed in self.allowed_domains:
            if host.endswith("." + allowed):
                return True

        return False
