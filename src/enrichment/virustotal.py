"""
AI Lure Tracker - VirusTotal v3 Enrichment
Queries VirusTotal for detection ratios, category verdicts, and community flags.
"""

from typing import Dict, Any, Optional
import os
import requests
import logging

logger = logging.getLogger("ai_lure_tracker.enrichment.virustotal")


class VirusTotalEnricher:
    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Queries VirusTotal v3 domain API.
        """
        info = {
            "detections": 0,
            "total_engines": 0,
            "malicious_votes": 0,
            "categories": [],
            "vt_link": None
        }

        if not self.api_key:
            return info

        dom = domain.lower().strip()
        if "://" in dom:
            dom = dom.split("://")[1].split("/")[0]
        else:
            dom = dom.split("/")[0]

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{dom}"
            headers = {"x-apikey": self.api_key}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                info["detections"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
                info["total_engines"] = sum(stats.values())
                info["vt_link"] = f"https://www.virustotal.com/gui/domain/{dom}"
                categories = attrs.get("categories", {})
                info["categories"] = list(set(categories.values()))
        except Exception as e:
            logger.debug(f"VirusTotal lookup error for {dom}: {e}")

        return info
