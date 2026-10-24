"""
AI Lure Tracker - Shodan Enrichment
Queries Shodan free-tier API for open ports, web banners, and exposed services.
"""

from typing import Dict, Any, List, Optional
import os
import requests
import logging

logger = logging.getLogger("ai_lure_tracker.enrichment.shodan")


class ShodanEnricher:
    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.timeout = timeout

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        info = {
            "ports": [],
            "vulns": [],
            "tags": [],
            "os": None
        }

        if not self.api_key or not ip:
            return info

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                info["ports"] = data.get("ports", [])
                info["vulns"] = list(data.get("vulns", {}).keys())
                info["tags"] = data.get("tags", [])
                info["os"] = data.get("os")
        except Exception as e:
            logger.debug(f"Shodan lookup error for {ip}: {e}")

        return info
