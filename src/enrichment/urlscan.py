"""
AI Lure Tracker - urlscan.io Enrichment
Queries urlscan.io for existing scans and page characteristics (screenshots, titles, downloads, login forms).
"""

from typing import Dict, Any, Optional
import os
import requests
import logging

logger = logging.getLogger("ai_lure_tracker.enrichment.urlscan")


class UrlscanEnricher:
    def __init__(self, api_key: Optional[str] = None, timeout: float = 6.0):
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")
        self.timeout = timeout
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"API-Key": self.api_key})

    def search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Searches urlscan.io for recent scans of the target domain.
        Extracts scan ID, screenshot URL, page title, and potential download or login lures.
        """
        info = {
            "urlscan_id": None,
            "urlscan_url": None,
            "screenshot_url": None,
            "page_title": None,
            "has_download": False,
            "has_login": False,
            "malicious": False
        }

        dom = domain.lower().strip()
        if "://" in dom:
            dom = dom.split("://")[1].split("/")[0]
        else:
            dom = dom.split("/")[0]

        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{dom}&size=1"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    hit = results[0]
                    task_id = hit.get("_id")
                    page = hit.get("page", {})
                    stats = hit.get("stats", {})

                    info["urlscan_id"] = task_id
                    info["urlscan_url"] = hit.get("result")
                    info["screenshot_url"] = hit.get("screenshot")
                    info["page_title"] = page.get("title")

                    # Check for malware/phishing verdicts in urlscan verdicts
                    verdicts = hit.get("verdicts", {}).get("overall", {})
                    if verdicts.get("malicious"):
                        info["malicious"] = True

                    # Check title or URL for installer / login keywords
                    title = (info["page_title"] or "").lower()
                    if any(w in title for w in ["installer", "download", "setup", "get chatgpt", "install claude"]):
                        info["has_download"] = True
                    if any(w in title for w in ["login", "sign in", "authentication", "account access"]):
                        info["has_login"] = True

        except Exception as e:
            logger.debug(f"urlscan.io query error for {dom}: {e}")

        return info
