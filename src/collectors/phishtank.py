"""
AI Lure Tracker - PhishTank Collector
Pulls active phishing URLs from PhishTank.
"""

from typing import List
import logging
import json
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.phishtank")


class PhishTankCollector(BaseCollector):
    def __init__(self, endpoint: str = "http://data.phishtank.com/data/online-valid.json", timeout: int = 30):
        super().__init__("PhishTank", timeout)
        self.endpoint = endpoint

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching verified feeds from PhishTank...")
            resp = self.session.get(self.endpoint, timeout=self.timeout)
            resp.raise_for_status()

            data = resp.json()
            for item in data:
                url = item.get("url")
                if not url:
                    continue

                target = item.get("target")
                phish_id = item.get("phish_id")
                verified = item.get("verified")

                results.append(RawIndicator(
                    value=url,
                    indicator_type=IndicatorType.URL,
                    source="PhishTank",
                    raw_metadata={
                        "phish_id": phish_id,
                        "phish_target": target,
                        "verified": verified,
                        "submission_time": item.get("submission_time")
                    }
                ))
            logger.info(f"PhishTank returned {len(results)} indicators.")
        except Exception as e:
            logger.error(f"Failed to fetch from PhishTank: {e}")
        return results
