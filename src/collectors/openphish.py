"""
AI Lure Tracker - OpenPhish Collector
Pulls active phishing URLs from OpenPhish Community Feed.
"""

from typing import List
import logging
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.openphish")


class OpenPhishCollector(BaseCollector):
    def __init__(self, endpoint: str = "https://openphish.com/feed.txt", timeout: int = 20):
        super().__init__("OpenPhish", timeout)
        self.endpoint = endpoint

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching active feeds from OpenPhish...")
            resp = self.session.get(self.endpoint, timeout=self.timeout)
            resp.raise_for_status()

            lines = resp.text.splitlines()
            for line in lines:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue

                results.append(RawIndicator(
                    value=url,
                    indicator_type=IndicatorType.URL,
                    source="OpenPhish",
                    raw_metadata={"category": "phishing"}
                ))
            logger.info(f"OpenPhish returned {len(results)} indicators.")
        except Exception as e:
            logger.error(f"Failed to fetch from OpenPhish: {e}")
        return results
