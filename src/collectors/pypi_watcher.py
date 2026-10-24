"""
AI Lure Tracker - PyPI Package Watcher
Monitors newly created and updated PyPI packages for typosquats of AI libraries.
"""

from typing import List
import logging
import feedparser
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.pypi")


class PyPIWatcher(BaseCollector):
    def __init__(
        self,
        new_packages_url: str = "https://pypi.org/rss/packages.xml",
        updates_url: str = "https://pypi.org/rss/updates.xml",
        timeout: int = 15
    ):
        super().__init__("PyPIWatcher", timeout)
        self.new_packages_url = new_packages_url
        self.updates_url = updates_url

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        for url in [self.new_packages_url, self.updates_url]:
            try:
                logger.info(f"Parsing PyPI RSS feed from {url}...")
                resp = self.session.get(url, timeout=self.timeout)
                resp.raise_for_status()

                feed = feedparser.parse(resp.content)
                for entry in feed.entries:
                    raw_title = entry.get("title", "")
                    # PyPI RSS titles are usually "package_name 1.0.0"
                    pkg_name = raw_title.split(" ")[0].strip() if raw_title else ""
                    if not pkg_name:
                        continue

                    link = entry.get("link", f"https://pypi.org/project/{pkg_name}/")
                    desc = entry.get("summary", "")
                    pub_date = entry.get("published", "")

                    results.append(RawIndicator(
                        value=pkg_name,
                        indicator_type=IndicatorType.PACKAGE_PYPI,
                        source="PyPI",
                        raw_metadata={
                            "url": link,
                            "summary": desc,
                            "published": pub_date
                        }
                    ))
            except Exception as e:
                logger.error(f"Failed to fetch PyPI feed {url}: {e}")

        logger.info(f"PyPIWatcher returned {len(results)} package entries.")
        return results
