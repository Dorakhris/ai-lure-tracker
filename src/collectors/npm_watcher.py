"""
AI Lure Tracker - npm Package Watcher
Monitors newly published or modified npm packages for typosquats of popular AI libraries.
"""

from typing import List
import logging
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.npm")


class NPMWatcher(BaseCollector):
    def __init__(
        self,
        changes_url: str = "https://replicate.npmjs.com/_changes?descending=true&limit=100",
        timeout: int = 15
    ):
        super().__init__("NPMWatcher", timeout)
        self.changes_url = changes_url

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching recent changes from npm replicate registry...")
            resp = self.session.get(self.changes_url, timeout=self.timeout)
            resp.raise_for_status()

            data = resp.json()
            rows = data.get("results", [])
            for row in rows:
                pkg_id = row.get("id", "")
                # Ignore design docs and system documents
                if not pkg_id or pkg_id.startswith("_design/"):
                    continue

                seq = row.get("seq")
                deleted = row.get("deleted", False)
                if deleted:
                    continue

                results.append(RawIndicator(
                    value=pkg_id,
                    indicator_type=IndicatorType.PACKAGE_NPM,
                    source="npm",
                    raw_metadata={
                        "seq": seq,
                        "url": f"https://www.npmjs.com/package/{pkg_id}"
                    }
                ))
            logger.info(f"NPMWatcher returned {len(results)} package entries.")
        except Exception as e:
            logger.error(f"Failed to fetch npm changes: {e}")
        return results
