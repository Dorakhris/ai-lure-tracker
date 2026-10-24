"""
AI Lure Tracker - CSV and JSON Public Feeds Exporter
Exports consumable threat intelligence feeds for SIEM, SOAR, EDR, and public sharing.
"""

from typing import List
import csv
import json
import os
import logging

from src.models import EnrichedIndicator

logger = logging.getLogger("ai_lure_tracker.storage.feeds")


class FeedExporter:
    def __init__(self, feeds_dir: str = "feeds"):
        self.feeds_dir = feeds_dir
        os.makedirs(feeds_dir, exist_ok=True)

    def export_csv(self, indicators: List[EnrichedIndicator], filename: str = "ai_lures_latest.csv") -> str:
        filepath = os.path.join(self.feeds_dir, filename)
        if not indicators:
            logger.warning("No indicators provided for CSV export.")
            return filepath

        fieldnames = list(indicators[0].to_csv_row().keys())
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ind in indicators:
                writer.writerow(ind.to_csv_row())

        logger.info(f"Exported {len(indicators)} indicators to CSV: {filepath}")
        return filepath

    def export_json(self, indicators: List[EnrichedIndicator], filename: str = "ai_lures_latest.json") -> str:
        filepath = os.path.join(self.feeds_dir, filename)
        data = [ind.to_dict() for ind in indicators]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported {len(indicators)} indicators to JSON: {filepath}")
        return filepath
