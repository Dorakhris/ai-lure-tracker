"""
AI Lure Tracker - SQLite Threat Storage
Provides persistent state, deduplication, and historical query capabilities for indicators.
"""

from typing import List, Optional, Dict, Any
import sqlite3
import json
import os
import logging
from datetime import datetime, timezone

from src.models import (
    EnrichedIndicator,
    EnrichmentData,
    IndicatorType,
    ConfidenceLevel
)

logger = logging.getLogger("ai_lure_tracker.storage.database")


class ThreatDatabase:
    def __init__(self, db_path: str = "data/ai_lures.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id TEXT PRIMARY KEY,
                    value TEXT UNIQUE,
                    indicator_type TEXT,
                    source TEXT,
                    target_brand TEXT,
                    lure_type TEXT,
                    associated_malware TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    confidence_score INTEGER,
                    confidence_level TEXT,
                    mitre_attack TEXT,
                    tags TEXT,
                    tlp TEXT,
                    enrichment_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators (value);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_brand ON indicators (target_brand);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_conf ON indicators (confidence_score);")
            conn.commit()

    def insert_or_update(self, item: EnrichedIndicator) -> bool:
        """
        Inserts a new enriched indicator or updates last_seen and enrichment if already exists.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            existing = conn.execute("SELECT id, first_seen, confidence_score FROM indicators WHERE value = ?", (item.value,)).fetchone()
            if existing:
                # Update last seen and boost confidence if re-observed
                new_conf = max(existing["confidence_score"], item.confidence_score)
                conn.execute("""
                    UPDATE indicators SET
                        last_seen = ?,
                        confidence_score = ?,
                        confidence_level = ?,
                        enrichment_json = ?
                    WHERE value = ?
                """, (
                    now_str,
                    new_conf,
                    item.confidence_level.value,
                    json.dumps(item.enrichment.__dict__),
                    item.value
                ))
            else:
                conn.execute("""
                    INSERT INTO indicators (
                        id, value, indicator_type, source, target_brand, lure_type,
                        associated_malware, first_seen, last_seen, confidence_score,
                        confidence_level, mitre_attack, tags, tlp, enrichment_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    item.id,
                    item.value,
                    item.indicator_type.value,
                    item.source,
                    item.target_brand,
                    item.lure_type,
                    item.associated_malware,
                    item.first_seen,
                    now_str,
                    item.confidence_score,
                    item.confidence_level.value,
                    json.dumps(item.mitre_attack),
                    json.dumps(item.tags),
                    item.tlp,
                    json.dumps(item.enrichment.__dict__)
                ))
            conn.commit()
        return True

    def get_all(self, min_confidence: int = 0) -> List[EnrichedIndicator]:
        results: List[EnrichedIndicator] = []
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM indicators WHERE confidence_score >= ? ORDER BY confidence_score DESC, last_seen DESC",
                (min_confidence,)
            ).fetchall()
            for r in rows:
                enr_dict = json.loads(r["enrichment_json"]) if r["enrichment_json"] else {}
                enr = EnrichmentData(**enr_dict)
                item = EnrichedIndicator(
                    id=r["id"],
                    value=r["value"],
                    indicator_type=IndicatorType(r["indicator_type"]),
                    source=r["source"],
                    target_brand=r["target_brand"],
                    lure_type=r["lure_type"],
                    associated_malware=r["associated_malware"],
                    first_seen=r["first_seen"],
                    last_seen=r["last_seen"],
                    confidence_score=r["confidence_score"],
                    confidence_level=ConfidenceLevel(r["confidence_level"]),
                    mitre_attack=json.loads(r["mitre_attack"]) if r["mitre_attack"] else [],
                    tags=json.loads(r["tags"]) if r["tags"] else [],
                    tlp=r["tlp"],
                    enrichment=enr
                )
                results.append(item)
        return results

    def get_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            high_conf = conn.execute("SELECT COUNT(*) FROM indicators WHERE confidence_level = 'high'").fetchone()[0]
            by_brand = dict(conn.execute("SELECT target_brand, COUNT(*) FROM indicators GROUP BY target_brand").fetchall())
            by_lure = dict(conn.execute("SELECT lure_type, COUNT(*) FROM indicators GROUP BY lure_type").fetchall())
            by_malware = dict(conn.execute("SELECT associated_malware, COUNT(*) FROM indicators WHERE associated_malware IS NOT NULL GROUP BY associated_malware").fetchall())
        return {
            "total_indicators": total,
            "high_confidence_count": high_conf,
            "by_brand": by_brand,
            "by_lure": by_lure,
            "by_malware": by_malware
        }
