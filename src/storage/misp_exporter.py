"""
AI Lure Tracker - Local MISP Integration Exporter
Syncs enriched AI lure indicators into a local or remote MISP instance via REST API.
"""

from typing import List, Dict, Any, Optional
import os
import requests
import logging

from src.models import EnrichedIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.storage.misp")


class MISPExporter:
    def __init__(
        self,
        misp_url: Optional[str] = None,
        auth_key: Optional[str] = None,
        verify_ssl: bool = False
    ):
        self.misp_url = (misp_url or os.getenv("MISP_URL", "https://localhost:8443")).rstrip("/")
        self.auth_key = auth_key or os.getenv("MISP_KEY", "")
        self.verify_ssl = verify_ssl

    def test_connection(self) -> bool:
        if not self.auth_key:
            return False
        try:
            url = f"{self.misp_url}/servers/getVersion.json"
            headers = {"Authorization": self.auth_key, "Accept": "application/json"}
            resp = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def push_event(self, indicators: List[EnrichedIndicator], event_info: str = "AI Lure Tracker Campaign Feed") -> Optional[str]:
        """
        Creates a MISP Event and adds all enriched indicators as attributes with tags.
        """
        if not self.auth_key:
            logger.warning("MISP_KEY not set. Skipping export to MISP.")
            return None

        headers = {
            "Authorization": self.auth_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # Create Event
        event_payload = {
            "Event": {
                "info": event_info,
                "distribution": "0",  # Your organisation only
                "threat_level_id": "2",  # Medium / High
                "analysis": "1",  # Ongoing
                "Tag": [
                    {"name": "ai-lure"},
                    {"name": "brand-impersonation"},
                    {"name": "phishing"}
                ]
            }
        }

        try:
            create_url = f"{self.misp_url}/events/add"
            resp = requests.post(create_url, json=event_payload, headers=headers, verify=self.verify_ssl, timeout=10)
            if resp.status_code not in [200, 201]:
                logger.error(f"Failed to create MISP event: {resp.status_code} - {resp.text}")
                return None

            event_id = resp.json().get("Event", {}).get("id")
            logger.info(f"Created MISP Event #{event_id}. Adding attributes...")

            # Add Attributes
            for ind in indicators:
                attr_type = "domain"
                if ind.indicator_type == IndicatorType.URL:
                    attr_type = "url"
                elif ind.indicator_type == IndicatorType.IP:
                    attr_type = "ip-dst"
                elif ind.indicator_type == IndicatorType.HASH_SHA256:
                    attr_type = "sha256"

                attr_payload = {
                    "type": attr_type,
                    "value": ind.value,
                    "category": "Network activity" if attr_type != "sha256" else "Payload delivery",
                    "to_ids": True,
                    "comment": f"AI Lure targeting {ind.target_brand}. Confidence: {ind.confidence_score}%",
                    "Tag": [{"name": f"brand:{ind.target_brand}"}, {"name": f"confidence:{ind.confidence_level.value}"}]
                }
                attr_url = f"{self.misp_url}/attributes/add/{event_id}"
                requests.post(attr_url, json=attr_payload, headers=headers, verify=self.verify_ssl, timeout=5)

            logger.info(f"Successfully synced {len(indicators)} indicators to MISP Event #{event_id}")
            return str(event_id)
        except Exception as e:
            logger.error(f"MISP export error: {e}")
            return None
