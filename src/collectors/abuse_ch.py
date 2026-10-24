"""
AI Lure Tracker - Abuse.ch Collector
Ingests feeds from URLhaus, ThreatFox, and MalwareBazaar.
"""

from typing import List
import logging
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.abuse_ch")


class URLhausCollector(BaseCollector):
    def __init__(self, endpoint: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout: int = 20):
        super().__init__("URLhaus", timeout)
        self.endpoint = endpoint

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching recent URLs from URLhaus...")
            resp = self.session.get(self.endpoint, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            urls = data.get("urls", [])

            for entry in urls:
                url = entry.get("url")
                if not url:
                    continue
                results.append(RawIndicator(
                    value=url,
                    indicator_type=IndicatorType.URL,
                    source="URLhaus",
                    raw_metadata={
                        "url_status": entry.get("url_status"),
                        "threat": entry.get("threat"),
                        "tags": entry.get("tags") or [],
                        "reporter": entry.get("reporter"),
                        "date_added": entry.get("date_added")
                    }
                ))
            logger.info(f"URLhaus returned {len(results)} raw indicators.")
        except Exception as e:
            logger.error(f"Failed to fetch from URLhaus: {e}")
        return results


class ThreatFoxCollector(BaseCollector):
    def __init__(self, endpoint: str = "https://threatfox-api.abuse.ch/v1/", timeout: int = 20):
        super().__init__("ThreatFox", timeout)
        self.endpoint = endpoint

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching recent IOCs from ThreatFox...")
            payload = {"query": "get_iocs", "days": 3}
            resp = self.session.post(self.endpoint, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") != "ok":
                logger.warning(f"ThreatFox returned status: {data.get('query_status')}")
                return results

            iocs = data.get("data", [])
            for item in iocs:
                ioc_value = item.get("ioc_value")
                ioc_type = item.get("ioc_type")
                if not ioc_value:
                    continue

                ind_type = IndicatorType.DOMAIN
                if ioc_type in ["url", "payload_delivery"]:
                    ind_type = IndicatorType.URL
                elif ioc_type in ["ip:port", "ip"]:
                    ind_type = IndicatorType.IP

                results.append(RawIndicator(
                    value=ioc_value,
                    indicator_type=ind_type,
                    source="ThreatFox",
                    raw_metadata={
                        "threat_type": item.get("threat_type"),
                        "threat_type_desc": item.get("threat_type_desc"),
                        "ioc_type": ioc_type,
                        "malware": item.get("malware_printable"),
                        "malware_alias": item.get("malware_alias"),
                        "confidence_level": item.get("confidence_level"),
                        "tags": item.get("tags") or []
                    }
                ))
            logger.info(f"ThreatFox returned {len(results)} raw indicators.")
        except Exception as e:
            logger.error(f"Failed to fetch from ThreatFox: {e}")
        return results


class MalwareBazaarCollector(BaseCollector):
    def __init__(self, endpoint: str = "https://mb-api.abuse.ch/api/v1/", timeout: int = 20):
        super().__init__("MalwareBazaar", timeout)
        self.endpoint = endpoint

    def collect(self) -> List[RawIndicator]:
        results: List[RawIndicator] = []
        try:
            logger.info("Fetching recent samples from MalwareBazaar...")
            payload = {"query": "get_recent", "selector": "time"}
            resp = self.session.post(self.endpoint, data=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") != "ok":
                logger.warning(f"MalwareBazaar query status: {data.get('query_status')}")
                return results

            samples = data.get("data", [])
            for s in samples:
                sha256 = s.get("sha256_hash")
                file_name = s.get("file_name", "")
                signature = s.get("signature")
                tags = s.get("tags") or []

                if not sha256:
                    continue

                results.append(RawIndicator(
                    value=sha256,
                    indicator_type=IndicatorType.HASH_SHA256,
                    source="MalwareBazaar",
                    raw_metadata={
                        "file_name": file_name,
                        "file_type": s.get("file_type"),
                        "file_size": s.get("file_size"),
                        "signature": signature,
                        "delivery_method": s.get("delivery_method"),
                        "tags": tags
                    }
                ))
            logger.info(f"MalwareBazaar returned {len(results)} raw indicators.")
        except Exception as e:
            logger.error(f"Failed to fetch from MalwareBazaar: {e}")
        return results
