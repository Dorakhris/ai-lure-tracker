"""
AI Lure Tracker - Certificate Transparency Monitor (CertStream & crt.sh)
Monitors newly issued SSL/TLS certificates for domains containing AI brand names and lures.
"""

import asyncio
import json
import logging
from typing import List, Generator, Optional, Callable
import websockets
from src.collectors.base import BaseCollector
from src.models import RawIndicator, IndicatorType

logger = logging.getLogger("ai_lure_tracker.collectors.certstream")


class CertStreamCollector(BaseCollector):
    def __init__(
        self,
        websocket_url: str = "wss://certstream.calidog.io",
        timeout: int = 15,
        reconnect_delay: int = 5
    ):
        super().__init__("CertStream", timeout)
        self.websocket_url = websocket_url
        self.reconnect_delay = reconnect_delay

    def collect_batch_crtsh(self, query: str = "%chatgpt%") -> List[RawIndicator]:
        """
        Queries crt.sh JSON API for historical/recent certificates matching an AI brand pattern.
        Provides on-demand CT log search without waiting for live stream messages.
        """
        results: List[RawIndicator] = []
        try:
            logger.info(f"Querying crt.sh for '{query}'...")
            url = f"https://crt.sh/?q={query}&output=json"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"crt.sh returned status {resp.status_code}")
                return results

            entries = resp.json()
            seen_domains = set()
            for entry in entries[:200]:  # limit batch size
                name_value = entry.get("name_value", "")
                domains = name_value.split("\n")
                for d in domains:
                    d = d.strip().lower()
                    if d.startswith("*."):
                        d = d[2:]
                    if d and d not in seen_domains:
                        seen_domains.add(d)
                        results.append(RawIndicator(
                            value=d,
                            indicator_type=IndicatorType.DOMAIN,
                            source="crt.sh",
                            raw_metadata={
                                "issuer_name": entry.get("issuer_name"),
                                "not_before": entry.get("not_before"),
                                "id": entry.get("id")
                            }
                        ))
            logger.info(f"crt.sh returned {len(results)} domain candidates for '{query}'.")
        except Exception as e:
            logger.error(f"crt.sh lookup error: {e}")
        return results

    async def stream_certificates(
        self,
        callback: Callable[[RawIndicator], None],
        max_messages: Optional[int] = None
    ):
        """
        Connects to the CertStream websocket and yields newly issued certificates.
        """
        count = 0
        logger.info(f"Connecting to CertStream websocket: {self.websocket_url}...")
        while True:
            try:
                async with websockets.connect(self.websocket_url, ping_interval=20, ping_timeout=20) as ws:
                    logger.info("Connected to CertStream live feed.")
                    async for message in ws:
                        data = json.loads(message)
                        msg_type = data.get("message_type")
                        if msg_type == "certificate_update":
                            cert_data = data.get("data", {})
                            leaf_cert = cert_data.get("leaf_cert", {})
                            all_domains = leaf_cert.get("all_domains", [])
                            source = cert_data.get("source", {}).get("name", "CertStream")

                            for domain in all_domains:
                                domain = domain.strip().lower()
                                if domain.startswith("*."):
                                    domain = domain[2:]

                                ind = RawIndicator(
                                    value=domain,
                                    indicator_type=IndicatorType.DOMAIN,
                                    source="CertStream",
                                    raw_metadata={
                                        "issuer": leaf_cert.get("issuer"),
                                        "not_before": leaf_cert.get("not_before"),
                                        "ct_source": source
                                    }
                                )
                                callback(ind)

                            count += 1
                            if max_messages and count >= max_messages:
                                logger.info(f"Reached max stream message limit ({max_messages}). Stopping.")
                                return

            except (websockets.ConnectionClosedError, websockets.ConnectionClosedOK) as e:
                logger.warning(f"CertStream connection closed: {e}. Reconnecting in {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)
            except Exception as e:
                logger.error(f"CertStream stream exception: {e}. Reconnecting in {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)

    def collect(self) -> List[RawIndicator]:
        """Default batch collection using crt.sh popular AI brand queries."""
        all_results = []
        queries = ["%chatgpt%", "%claude%", "%gemini%", "%copilot%", "%deepseek%"]
        for q in queries:
            items = self.collect_batch_crtsh(q)
            all_results.extend(items)
        return all_results
