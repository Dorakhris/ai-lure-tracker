"""
AI Lure Tracker - Base Collector
Standard interface for threat feed ingestion and real-time streams.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.models import RawIndicator

logger = logging.getLogger("ai_lure_tracker.collectors")


class BaseCollector(ABC):
    def __init__(self, name: str, timeout: int = 15):
        self.name = name
        self.timeout = timeout
        self.session = self._create_resilient_session()

    def _create_resilient_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "AILureTracker-CTI/1.0 (+https://github.com/ai-lure-tracker)"
        })
        return session

    @abstractmethod
    def collect(self) -> List[RawIndicator]:
        """Collect and return a list of raw indicators."""
        pass
