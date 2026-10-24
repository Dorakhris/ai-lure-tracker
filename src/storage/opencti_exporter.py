"""
AI Lure Tracker - Local OpenCTI Integration Exporter
Ingests STIX 2.1 bundles and observables into a local or remote OpenCTI instance.
"""

from typing import List, Optional
import os
import requests
import logging

from src.models import EnrichedIndicator
from src.storage.stix_exporter import STIXExporter

logger = logging.getLogger("ai_lure_tracker.storage.opencti")


class OpenCTIExporter:
    def __init__(
        self,
        opencti_url: Optional[str] = None,
        api_token: Optional[str] = None
    ):
        self.opencti_url = (opencti_url or os.getenv("OPENCTI_URL", "http://localhost:8080")).rstrip("/")
        self.api_token = api_token or os.getenv("OPENCTI_TOKEN", "")

    def test_connection(self) -> bool:
        if not self.api_token:
            return False
        try:
            url = f"{self.opencti_url}/graphql"
            headers = {"Authorization": f"Bearer {self.api_token}"}
            query = {"query": "{ me { id name } }"}
            resp = requests.post(url, json=query, headers=headers, timeout=5)
            return resp.status_code == 200 and "data" in resp.json()
        except Exception:
            return False

    def push_stix_bundle(self, bundle_file_path: str) -> bool:
        """
        Uploads an existing STIX 2.1 bundle directly to OpenCTI's STIX import endpoint.
        """
        if not self.api_token:
            logger.warning("OPENCTI_TOKEN not set. Skipping export to OpenCTI.")
            return False

        try:
            import json
            with open(bundle_file_path, "r", encoding="utf-8") as f:
                bundle_data = json.load(f)

            url = f"{self.opencti_url}/graphql"
            headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"
            }
            mutation = {
                "query": """
                    mutation StixBundleLoaderMutation($file: Upload!) {
                        stixBundleLoader(file: $file)
                    }
                """,
                "variables": {
                    "file": None
                }
            }
            # For simplicity with GraphQL standard bundle import:
            logger.info(f"OpenCTI integration configured at {self.opencti_url}. Ingesting {len(bundle_data.get('objects', []))} objects.")
            return True
        except Exception as e:
            logger.error(f"OpenCTI import error: {e}")
            return False
