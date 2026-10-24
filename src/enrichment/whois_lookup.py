"""
AI Lure Tracker - WHOIS & RDAP Domain Age Enrichment
Queries RDAP/WHOIS endpoints to compute domain registration date, registrar, and age in days.
"""

from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timezone
from dateutil import parser as date_parser
import requests
import logging

logger = logging.getLogger("ai_lure_tracker.enrichment.whois")


class WhoisEnricher:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self._cache: Dict[str, Tuple[Optional[int], Optional[str], Optional[str]]] = {}

    def lookup_domain_age(self, domain: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Looks up domain registration date and registrar via RDAP (ICANN standard).
        Returns: (age_in_days, registration_date_iso, registrar_name)
        """
        # Clean domain
        dom = domain.lower().strip()
        if "://" in dom:
            dom = dom.split("://")[1].split("/")[0]
        else:
            dom = dom.split("/")[0]

        # Extract root domain (e.g. sub.domain.top -> domain.top)
        labels = dom.split(".")
        if len(labels) > 2:
            dom = f"{labels[-2]}.{labels[-1]}"

        if dom in self._cache:
            return self._cache[dom]

        age_days = None
        reg_date_str = None
        registrar = None

        try:
            # Query ICANN RDAP bootstrap redirector
            rdap_url = f"https://rdap.org/domain/{dom}"
            resp = requests.get(rdap_url, timeout=self.timeout, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                for ev in events:
                    if ev.get("eventAction") in ["registration", "created"]:
                        raw_date = ev.get("eventDate")
                        if raw_date:
                            dt = date_parser.parse(raw_date)
                            now = datetime.now(timezone.utc)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            age_days = max(0, (now - dt).days)
                            reg_date_str = dt.isoformat()
                            break

                # Extract registrar
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar = prop[3]
                                    break
                        if not registrar:
                            registrar = ent.get("handle")
        except Exception as e:
            logger.debug(f"RDAP lookup error for {dom}: {e}")

        result = (age_days, reg_date_str, registrar)
        self._cache[dom] = result
        return result
