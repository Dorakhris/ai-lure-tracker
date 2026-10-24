"""
AI Lure Tracker - DNS, ASN, and GeoIP Enrichment
Resolves IP addresses, ASNs, hosting providers, and geographic location.
"""

from typing import List, Optional, Tuple, Dict, Any
import socket
import logging
import requests
import dns.resolver

logger = logging.getLogger("ai_lure_tracker.enrichment.dns_asn")


class DNSASNEnricher:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self._cache: Dict[str, Dict[str, Any]] = {}

    def resolve_ips(self, hostname: str) -> List[str]:
        """Resolves IPv4 addresses for a given hostname."""
        ips: List[str] = []
        try:
            answers = self.resolver.resolve(hostname, "A")
            for rdata in answers:
                ips.append(rdata.address)
        except Exception:
            try:
                # Fallback to standard socket
                addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET)
                for item in addrinfo:
                    ip = item[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except Exception as e:
                logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return ips

    def lookup_asn_and_geo(self, ip: str) -> Dict[str, Any]:
        """
        Enriches IP with ASN, Org/ISP, and Country using ip-api.com (free, no API key required).
        """
        if ip in self._cache:
            return self._cache[ip]

        info = {
            "asn": None,
            "asn_org": None,
            "country": None,
            "city": None,
            "isp": None
        }

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    as_raw = data.get("as", "")  # e.g., "AS13335 Cloudflare, Inc."
                    asn_str = as_raw.split(" ")[0] if as_raw else None
                    info["asn"] = asn_str
                    info["asn_org"] = data.get("org") or data.get("isp")
                    info["country"] = data.get("country")
                    info["city"] = data.get("city")
                    info["isp"] = data.get("isp")
                    self._cache[ip] = info
        except Exception as e:
            logger.debug(f"IP-API lookup failed for {ip}: {e}")

        return info
