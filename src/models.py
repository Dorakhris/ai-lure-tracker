"""
AI Lure Tracker - Data Models
Defines internal data representations for indicators, enrichment data, and CTI metadata.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
import json
import uuid


class IndicatorType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    PACKAGE_PYPI = "package-pypi"
    PACKAGE_NPM = "package-npm"
    HASH_MD5 = "hash-md5"
    HASH_SHA256 = "hash-sha256"


class ConfidenceLevel(str, Enum):
    HIGH = "high"       # 75 - 100
    MEDIUM = "medium"   # 50 - 74
    LOW = "low"         # 0 - 49


@dataclass
class RawIndicator:
    value: str
    indicator_type: IndicatorType
    source: str
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    matched_brand: Optional[str] = None
    matched_keyword: Optional[str] = None
    lure_category: Optional[str] = None  # e.g., "fake_installer", "phishing_login", "typosquat_package"


@dataclass
class EnrichmentData:
    domain_age_days: Optional[int] = None
    registration_date: Optional[str] = None
    registrar: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    has_download_link: bool = False
    download_extensions: List[str] = field(default_factory=list)
    has_login_form: bool = False
    urlscan_id: Optional[str] = None
    urlscan_screenshot_url: Optional[str] = None
    virustotal_detections: int = 0
    virustotal_positives: int = 0
    virustotal_link: Optional[str] = None
    shodan_ports: List[int] = field(default_factory=list)
    page_title: Optional[str] = None


@dataclass
class EnrichedIndicator:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    value: str = ""
    indicator_type: IndicatorType = IndicatorType.DOMAIN
    source: str = ""
    target_brand: str = ""
    lure_type: str = "generic_ai_lure"  # fake_installer, credential_phish, typosquat_dependency
    associated_malware: Optional[str] = None  # LummaC2, Stealc, Vidar, etc.
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence_score: int = 50
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    mitre_attack: List[str] = field(default_factory=list)
    enrichment: EnrichmentData = field(default_factory=EnrichmentData)
    tags: List[str] = field(default_factory=list)
    tlp: str = "TLP:CLEAR"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_csv_row(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "indicator": self.value,
            "type": self.indicator_type.value,
            "target_brand": self.target_brand,
            "lure_type": self.lure_type,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "associated_malware": self.associated_malware or "Unknown",
            "source": self.source,
            "first_seen": self.first_seen,
            "domain_age_days": self.enrichment.domain_age_days if self.enrichment.domain_age_days is not None else "",
            "registrar": self.enrichment.registrar or "",
            "asn": self.enrichment.asn or "",
            "asn_org": self.enrichment.asn_org or "",
            "resolved_ips": ";".join(self.enrichment.resolved_ips),
            "country": self.enrichment.country or "",
            "has_download": self.enrichment.has_download_link,
            "has_login": self.enrichment.has_login_form,
            "vt_detections": self.enrichment.virustotal_detections,
            "mitre_techniques": ";".join(self.mitre_attack),
            "tags": ";".join(self.tags),
            "tlp": self.tlp,
        }
