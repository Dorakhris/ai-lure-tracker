"""
AI Lure Tracker - Infrastructure Clustering Engine
Groups malicious indicators by ASN, registrar, TLD, and malware families to uncover threat actor campaigns.
"""

from typing import List, Dict, Any
from collections import defaultdict

from src.models import EnrichedIndicator


class InfrastructureClusterer:
    @staticmethod
    def cluster_indicators(indicators: List[EnrichedIndicator]) -> Dict[str, Any]:
        asn_clusters = defaultdict(list)
        registrar_clusters = defaultdict(list)
        brand_distribution = defaultdict(int)
        malware_distribution = defaultdict(int)
        tld_distribution = defaultdict(int)
        lure_type_distribution = defaultdict(int)

        for ind in indicators:
            brand_distribution[ind.target_brand] += 1
            lure_type_distribution[ind.lure_type] += 1
            if ind.associated_malware:
                malware_distribution[ind.associated_malware] += 1

            # ASN Clustering
            asn_key = f"{ind.enrichment.asn} - {ind.enrichment.asn_org}" if ind.enrichment.asn else "Unresolved / Cloudflare CDN"
            asn_clusters[asn_key].append(ind.value)

            # Registrar Clustering
            reg_key = ind.enrichment.registrar or "Unknown Registrar"
            registrar_clusters[reg_key].append(ind.value)

            # TLD distribution
            val = ind.value.lower()
            if "." in val and "/" not in val.split(".")[-1]:
                tld = "." + val.split(".")[-1].split("/")[0]
                tld_distribution[tld] += 1

        # Sort clusters by frequency
        sorted_asns = sorted(
            [{"asn": k, "count": len(v), "samples": v[:5]} for k, v in asn_clusters.items()],
            key=lambda x: x["count"],
            reverse=True
        )

        sorted_registrars = sorted(
            [{"registrar": k, "count": len(v), "samples": v[:5]} for k, v in registrar_clusters.items()],
            key=lambda x: x["count"],
            reverse=True
        )

        return {
            "total_indicators_analyzed": len(indicators),
            "top_asns": sorted_asns[:8],
            "top_registrars": sorted_registrars[:8],
            "brand_distribution": dict(sorted(brand_distribution.items(), key=lambda x: x[1], reverse=True)),
            "malware_distribution": dict(sorted(malware_distribution.items(), key=lambda x: x[1], reverse=True)),
            "tld_distribution": dict(sorted(tld_distribution.items(), key=lambda x: x[1], reverse=True)[:10]),
            "lure_type_distribution": dict(sorted(lure_type_distribution.items(), key=lambda x: x[1], reverse=True))
        }
