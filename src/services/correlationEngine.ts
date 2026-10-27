import { EnrichedIndicator, IndicatorRelationship, CorrelationCluster, RelationshipType, CorrelationEvidenceItem } from '../types/threat';

const SHARED_CDN_ASNS = new Map([
  ['AS13335', 'Cloudflare, Inc.'],
  ['AS16509', 'AWS CloudFront (GLOBAL)'],
  ['AS54113', 'Fastly, Inc'],
  ['AS20940', 'Akamai Technologies'],
  ['AS15169', 'Google Cloud'],
]);

// Helper to extract root / apex domain from indicator
export function extractApexDomain(raw: string): string | null {
  try {
    let clean = raw.trim().toLowerCase();
    if (clean.startsWith('http://') || clean.startsWith('https://')) {
      clean = new URL(clean).hostname;
    }
    // Remove port if present
    clean = clean.split(':')[0];
    // Split domain parts
    const parts = clean.split('.');
    if (parts.length >= 2) {
      // E.g. claude.serv7231.pro -> serv7231.pro
      return parts.slice(-2).join('.');
    }
    return clean;
  } catch {
    return null;
  }
}

// Find relationships for a specific indicator against all other indicators
export function findRelationshipsForIndicator(
  target: EnrichedIndicator,
  allIndicators: EnrichedIndicator[]
): IndicatorRelationship[] {
  const relationships: IndicatorRelationship[] = [];
  const targetApex = extractApexDomain(target.value);
  const targetIps = new Set(target.enrichment?.resolved_ips || []);
  const targetAsn = target.enrichment?.asn;
  const targetRegistrar = target.enrichment?.registrar?.toLowerCase().trim();
  const targetMalware = target.associated_malware?.toLowerCase().trim();
  const targetPackagePrefix = target.value.includes('-') ? target.value.split('-')[0].toLowerCase() : null;

  for (const other of allIndicators) {
    if (other.id === target.id) continue;

    const evidenceItems: CorrelationEvidenceItem[] = [];
    const cautions: string[] = [];

    // 1. Shared Base / Apex Domain
    const otherApex = extractApexDomain(other.value);
    if (targetApex && otherApex && targetApex === otherApex) {
      evidenceItems.push({
        pivotType: 'shared_domain',
        pivotValue: targetApex,
        explanation: `Both indicators share the apex domain '${targetApex}'. Highly probable same infrastructure operator.`,
        relationshipStrength: 'confirmed_association',
      });
    }

    // 2. Shared IP Addresses
    const otherIps = other.enrichment?.resolved_ips || [];
    const sharedIps = otherIps.filter(ip => targetIps.has(ip));
    if (sharedIps.length > 0) {
      const isCdn = targetAsn && SHARED_CDN_ASNS.has(targetAsn);
      if (isCdn) {
        cautions.push(`Shared IP (${sharedIps.join(', ')}) is hosted behind a multitenant CDN (${targetAsn} - ${SHARED_CDN_ASNS.get(targetAsn)}). Does NOT prove common threat actor control.`);
        evidenceItems.push({
          pivotType: 'shared_ip',
          pivotValue: sharedIps.join(', '),
          explanation: `Shared IP address (${sharedIps.join(', ')}), but multitenant CDN usage was detected.`,
          isSharedCdn: true,
          relationshipStrength: 'possible_association_shared_infra',
        });
      } else {
        evidenceItems.push({
          pivotType: 'shared_ip',
          pivotValue: sharedIps.join(', '),
          explanation: `Dedicated IP address overlap on ${sharedIps.join(', ')}. Strong infrastructure linkage.`,
          isSharedCdn: false,
          relationshipStrength: 'supported_association',
        });
      }
    }

    // 3. Shared Specific Registrar (ignore privacy services)
    const otherRegistrar = other.enrichment?.registrar?.toLowerCase().trim();
    if (
      targetRegistrar && 
      otherRegistrar && 
      targetRegistrar === otherRegistrar && 
      !targetRegistrar.includes('privacy') && 
      !targetRegistrar.includes('redacted') &&
      !targetRegistrar.includes('godaddy') // Common generic registrars get low weight
    ) {
      evidenceItems.push({
        pivotType: 'shared_registrar',
        pivotValue: other.enrichment?.registrar || targetRegistrar,
        explanation: `Registered through specialized registrar '${other.enrichment?.registrar}'.`,
        relationshipStrength: 'possible_association_shared_infra',
      });
    }

    // 4. Package Publisher Prefix Cluster (e.g. primarypath-*)
    if (
      targetPackagePrefix && 
      targetPackagePrefix.length > 4 && 
      other.value.toLowerCase().startsWith(targetPackagePrefix + '-')
    ) {
      evidenceItems.push({
        pivotType: 'package_ecosystem',
        pivotValue: `${targetPackagePrefix}-* namespace`,
        explanation: `Shared package prefix namespace '${targetPackagePrefix}-*'. Identifies coordinated dependency confusion cluster.`,
        relationshipStrength: 'confirmed_association',
      });
    }

    // 5. Shared Malware Family + Lure Type
    const otherMalware = other.associated_malware?.toLowerCase().trim();
    if (
      targetMalware && 
      otherMalware && 
      targetMalware === otherMalware && 
      !targetMalware.includes('unattributed') &&
      !targetMalware.includes('generic')
    ) {
      evidenceItems.push({
        pivotType: 'shared_malware',
        pivotValue: other.associated_malware || targetMalware,
        explanation: `Both distribute identical payload family: ${other.associated_malware}.`,
        relationshipStrength: 'supported_association',
      });
    }

    // If correlation evidence was found, assign overall relationship type
    if (evidenceItems.length > 0) {
      let highestStrength: RelationshipType = 'possible_association_shared_infra';
      let confidence = 40;

      if (evidenceItems.some(e => e.relationshipStrength === 'confirmed_association')) {
        highestStrength = 'confirmed_association';
        confidence = 90;
      } else if (evidenceItems.some(e => e.relationshipStrength === 'supported_association')) {
        highestStrength = 'supported_association';
        confidence = 70;
      }

      relationships.push({
        sourceIndicatorId: target.id,
        sourceValue: target.value,
        targetIndicatorId: other.id,
        targetValue: other.value,
        relationshipType: highestStrength,
        confidence,
        evidence: evidenceItems,
        cautions,
      });
    }
  }

  return relationships.sort((a, b) => b.confidence - a.confidence);
}

// Generate all macro correlation clusters across the dataset
export function generateCorrelationClusters(indicators: EnrichedIndicator[]): CorrelationCluster[] {
  const clusters: CorrelationCluster[] = [];

  // 1. Group by Shared Apex Domain
  const apexGroups = new Map<string, EnrichedIndicator[]>();
  indicators.forEach(ind => {
    const apex = extractApexDomain(ind.value);
    if (apex && apex.includes('.')) {
      if (!apexGroups.has(apex)) apexGroups.set(apex, []);
      apexGroups.get(apex)!.push(ind);
    }
  });

  apexGroups.forEach((group, apex) => {
    if (group.length > 1) {
      clusters.push({
        id: `cluster-domain-${apex}`,
        title: `Apex Domain Cluster: ${apex}`,
        pivotType: 'shared_domain',
        pivotValue: apex,
        indicators: group,
        relationshipType: 'confirmed_association',
        explanation: `All ${group.length} indicators share identical base domain '${apex}'. Represents single infrastructure staging campaign.`,
      });
    }
  });

  // 2. Group by Package Namespace Prefix (e.g. primarypath-*)
  const packagePrefixGroups = new Map<string, EnrichedIndicator[]>();
  indicators.forEach(ind => {
    if (ind.indicator_type?.toString().includes('package')) {
      const parts = ind.value.split('-');
      if (parts.length > 1 && parts[0].length > 4) {
        const prefix = parts[0].toLowerCase();
        if (!packagePrefixGroups.has(prefix)) packagePrefixGroups.set(prefix, []);
        packagePrefixGroups.get(prefix)!.push(ind);
      }
    }
  });

  packagePrefixGroups.forEach((group, prefix) => {
    if (group.length > 1) {
      clusters.push({
        id: `cluster-pkg-${prefix}`,
        title: `Coordinated Package Prefix Cluster: ${prefix}-*`,
        pivotType: 'package_ecosystem',
        pivotValue: `${prefix}-*`,
        indicators: group,
        relationshipType: 'confirmed_association',
        explanation: `${group.length} trojanized packages published across PyPI/npm sharing common publisher handle '${prefix}'.`,
      });
    }
  });

  // 3. Group by Shared Non-CDN IP Address
  const ipGroups = new Map<string, EnrichedIndicator[]>();
  indicators.forEach(ind => {
    const isCdn = ind.enrichment?.asn && SHARED_CDN_ASNS.has(ind.enrichment.asn);
    (ind.enrichment?.resolved_ips || []).forEach(ip => {
      // Ignore localhost / private IPs
      if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return;
      if (!ipGroups.has(ip)) ipGroups.set(ip, []);
      ipGroups.get(ip)!.push(ind);
    });
  });

  ipGroups.forEach((group, ip) => {
    if (group.length > 1) {
      const isCdn = group.some(i => i.enrichment?.asn && SHARED_CDN_ASNS.has(i.enrichment.asn));
      clusters.push({
        id: `cluster-ip-${ip.replace(/\./g, '-')}`,
        title: `Shared IP Cluster: ${ip} ${isCdn ? '(Shared CDN / Proxy)' : '(Dedicated Host)'}`,
        pivotType: 'shared_ip',
        pivotValue: ip,
        indicators: group,
        relationshipType: isCdn ? 'possible_association_shared_infra' : 'supported_association',
        explanation: `${group.length} indicators resolve to IPv4 address ${ip}.`,
        caveatNotes: isCdn 
          ? 'CAUTION: This IP is routed through a multitenant Content Delivery Network. Indicators sharing this IP may be operated by distinct actors.'
          : undefined,
      });
    }
  });

  // 4. Group by Malware Family Campaigns (e.g. LummaC2 Stealer, Stealc)
  const malwareGroups = new Map<string, EnrichedIndicator[]>();
  indicators.forEach(ind => {
    const mal = ind.associated_malware;
    if (mal && !mal.toLowerCase().includes('unattributed') && !mal.toLowerCase().includes('generic')) {
      if (!malwareGroups.has(mal)) malwareGroups.set(mal, []);
      malwareGroups.get(mal)!.push(ind);
    }
  });

  malwareGroups.forEach((group, mal) => {
    if (group.length > 2) {
      clusters.push({
        id: `cluster-malware-${mal.toLowerCase().replace(/\s+/g, '-')}`,
        title: `Threat Attribution Cluster: ${mal}`,
        pivotType: 'shared_malware',
        pivotValue: mal,
        indicators: group,
        relationshipType: 'supported_association',
        explanation: `${group.length} active lures attributed to the ${mal} threat ecosystem.`,
      });
    }
  });

  return clusters;
}
