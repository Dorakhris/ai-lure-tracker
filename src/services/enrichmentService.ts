import { EnrichedIndicator, EvidenceLink } from '../types/threat';
import { extractApexDomain } from './correlationEngine';

export interface LiveDnsResult {
  status: number;
  answers: Array<{ name: string; type: number; data: string; TTL: number }>;
  provider: string;
  queriedAt: string;
  error?: string;
}

// Perform Live DNS Resolution via free public DNS-over-HTTPS (DoH)
export async function queryLiveDns(domainOrUrl: string): Promise<LiveDnsResult> {
  const domain = extractApexDomain(domainOrUrl) || domainOrUrl;
  const queriedAt = new Date().toISOString();

  try {
    // Cloudflare DoH (free, public, CORS enabled)
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    const res = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
    });

    if (!res.ok) {
      throw new Error(`DNS DoH error: HTTP ${res.status}`);
    }

    const json = await res.json();
    return {
      status: json.Status,
      answers: json.Answer || [],
      provider: 'Cloudflare 1.1.1.1 DoH',
      queriedAt,
    };
  } catch (err: any) {
    // Fallback to Google DoH if Cloudflare is unreachable
    try {
      const gUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
      const gRes = await fetch(gUrl);
      if (gRes.ok) {
        const gJson = await gRes.json();
        return {
          status: gJson.Status,
          answers: gJson.Answer || [],
          provider: 'Google 8.8.8.8 DoH',
          queriedAt,
        };
      }
    } catch {}

    return {
      status: -1,
      answers: [],
      provider: 'Offline / Browser Network Boundary',
      queriedAt,
      error: err.message || 'Live DNS lookup unavailable from client browser.',
    };
  }
}

// Generate direct external verification evidence links
export function generateEvidenceLinks(indicator: EnrichedIndicator): EvidenceLink[] {
  const links: EvidenceLink[] = [];
  const val = indicator.value || indicator.indicator || '';
  const apex = extractApexDomain(val) || val;
  const isUrl = indicator.indicator_type === 'url' || val.startsWith('http');
  const isPackage = indicator.indicator_type?.toString().includes('package');
  const isIp = indicator.indicator_type === 'ip';

  // 1. Certificate Transparency (crt.sh) - Crucial for domain investigations
  if (!isPackage && !isIp) {
    links.push({
      label: 'crt.sh Certificate History',
      url: `https://crt.sh/?q=${encodeURIComponent(apex)}`,
      provider: 'crt.sh',
      description: 'Historical SSL/TLS certificates and Subject Alternative Names (SANs) issued for this domain.',
      isExternal: true,
    });
  }

  // 2. VirusTotal Search
  links.push({
    label: 'VirusTotal Threat Graph',
    url: indicator.enrichment?.virustotal_link || `https://www.virustotal.com/gui/search/${encodeURIComponent(val)}`,
    provider: 'VirusTotal',
    description: 'Community multi-engine antivirus detection ratios, passive DNS resolutions, and submitted samples.',
    isExternal: true,
  });

  // 3. urlscan.io Link
  if (indicator.enrichment?.urlscan_id) {
    links.push({
      label: 'urlscan.io Page Submission',
      url: `https://urlscan.io/result/${indicator.enrichment.urlscan_id}/`,
      provider: 'urlscan.io',
      description: 'Automated headless browser capture, DOM screenshot, network requests, and TLS certificates.',
      isExternal: true,
    });
  } else if (!isPackage) {
    links.push({
      label: 'urlscan.io Domain Search',
      url: `https://urlscan.io/search/#${encodeURIComponent(apex)}`,
      provider: 'urlscan.io',
      description: 'Search public website scans and historical screenshots.',
      isExternal: true,
    });
  }

  // 4. Source Specific Community Database
  if (indicator.source?.toLowerCase().includes('urlhaus')) {
    links.push({
      label: 'URLhaus Payload Record',
      url: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(val)}`,
      provider: 'URLhaus',
      description: 'Direct abuse.ch submission details and malware payload SHA256 hashes.',
      isExternal: true,
    });
  } else if (indicator.source?.toLowerCase().includes('threatfox')) {
    links.push({
      label: 'ThreatFox IOC Record',
      url: `https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent(apex)}`,
      provider: 'ThreatFox',
      description: 'Corroborated IOC metadata, threat actor tags, and C2 ports from abuse.ch.',
      isExternal: true,
    });
  }

  // 5. Package Ecosystem (PyPI / npm)
  if (indicator.indicator_type === 'package-pypi' || indicator.source?.toLowerCase().includes('pypi')) {
    links.push({
      label: 'PyPI Registry Package',
      url: `https://pypi.org/project/${encodeURIComponent(val)}/`,
      provider: 'PyPI',
      description: 'Official Python Package Index release timeline, author handle, and release archives.',
      isExternal: true,
    });
  } else if (indicator.indicator_type === 'package-npm' || indicator.source?.toLowerCase().includes('npm')) {
    links.push({
      label: 'npm Registry Package',
      url: `https://www.npmjs.com/package/${encodeURIComponent(val)}`,
      provider: 'npm',
      description: 'Official Node Package Manager version history, dependencies, and tarball link.',
      isExternal: true,
    });
  }

  // 6. Shodan / AbuseIPDB for Resolved IPs
  const resolvedIp = indicator.enrichment?.resolved_ips?.[0];
  if (resolvedIp) {
    links.push({
      label: `Shodan Host Intelligence (${resolvedIp})`,
      url: `https://www.shodan.io/host/${resolvedIp}`,
      provider: 'Shodan',
      description: 'Open network ports, banners, TLS fingerprints, and host vulnerabilities.',
      isExternal: true,
    });

    links.push({
      label: `AbuseIPDB IP Reputation (${resolvedIp})`,
      url: `https://www.abuseipdb.com/check/${resolvedIp}`,
      provider: 'AbuseIPDB',
      description: 'Community abuse reports and brute-force/scanning history for this IP.',
      isExternal: true,
    });
  }

  return links;
}

// Generate evidence-driven investigative context
export function generateInvestigativeContext(indicator: EnrichedIndicator) {
  const behaviors: string[] = [];
  const missingInfo: string[] = [];
  const conflictingEvidence: string[] = [];
  const limitations: string[] = [];
  const nextSteps: string[] = [];

  const val = indicator.value || indicator.indicator || '';
  const lure = (indicator.lure_type || '').toLowerCase();
  const enrichment = indicator.enrichment;

  // Behaviors
  if (enrichment?.has_download_link) {
    behaviors.push('Observed serving binary payload installer artifacts (.exe/.dmg) masquerading as desktop AI client.');
  }
  if (enrichment?.has_login_form) {
    behaviors.push('Exhibits interactive credential authentication/OAuth sign-in form targeting victim AI account tokens.');
  }
  if (lure.includes('typosquat') || lure.includes('lookalike')) {
    behaviors.push('Implements dependency confusion typosquat targeting developer workflows with near-identical package naming.');
  }
  if (indicator.associated_malware && !indicator.associated_malware.includes('Unattributed')) {
    behaviors.push(`Corroborated as distribution infrastructure for ${indicator.associated_malware} infostealer payload.`);
  }
  if (behaviors.length === 0) {
    behaviors.push(`Candidate indicator matched on ${indicator.target_brand} brand naming pattern.`);
  }

  // Missing Information
  if (!enrichment?.registrar || enrichment.registrar.includes('Redacted')) {
    missingInfo.push('RDAP / WHOIS registration authority is redacted behind privacy proxy.');
  }
  if (!enrichment?.resolved_ips?.length) {
    missingInfo.push('No passive or active IPv4 DNS resolution currently recorded.');
  }
  if (!enrichment?.virustotal_detections) {
    missingInfo.push('VirusTotal detection counts unobserved or zero engine reports.');
  }
  if (enrichment?.domain_age_days === null) {
    missingInfo.push('Exact domain registration date unrecorded.');
  }

  // Conflicting Evidence
  if (enrichment?.domain_age_days !== null && enrichment.domain_age_days > 365 && !enrichment.has_download_link) {
    conflictingEvidence.push(`Domain was registered ${enrichment.domain_age_days} days ago (>1 year). Typical infostealer campaign domains are newly registered (<14 days). Possible hijacked subdomain or false positive.`);
  }
  if (enrichment?.asn?.includes('AS13335') || enrichment?.asn_org?.includes('Cloudflare')) {
    conflictingEvidence.push('Infrastructure is proxied by Cloudflare CDN. The resolved IP represents an edge proxy, not the threat actor origin server.');
  }

  // Limitations
  limitations.push('Passive analysis only; dynamic sandbox execution not executed to avoid threat actor counter-surveillance.');
  limitations.push('Domain registration or hosting overlap indicates shared infrastructure, not definitive threat actor identity.');

  // Recommended Next Steps
  if (indicator.indicator_type?.toString().includes('package')) {
    nextSteps.push('Download and inspect package setup.py / package.json for base64 encoded reverse shells or webhook exfiltration.');
    nextSteps.push('Report malicious package to PyPI Security (security@pypi.org) or npm security team for takedown.');
    nextSteps.push('Check enterprise dependency lockfiles for unauthorized imports of this package.');
  } else {
    nextSteps.push('Query crt.sh to map all Subject Alternative Names (SANs) and related staging hostnames.');
    nextSteps.push('Review corporate DNS logs and proxy caches for historical outbound queries to this indicator.');
    nextSteps.push('Enforce immediate DNS sinkhole (RPZ) or block at edge firewall/secure web gateway.');
    if (enrichment?.has_login_form) {
      nextSteps.push('Enforce multi-factor authentication (MFA) session resets for users with corporate AI logins.');
    }
  }

  return {
    behaviors,
    missingInfo,
    conflictingEvidence,
    limitations,
    nextSteps,
  };
}
