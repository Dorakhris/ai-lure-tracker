import { EnrichedIndicator } from '../types/threat';
import { isAbusedLegitimateService } from '../utils/defang';
import { normalizeIndicatorValue, deduplicateIndicators } from '../utils/normalization';

// Import verified JSON indicators
import rawFeedData from '../../public/feeds/ai_lures_latest.json';

function generateSourceUrl(source: string, val: string): string {
  const s = source.toLowerCase();
  const clean = val.replace(/^https?:\/\//i, '').split('/')[0];
  if (s.includes('threatfox')) {
    return 'https://threatfox.abuse.ch/browse/';
  }
  if (s.includes('urlhaus')) {
    return 'https://urlhaus.abuse.ch/browse/';
  }
  if (s.includes('openphish')) {
    return 'https://openphish.com/';
  }
  if (s.includes('phishtank')) {
    return 'https://phishtank.org/';
  }
  if (s.includes('certstream')) {
    return `https://crt.sh/?q=${encodeURIComponent(clean)}`;
  }
  if (s.includes('pypi')) {
    return `https://pypi.org/project/${encodeURIComponent(clean)}/`;
  }
  if (s.includes('npm')) {
    return `https://www.npmjs.com/package/${encodeURIComponent(clean)}`;
  }
  return 'https://crt.sh/?q=' + encodeURIComponent(clean);
}

const rawList = (rawFeedData as unknown as EnrichedIndicator[]).map((item, index) => {
  const cleanVal = normalizeIndicatorValue(item.value || item.indicator || '');
  const source = item.source || 'ThreatFeeds';
  const isCertStream = source.toLowerCase().includes('certstream');
  const isPackage = (item.indicator_type || '').includes('package') || source.toLowerCase().includes('pypi') || source.toLowerCase().includes('npm');

  // Enforce attribution discipline rules:
  // CertStream: Family unknown, Lure suspected, no malware link established
  let malware = item.associated_malware;
  let attributionSource = item.malware_attribution_source;

  if (isCertStream) {
    malware = 'Family unknown (Lure suspected, no malware link established)';
    attributionSource = 'None (CertStream CT Log)';
  } else if (isPackage && (!malware || malware.includes('Trojanized'))) {
    malware = 'Suspected typosquat or lookalike package';
    attributionSource = 'Package Namespace Heuristic';
  } else if (malware && source.toLowerCase().includes('threatfox')) {
    attributionSource = 'ThreatFox Tag';
  } else if (malware && source.toLowerCase().includes('urlhaus')) {
    attributionSource = 'URLhaus Payload Tag';
  }

  // Abused legitimate service detection
  const isAbusedLegit = isAbusedLegitimateService(cleanVal);

  return {
    ...item,
    id: item.id || `lure-${index + 1}`,
    value: cleanVal,
    indicator_type: item.indicator_type || (cleanVal.startsWith('http') ? 'url' : 'domain'),
    source,
    source_url: item.source_url || generateSourceUrl(source, cleanVal),
    target_brand: item.target_brand || 'generic_ai',
    lure_type: item.lure_type || 'generic_lure',
    associated_malware: malware,
    malware_attribution_source: attributionSource,
    first_seen: item.first_seen || new Date(Date.now() - 3 * 86400000).toISOString(),
    last_seen: item.last_seen || new Date().toISOString(),
    last_checked: item.last_checked || new Date(Date.now() - 15 * 60000).toISOString(),
    confidence_score: typeof item.confidence_score === 'number' ? item.confidence_score : 50,
    confidence_level: (item.confidence_level || 'medium').toLowerCase(),
    status: item.status || 'Active',
    is_demo_data: false,
    is_abused_legitimate_service: isAbusedLegit,
    mitre_attack: Array.isArray(item.mitre_attack) ? item.mitre_attack : [],
    enrichment: item.enrichment || {
      domain_age_days: null,
      registration_date: null,
      registrar: null,
      resolved_ips: [],
      asn: null,
      asn_org: null,
      country: null,
      has_download_link: false,
      download_extensions: [],
      has_login_form: false,
      urlscan_id: null,
      urlscan_screenshot_url: null,
      virustotal_detections: 0,
      virustotal_positives: 0,
      virustotal_link: null,
      shodan_ports: [],
      page_title: null,
    },
    tags: Array.isArray(item.tags) ? item.tags : [],
    tlp: item.tlp || 'TLP:CLEAR',
  };
});

// Deduplicate indicators across feed
export const INITIAL_INDICATORS: EnrichedIndicator[] = deduplicateIndicators(rawList);

export const BRAND_LABELS: Record<string, string> = {
  ALL: 'All Brands',
  openai: 'OpenAI / ChatGPT',
  anthropic: 'Anthropic / Claude',
  google_ai: 'Google AI / Gemini',
  deepseek: 'DeepSeek',
  midjourney: 'Midjourney',
  ollama: 'Ollama',
  ai_ecosystem_library: 'Ecosystem Libraries (LangChain, PyTorch, etc.)',
  general_ai_terms: 'General AI Terms',
};

export const MITRE_DESCRIPTIONS: Record<string, string> = {
  'T1566.002': 'Phishing: Spearphishing Link - Delivery of links to malicious landing pages',
  'T1036.005': 'Masquerading: Match Legitimate Name or Location - AI brand typosquatting & spoofing',
  'T1204.002': 'User Execution: Malicious File - Victims lured to run trojanized installers',
  'T1195.001': 'Supply Chain Compromise: Compromise Software Dependencies - Typosquatted PyPI/npm packages',
  'T1059.006': 'Command and Scripting Interpreter: Python - Malicious execution in setup.py',
  'T1071.001': 'Application Layer Protocol: Web Protocols - C2 beaconing over HTTP/HTTPS',
  'T1005': 'Data from Local System - Infostealer harvesting credentials and browser tokens',
};
