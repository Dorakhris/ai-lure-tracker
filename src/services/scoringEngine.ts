import { 
  EnrichedIndicator, 
  ScoringBreakdown, 
  ScoringFactor, 
  ConfidenceLevel, 
  ThreatVerdict,
  ScoringRuleConfig 
} from '../types/threat';

// Default editable official-domain allowlist
export const DEFAULT_ALLOWLIST = [
  'openai.com',
  'chatgpt.com',
  'anthropic.com',
  'claude.ai',
  'google.com',
  'deepmind.google',
  'gemini.google.com',
  'microsoft.com',
  'github.com',
  'huggingface.co',
  'ollama.com',
  'deepseek.com',
  'midjourney.com',
  'pypi.org',
  'npmjs.com'
];

export const SHARED_CDN_ASNS = new Set([
  'AS13335', // Cloudflare
  'AS16509', // AWS CloudFront
  'AS54113', // Fastly
  'AS20940', // Akamai
  'AS15169', // Google
]);

export const HIGH_RISK_ASNS = new Set([
  'AS44444', 'AS9999', 'AS200000', 'AS51852', 'AS49870', 'AS206983'
]);

export const SUSPICIOUS_TLDS = new Set([
  'top', 'icu', 'buzz', 'cfd', 'lat', 'site', 'xyz', 'pro', 'click', 'link', 'download', 'kim'
]);

// Default Scoring Rule Configuration (Version 1.0)
export const DEFAULT_SCORING_CONFIG: ScoringRuleConfig = {
  version: 'Scoring v1.0',
  updatedAt: '2026-10-26T10:00:00.000Z',
  weights: {
    authoritativeSourceConfirms: 40,
    secondSourceAgrees: 20,
    registeredWithin7Days: 10,
    brandInHostname: 10,
    downloadOrLoginPresent: 10,
    knownHighRiskAsn: 5,
    matchesCampaignCluster: 5,
    allowlistPenalty: -80,
    sharedCdnPenalty: -5,
  },
  allowlist: [...DEFAULT_ALLOWLIST],
  changelog: [
    {
      version: 'Scoring v1.0',
      date: '2026-10-26',
      author: 'CTI Lead Architect',
      description: 'Initial transparent evidence-based weights baseline (+40 authoritative, +20 corroboration, +10 recency, +10 brand, +10 weaponization, +5 ASN/cluster).'
    }
  ]
};

const STORAGE_KEY = 'ai_lure_scoring_config_v1';

export function getActiveScoringConfig(): ScoringRuleConfig {
  try {
    const raw = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.version && parsed.weights) {
        return parsed;
      }
    }
  } catch {
    // Fall back to default
  }
  return DEFAULT_SCORING_CONFIG;
}

export function saveScoringConfig(config: ScoringRuleConfig): void {
  try {
    if (typeof window !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    }
  } catch (e) {
    console.error('Failed to persist scoring config:', e);
  }
}

export function resetScoringConfig(): ScoringRuleConfig {
  saveScoringConfig(DEFAULT_SCORING_CONFIG);
  return DEFAULT_SCORING_CONFIG;
}

/**
 * Calculates evidence-driven score, 5-verdict classification, and attribution rationale.
 */
export function calculateEvidenceBasedScore(
  indicator: Partial<EnrichedIndicator>,
  config: ScoringRuleConfig = getActiveScoringConfig()
): ScoringBreakdown & { verdict: ThreatVerdict; verdictRuleMatched: string } {
  const factors: ScoringFactor[] = [];
  const reviewReasons: string[] = [];

  const rawVal = (indicator.value || indicator.indicator || '').trim().toLowerCase();
  const source = (indicator.source || '').toLowerCase();
  const lureType = (indicator.lure_type || '').toLowerCase();
  const malware = (indicator.associated_malware || '').toLowerCase();
  const status = indicator.status;
  
  const enrichment = indicator.enrichment || {
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
  };

  // 0. Check Status First: Taken Down
  if (status === 'Taken Down' || rawVal.includes('taken-down')) {
    factors.push({
      name: 'Host Inactive / Taken Down',
      category: 'penalty_or_limitation',
      scoreImpact: 0,
      rationale: 'Infrastructure confirmed taken down, sinkholed, or DNS record removed.',
    });
    return {
      totalScore: 10,
      confidenceLevel: 'low',
      verdictCategory: 'inconclusive',
      verdict: 'Taken Down',
      verdictRuleMatched: 'Sinkholed or taken down by registrar/provider',
      malwareAttributionConfidence: 'unattributed',
      operationalPriority: 'low_triage',
      sourceReliabilityScore: 0,
      evidenceQualityScore: 0,
      corroborationScore: 0,
      behaviouralScore: 0,
      penaltiesScore: 0,
      recencyAdjustment: 0,
      factors,
      summaryExplanation: 'Domain or URL has been officially taken down or deactivated.',
      requiresManualReview: false,
      reviewReasons: []
    };
  }

  // 1. Allowlist Suppression Check
  const effectiveAllowlist = config.allowlist || DEFAULT_ALLOWLIST;
  for (const domain of effectiveAllowlist) {
    const cleanDomain = domain.toLowerCase().trim();
    if (rawVal === cleanDomain || rawVal.endsWith('.' + cleanDomain) || rawVal.includes(`://${cleanDomain}/`) || rawVal.includes(`@${cleanDomain}`)) {
      factors.push({
        name: 'Legitimate Vendor Authority',
        category: 'penalty_or_limitation',
        scoreImpact: config.weights.allowlistPenalty,
        rationale: `Matched legitimate authorized domain '${domain}'. High false-positive suppression applied.`,
      });
      return {
        totalScore: 5,
        confidenceLevel: 'low',
        verdictCategory: 'likely_benign',
        verdict: 'Likely Benign',
        verdictRuleMatched: `Matched official vendor domain allowlist (${domain})`,
        malwareAttributionConfidence: 'unattributed',
        operationalPriority: 'low_triage',
        sourceReliabilityScore: 0,
        evidenceQualityScore: 0,
        corroborationScore: 0,
        behaviouralScore: 0,
        penaltiesScore: config.weights.allowlistPenalty,
        recencyAdjustment: 0,
        factors,
        summaryExplanation: `Indicator is verified official infrastructure belonging to ${domain}.`,
        requiresManualReview: false,
        reviewReasons: []
      };
    }
  }

  // 2. Authoritative Source Confirmation (+40 default)
  let sourceScore = 0;
  let isAuthoritative = false;
  let authoritativeSourceName = '';

  if (source.includes('threatfox')) {
    sourceScore = config.weights.authoritativeSourceConfirms;
    isAuthoritative = true;
    authoritativeSourceName = 'ThreatFox';
    factors.push({
      name: 'Authoritative CTI Feed (ThreatFox)',
      category: 'source_reliability',
      scoreImpact: sourceScore,
      rationale: 'abuse.ch validated sensor confirming active malware payload or C2 endpoint.'
    });
  } else if (source.includes('urlhaus')) {
    sourceScore = config.weights.authoritativeSourceConfirms;
    isAuthoritative = true;
    authoritativeSourceName = 'URLhaus';
    factors.push({
      name: 'Authoritative Malware URL Feed (URLhaus)',
      category: 'source_reliability',
      scoreImpact: sourceScore,
      rationale: 'abuse.ch verified malware payload distribution host.'
    });
  } else if (source.includes('openphish')) {
    sourceScore = Math.round(config.weights.authoritativeSourceConfirms * 0.8);
    isAuthoritative = true;
    authoritativeSourceName = 'OpenPhish';
    factors.push({
      name: 'Active Phishing Feed (OpenPhish)',
      category: 'source_reliability',
      scoreImpact: sourceScore,
      rationale: 'Automated phishing detection with verified target payload rendering.'
    });
  } else if (source.includes('phishtank')) {
    sourceScore = Math.round(config.weights.authoritativeSourceConfirms * 0.75);
    isAuthoritative = true;
    authoritativeSourceName = 'PhishTank';
    factors.push({
      name: 'Verified Phishing Community (PhishTank)',
      category: 'source_reliability',
      scoreImpact: sourceScore,
      rationale: 'Community consensus verified phishing page.'
    });
  } else if (source.includes('certstream')) {
    sourceScore = 10;
    factors.push({
      name: 'Certificate Transparency Log (CertStream)',
      category: 'source_reliability',
      scoreImpact: 10,
      rationale: 'Passive SSL/TLS certificate observation. Represents early candidate staging, not confirmed weaponization.'
    });
  } else if (source.includes('pypi') || source.includes('npm')) {
    sourceScore = 15;
    factors.push({
      name: 'Package Registry Feeds (PyPI / npm)',
      category: 'source_reliability',
      scoreImpact: 15,
      rationale: 'Direct observation of published package metadata from official package index.'
    });
  } else {
    sourceScore = 10;
    factors.push({
      name: 'Secondary CTI Sensor',
      category: 'source_reliability',
      scoreImpact: 10,
      rationale: 'Single reporting sensor or community telemetry.'
    });
  }

  // 3. Multi-source Corroboration (+20 default)
  let corroborationScore = 0;
  let sourceCount = 1;
  const extraSources = indicator.sources || [];
  if (extraSources.length > 1) {
    sourceCount = extraSources.length;
  } else {
    if ((source.includes('threatfox') || source.includes('urlhaus')) && (enrichment.virustotal_detections >= 2 || enrichment.urlscan_id)) {
      sourceCount++;
    }
  }

  if (sourceCount >= 2) {
    corroborationScore = config.weights.secondSourceAgrees;
    factors.push({
      name: 'Second Independent Source Agrees',
      category: 'corroboration',
      scoreImpact: corroborationScore,
      rationale: `Independently corroborated across ${sourceCount} distinct reporting sensors or analysis engines.`
    });
  }

  // 4. Registration Recency (+10 default if <= 7 days)
  let registrationScore = 0;
  if (enrichment.domain_age_days !== null && enrichment.domain_age_days <= 7) {
    registrationScore = config.weights.registeredWithin7Days;
    factors.push({
      name: 'Newly Registered Domain (≤ 7 Days)',
      category: 'evidence_quality',
      scoreImpact: registrationScore,
      rationale: `Domain was created ${enrichment.domain_age_days} days ago. Newly registered domains carry high infostealer staging correlation.`
    });
  } else if (enrichment.registration_date) {
    const regAge = (Date.now() - new Date(enrichment.registration_date).getTime()) / (1000 * 60 * 60 * 24);
    if (regAge <= 7) {
      registrationScore = config.weights.registeredWithin7Days;
      factors.push({
        name: 'Newly Registered Domain (≤ 7 Days)',
        category: 'evidence_quality',
        scoreImpact: registrationScore,
        rationale: 'WHOIS registration record indicates domain was provisioned within the last 7 days.'
      });
    }
  }

  // 5. AI Brand in Hostname (+10 default)
  let brandScore = 0;
  const targetBrand = (indicator.target_brand || '').toLowerCase();
  const brandKeywords = ['chatgpt', 'openai', 'anthropic', 'claude', 'gemini', 'deepseek', 'midjourney', 'ollama'];
  const hasBrandInHostname = brandKeywords.some(b => rawVal.includes(b)) || (targetBrand && targetBrand !== 'generic_ai' && targetBrand !== 'unknown');
  
  if (hasBrandInHostname) {
    brandScore = config.weights.brandInHostname;
    factors.push({
      name: 'AI Brand In Hostname / Package Name',
      category: 'behaviour',
      scoreImpact: brandScore,
      rationale: `Impersonates targeted brand identity (${targetBrand.toUpperCase() || 'AI'}) in hostname or namespace.`
    });
  }

  // 6. Download Link or Login Form (+10 default)
  let weaponizationScore = 0;
  if (enrichment.has_download_link || enrichment.has_login_form || rawVal.includes('.exe') || rawVal.includes('.dmg') || rawVal.includes('login') || rawVal.includes('setup')) {
    weaponizationScore = config.weights.downloadOrLoginPresent;
    factors.push({
      name: 'Download Link or Credential Harvesting Form Present',
      category: 'evidence_quality',
      scoreImpact: weaponizationScore,
      rationale: 'Telemetry or URI path points directly to an installer binary or credentials collection form.'
    });
  }

  // High VT detections bonus
  if (enrichment.virustotal_detections && enrichment.virustotal_detections >= 3) {
    factors.push({
      name: `Multi-Engine AV Detection (VT: ${enrichment.virustotal_detections})`,
      category: 'evidence_quality',
      scoreImpact: 15,
      rationale: `${enrichment.virustotal_detections} antivirus engines flagged this indicator as malicious.`
    });
  }

  // 7. Known High-Risk ASN (+5 default)
  let asnScore = 0;
  if (enrichment.asn && HIGH_RISK_ASNS.has(enrichment.asn)) {
    asnScore = config.weights.knownHighRiskAsn;
    factors.push({
      name: `Known High-Risk Bulletproof ASN (${enrichment.asn})`,
      category: 'behaviour',
      scoreImpact: asnScore,
      rationale: `Hosted on ASN ${enrichment.asn} frequently observed hosting malicious lure operations.`
    });
  }

  // 8. Matches Known Campaign Cluster (+5 default)
  let clusterScore = 0;
  if (indicator.tags?.some(t => t.includes('campaign') || t.includes('cluster') || t.includes('primarypath'))) {
    clusterScore = config.weights.matchesCampaignCluster;
    factors.push({
      name: 'Correlated With Known Campaign Cluster',
      category: 'corroboration',
      scoreImpact: clusterScore,
      rationale: 'Shares infrastructure pivots with an active tracked threat campaign.'
    });
  }

  // Penalties & Limitations
  let penalties = 0;
  if (enrichment.asn && SHARED_CDN_ASNS.has(enrichment.asn)) {
    penalties += config.weights.sharedCdnPenalty;
    factors.push({
      name: 'Shared Infrastructure Notice (Cloudflare/CDN)',
      category: 'penalty_or_limitation',
      scoreImpact: config.weights.sharedCdnPenalty,
      rationale: `Hosted behind ${enrichment.asn} (${enrichment.asn_org || 'CDN'}). Shared multi-tenant IP cannot prove threat operator ownership.`
    });
  }

  // Incomplete enrichment caveat
  if (enrichment.domain_age_days === null && (!enrichment.resolved_ips || !enrichment.resolved_ips.length)) {
    factors.push({
      name: 'Incomplete Enrichment Notice',
      category: 'penalty_or_limitation',
      scoreImpact: 0,
      rationale: 'Passive DNS and RDAP registration are unobserved. Score relies on lexical and feed indicators.'
    });
    reviewReasons.push('Passive DNS and WHOIS registration history unobserved.');
  }

  // Suspicious TLD bonus
  const tldMatch = rawVal.match(/\.([a-z0-9-]+)(?:\/|$|\?)/);
  if (tldMatch && SUSPICIOUS_TLDS.has(tldMatch[1])) {
    factors.push({
      name: `High-Risk Throwaway TLD (.${tldMatch[1]})`,
      category: 'behaviour',
      scoreImpact: 5,
      rationale: `TLD .${tldMatch[1]} is heavily weaponized in disposable infostealer lure distributions.`
    });
  }

  // Stale age penalty
  let recency = 0;
  if (indicator.first_seen) {
    const ageDays = (Date.now() - new Date(indicator.first_seen).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays > 60) {
      recency = -10;
      factors.push({
        name: 'Stale Observation (> 60 Days)',
        category: 'recency',
        scoreImpact: -10,
        rationale: 'Indicator is aged; may be sinkholed or abandoned.'
      });
      reviewReasons.push('Observation is older than 60 days. Verify current active status.');
    }
  }

  // Compute Total Score
  let totalScore = sourceScore + corroborationScore + registrationScore + brandScore + weaponizationScore + asnScore + clusterScore + penalties + recency;
  totalScore = Math.max(5, Math.min(100, Math.round(totalScore)));

  // Strict Verdict & Attribution Rules:
  // "Confirmed Malicious" requires at least one authoritative source that explicitly reports the indicator as malicious,
  // OR two independent sources agreeing.
  // Lookalike domain names or package names alone are NEVER confirmed. They are "Suspected" at most until a source or inspection confirms them.
  let verdict: ThreatVerdict = 'Needs Review';
  let verdictRuleMatched = '';
  let verdictCategory: ScoringBreakdown['verdictCategory'] = 'inconclusive';
  let confidenceLevel: ConfidenceLevel = 'low';

  const isLookalikeOnly = (source.includes('certstream') || lureType.includes('lookalike') || lureType.includes('typosquat')) && !isAuthoritative && sourceCount < 2;

  if (isLookalikeOnly) {
    // Lookalike alone is NEVER confirmed
    if (totalScore >= 40) {
      verdict = 'Suspected';
      verdictCategory = 'suspicious_candidate';
      confidenceLevel = 'medium';
      verdictRuleMatched = 'Lookalike domain/package alone is capped at Suspected (awaiting authoritative inspection)';
    } else {
      verdict = 'Needs Review';
      verdictCategory = 'inconclusive';
      confidenceLevel = 'low';
      verdictRuleMatched = 'Uncorroborated candidate without payload inspection';
    }
    reviewReasons.push('Lookalike domain or package alone cannot be marked Confirmed Malicious without payload verification.');
  } else if (isAuthoritative || sourceCount >= 2 || (enrichment.virustotal_detections && enrichment.virustotal_detections >= 3)) {
    if (totalScore >= 75) {
      verdict = 'Confirmed Malicious';
      verdictCategory = 'confirmed_malicious';
      confidenceLevel = 'high';
      if (isAuthoritative && authoritativeSourceName) {
        verdictRuleMatched = `Authoritative source (${authoritativeSourceName}) verified malicious`;
      } else if (sourceCount >= 2) {
        verdictRuleMatched = `Two independent agreeing sources (${sourceCount} sources confirmed)`;
      } else {
        verdictRuleMatched = `Multi-engine security engine verification (${enrichment.virustotal_detections} AV engines)`;
      }
    } else if (totalScore >= 40) {
      verdict = 'Suspected';
      verdictCategory = 'suspicious_candidate';
      confidenceLevel = 'medium';
      verdictRuleMatched = 'Reported by threat feed with moderate confidence';
    } else {
      verdict = 'Needs Review';
      verdictCategory = 'inconclusive';
      confidenceLevel = 'low';
      verdictRuleMatched = 'Score under 40 points; requires analyst triage';
    }
  } else {
    if (totalScore >= 40) {
      verdict = 'Suspected';
      verdictCategory = 'suspicious_candidate';
      confidenceLevel = 'medium';
      verdictRuleMatched = 'Suspicious heuristics observed without authoritative confirmation';
    } else {
      verdict = 'Needs Review';
      verdictCategory = 'inconclusive';
      confidenceLevel = 'low';
      verdictRuleMatched = 'Insufficient evidence / score below 40';
    }
  }

  // Malware Attribution Discipline:
  // Family attribution ONLY if source explicitly states it (such as URLhaus tag or sandbox report).
  // CertStream must be labelled "Family unknown" and "Lure suspected, no malware link established".
  let malwareAttributionConfidence: ScoringBreakdown['malwareAttributionConfidence'] = 'unattributed';
  if (source.includes('certstream')) {
    malwareAttributionConfidence = 'unverified_candidate';
    reviewReasons.push('CertStream SSL certificate observation: Family unknown (Lure suspected, no malware link established).');
  } else if (malware && !malware.includes('unattributed') && !malware.includes('unknown') && !malware.includes('generic')) {
    if (source.includes('threatfox') || (source.includes('urlhaus') && enrichment.has_download_link)) {
      malwareAttributionConfidence = 'confirmed';
    } else {
      malwareAttributionConfidence = 'supported';
    }
  }

  // Operational priority
  let operationalPriority: ScoringBreakdown['operationalPriority'] = 'low_triage';
  if (verdict === 'Confirmed Malicious') {
    operationalPriority = 'critical_block';
  } else if (verdict === 'Suspected') {
    operationalPriority = 'high_investigation';
  } else if (verdict === 'Needs Review') {
    operationalPriority = 'medium_monitor';
  }

  const requiresManualReview = reviewReasons.length > 0 || verdict === 'Needs Review';

  const summaryExplanation = `Verdict: ${verdict.toUpperCase()} (${totalScore}/100, ${config.version}). Rule: ${verdictRuleMatched}. ` +
    `Signals: Source (+${sourceScore}), Corroboration (+${corroborationScore}), Registration (+${registrationScore}), Brand (+${brandScore}), Payload (+${weaponizationScore}), ASN (+${asnScore}).`;

  return {
    totalScore,
    confidenceLevel,
    verdictCategory,
    verdict,
    verdictRuleMatched,
    malwareAttributionConfidence,
    operationalPriority,
    sourceReliabilityScore: sourceScore,
    evidenceQualityScore: weaponizationScore + registrationScore,
    corroborationScore: corroborationScore + clusterScore,
    behaviouralScore: brandScore + asnScore,
    penaltiesScore: penalties,
    recencyAdjustment: recency,
    factors,
    summaryExplanation,
    requiresManualReview,
    reviewReasons
  };
}
