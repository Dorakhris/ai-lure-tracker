export type IndicatorType = 
  | 'domain' 
  | 'url' 
  | 'ip' 
  | 'package-pypi' 
  | 'package-npm' 
  | 'hash-md5' 
  | 'hash-sha256';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type ThreatVerdict = 
  | 'Confirmed Malicious' 
  | 'Suspected' 
  | 'Needs Review' 
  | 'Likely Benign' 
  | 'Taken Down';

export interface FeedHealthItem {
  name: string;
  category: 'malware' | 'phishing' | 'ct_log' | 'ecosystem';
  lastSuccessfulFetch: string;
  recordCount: number;
  status: 'OK' | 'delayed' | 'failed';
  latencyMs: number;
  authoritative: boolean;
  notes?: string;
}

export interface EnrichmentData {
  domain_age_days: number | null;
  registration_date: string | null;
  registrar: string | null;
  resolved_ips: string[];
  asn: string | null;
  asn_org: string | null;
  country: string | null;
  has_download_link: boolean;
  download_extensions: string[];
  has_login_form: boolean;
  urlscan_id: string | null;
  urlscan_screenshot_url: string | null;
  virustotal_detections: number;
  virustotal_positives: number;
  virustotal_link: string | null;
  shodan_ports: number[];
  page_title: string | null;
}

export interface ScoringFactor {
  name: string;
  category: 'source_reliability' | 'evidence_quality' | 'corroboration' | 'behaviour' | 'penalty_or_limitation' | 'recency';
  scoreImpact: number;
  rationale: string;
  evidenceRef?: string;
}

export interface ScoringRuleConfig {
  version: string;
  updatedAt: string;
  weights: {
    authoritativeSourceConfirms: number;
    secondSourceAgrees: number;
    registeredWithin7Days: number;
    brandInHostname: number;
    downloadOrLoginPresent: number;
    knownHighRiskAsn: number;
    matchesCampaignCluster: number;
    allowlistPenalty: number;
    sharedCdnPenalty: number;
  };
  allowlist: string[];
  changelog: Array<{
    version: string;
    date: string;
    author: string;
    description: string;
  }>;
}

export interface ScoringBreakdown {
  totalScore: number;
  confidenceLevel: ConfidenceLevel;
  verdictCategory: 'confirmed_malicious' | 'suspicious_candidate' | 'inconclusive' | 'likely_benign';
  malwareAttributionConfidence: 'confirmed' | 'supported' | 'unverified_candidate' | 'unattributed';
  operationalPriority: 'critical_block' | 'high_investigation' | 'medium_monitor' | 'low_triage';
  sourceReliabilityScore: number;
  evidenceQualityScore: number;
  corroborationScore: number;
  behaviouralScore: number;
  penaltiesScore: number;
  recencyAdjustment: number;
  factors: ScoringFactor[];
  summaryExplanation: string;
  requiresManualReview: boolean;
  reviewReasons: string[];
}

export interface EvidenceLink {
  label: string;
  url: string;
  provider: 'crt.sh' | 'urlscan.io' | 'VirusTotal' | 'URLhaus' | 'ThreatFox' | 'PyPI' | 'npm' | 'Shodan' | 'AbuseIPDB' | 'RDAP' | 'DNS' | 'Source';
  description: string;
  isExternal: boolean;
}

export interface EnrichedIndicator {
  id: string;
  value: string;
  indicator?: string;
  indicator_type: IndicatorType | string;
  source: string;
  target_brand: string;
  lure_type: string;
  associated_malware: string | null;
  first_seen: string;
  last_seen?: string;
  last_checked?: string;
  confidence_score: number;
  confidence_level: ConfidenceLevel | string;
  historical_score?: number;
  malware_attribution_confidence?: 'confirmed' | 'supported' | 'unverified_candidate' | 'unattributed';
  operational_priority?: 'critical_block' | 'high_investigation' | 'medium_monitor' | 'low_triage';
  data_provenance?: 'curated_threat_feed' | 'phishing_feed' | 'package_registry' | 'certstream_ct_log' | 'manual_triage';
  mitre_attack: string[];
  enrichment: EnrichmentData;
  tags: string[];
  tlp: string;
  // CTI Operational and Attribution fields
  verdict?: ThreatVerdict;
  verdict_rule_matched?: string;
  is_demo_data?: boolean;
  status?: 'Active' | 'Taken Down' | 'Unreachable';
  source_url?: string;
  sources?: string[];
  is_abused_legitimate_service?: boolean;
  malware_attribution_source?: string;
  // Investigative additions
  scoring_breakdown?: ScoringBreakdown;
  evidence_links?: EvidenceLink[];
  observed_behaviors?: string[];
  missing_information?: string[];
  conflicting_evidence?: string[];
  investigation_limitations?: string[];
  recommended_next_steps?: string[];
  is_flagged_for_review?: boolean;
}

// Indicator Correlation Types
export type RelationshipType = 
  | 'confirmed_association'             // Cryptographic hash, same payload, direct redirect
  | 'supported_association'             // Dedicated hosting, unique registrant, distinct nameserver
  | 'possible_association_shared_infra' // Shared CDN (Cloudflare, AWS Cloudfront), shared multitenant host
  | 'unrelated_coincidental';           // Generic coincidences

export interface CorrelationEvidenceItem {
  pivotType: 'shared_domain' | 'shared_ip' | 'shared_asn' | 'shared_registrar' | 'shared_malware' | 'package_ecosystem';
  pivotValue: string;
  explanation: string;
  isSharedCdn?: boolean;
  relationshipStrength: RelationshipType;
}

export interface IndicatorRelationship {
  sourceIndicatorId: string;
  sourceValue: string;
  targetIndicatorId: string;
  targetValue: string;
  relationshipType: RelationshipType;
  confidence: number; // 0 - 100
  evidence: CorrelationEvidenceItem[];
  cautions: string[];
}

export interface CorrelationCluster {
  id: string;
  title: string;
  pivotType: 'shared_domain' | 'shared_ip' | 'shared_asn' | 'shared_registrar' | 'shared_malware' | 'package_ecosystem';
  pivotValue: string;
  indicators: EnrichedIndicator[];
  relationshipType: RelationshipType;
  explanation: string;
  caveatNotes?: string;
}

// Casebook Types
export interface CaseTimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  indicatorValue?: string;
  sourceRef?: string;
}

export interface CaseHypothesis {
  id: string;
  statement: string;
  status: 'supported' | 'refuted' | 'unverified';
  supportingEvidence: string;
  alternativeExplanation?: string;
}

export interface CaseEvidenceNote {
  id: string;
  timestamp: string;
  title: string;
  content: string;
  author: string;
  tags?: string[];
}

export interface InvestigationCase {
  id: string; // e.g. CASE-2026-001
  title: string;
  investigationQuestion: string;
  status: 'open' | 'in_progress' | 'closed' | 'escalated';
  priority: 'critical' | 'high' | 'medium' | 'low';
  createdAt: string;
  updatedAt: string;
  leadAnalyst: string;
  indicatorIds: string[]; // references EnrichedIndicator.id
  hypotheses: CaseHypothesis[];
  alternativeExplanations: string[];
  evidenceNotes: CaseEvidenceNote[];
  timeline: CaseTimelineEvent[];
  findings: string[];
  unresolvedQuestions: string[];
  recommendedActions: string[];
  finalSummary: string;
}

// Grounded AI Triage Result
export interface GroundedFact {
  claim: string;
  sourceEvidence: string;
  verified: boolean;
}

export interface GeminiTriageResult {
  rawResponse: string;
  verdict: 'MALICIOUS HIGH CONFIDENCE' | 'SUSPICIOUS CANDIDATE' | 'INCONCLUSIVE' | 'LIKELY BENIGN' | 'UNKNOWN';
  targetBrand?: string;
  attackPattern?: string;
  malwareFamily?: string;
  mitreTechniques?: string[];
  defensiveAction?: string;
  // Delineated Evidence Grounding
  factsSupportedBySources: string[];
  analystInferences: string[];
  unverifiedHypotheses: string[];
  unknownInformation: string[];
  evidenceCitations: string[];
  promptInjectionDefended?: boolean;
}

export interface CertStreamEvent {
  id: string;
  timestamp: string;
  domain: string;
  matchedBrand: string;
  issuer: string;
  certType: string;
  suspicionScore: number;
  isFlagged: boolean;
}
