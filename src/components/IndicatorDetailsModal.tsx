import React, { useState, useMemo } from 'react';
import { 
  X, 
  ShieldAlert, 
  Sparkles, 
  Copy, 
  Check, 
  ExternalLink, 
  Globe, 
  Server, 
  Calendar, 
  AlertTriangle,
  FolderPlus,
  Activity,
  CheckCircle2,
  RefreshCw,
  Scale,
  ShieldCheck,
  Eye,
  EyeOff,
  AlertOctagon,
  Network,
  Clock
} from 'lucide-react';
import { EnrichedIndicator, ScoringBreakdown, ThreatVerdict } from '../types/threat';
import { MITRE_DESCRIPTIONS } from '../data/initialFeed';
import { triggerDownload } from '../utils/exportUtils';
import { calculateEvidenceBasedScore } from '../services/scoringEngine';
import { generateEvidenceLinks, generateInvestigativeContext, queryLiveDns, LiveDnsResult } from '../services/enrichmentService';
import { findRelationshipsForIndicator } from '../services/correlationEngine';
import { getStoredCases, updateOrAddCase } from '../services/casebookService';
import { defang, refang, copyToClipboard } from '../utils/defang';

interface IndicatorDetailsModalProps {
  indicator: EnrichedIndicator;
  allIndicators?: EnrichedIndicator[];
  onClose: () => void;
  onTriage: (val: string) => void;
  onSelectIndicator?: (ind: EnrichedIndicator) => void;
}

export const IndicatorDetailsModal: React.FC<IndicatorDetailsModalProps> = ({
  indicator,
  allIndicators = [],
  onClose,
  onTriage,
  onSelectIndicator,
}) => {
  // Unconditional top-level hooks
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const [showJson, setShowJson] = useState(false);
  const [liveDnsLoading, setLiveDnsLoading] = useState(false);
  const [liveDnsResult, setLiveDnsResult] = useState<LiveDnsResult | null>(null);
  const [caseAttachedMsg, setCaseAttachedMsg] = useState<string | null>(null);
  const [rawWarningOpen, setRawWarningOpen] = useState(false);

  // Compute scoring breakdown unconditionally
  const scoring: ScoringBreakdown & { verdict: ThreatVerdict; verdictRuleMatched: string } = useMemo(() => {
    return calculateEvidenceBasedScore(indicator);
  }, [indicator]);

  // Generate evidence links unconditionally
  const evidenceLinks = useMemo(() => {
    return indicator.evidence_links || generateEvidenceLinks(indicator);
  }, [indicator]);

  // Generate investigative context unconditionally
  const context = useMemo(() => {
    return generateInvestigativeContext(indicator);
  }, [indicator]);

  // Correlate with other indicators unconditionally
  const relatedIndicators = useMemo(() => {
    return findRelationshipsForIndicator(indicator, allIndicators);
  }, [indicator, allIndicators]);

  const rawValue = indicator.value || indicator.indicator || '';
  const displayValue = showRaw ? refang(rawValue) : defang(rawValue);
  const verdict = scoring.verdict;
  const isAbusedLegit = indicator.is_abused_legitimate_service;

  const handleCopyDefanged = async () => {
    await copyToClipboard(defang(rawValue));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyRawConfirmed = async () => {
    await copyToClipboard(refang(rawValue));
    setRawWarningOpen(false);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLiveDnsLookup = async () => {
    setLiveDnsLoading(true);
    try {
      const res = await queryLiveDns(rawValue);
      setLiveDnsResult(res);
    } catch (e) {
      console.error('DoH resolution error:', e);
    } finally {
      setLiveDnsLoading(false);
    }
  };

  const handleAttachToDefaultCase = () => {
    const cases = getStoredCases();
    if (cases.length === 0) {
      alert('Please create a case first in the Investigation Casebook tab.');
      return;
    }

    const targetCase = cases[0];
    if (targetCase.indicatorIds.includes(indicator.id)) {
      setCaseAttachedMsg(`Already attached to ${targetCase.id}`);
      setTimeout(() => setCaseAttachedMsg(null), 3000);
      return;
    }

    const updatedCase = {
      ...targetCase,
      indicatorIds: [...targetCase.indicatorIds, indicator.id],
      timeline: [
        ...targetCase.timeline,
        {
          id: `time-${Date.now()}`,
          timestamp: new Date().toISOString(),
          title: `Attached IOC: ${defang(indicator.value)}`,
          description: `Verdict: ${verdict}. Score: ${scoring.totalScore}/100. Target brand: ${indicator.target_brand}.`,
          indicatorValue: indicator.value,
        }
      ]
    };

    updateOrAddCase(updatedCase);
    setCaseAttachedMsg(`Attached to ${targetCase.id} (${targetCase.title})`);
    setTimeout(() => setCaseAttachedMsg(null), 3000);
  };

  const handleDownloadSingleStix = () => {
    const singleObj = {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${indicator.id}`,
      name: `AI Lure: ${defang(rawValue)}`,
      description: `Target Brand: ${indicator.target_brand}. Verdict: ${verdict}. Rule: ${scoring.verdictRuleMatched}.`,
      pattern: `[domain-name:value = '${rawValue}']`,
      pattern_type: 'stix',
      confidence: scoring.totalScore,
      labels: indicator.tags,
      created: indicator.first_seen,
      modified: indicator.last_seen || indicator.first_seen,
    };
    triggerDownload(
      JSON.stringify(singleObj, null, 2),
      `indicator-${indicator.id.slice(0, 8)}.json`,
      'application/json'
    );
  };

  let verdictBadgeClass = 'bg-amber-50 text-amber-800 border border-amber-200';
  if (verdict === 'Confirmed Malicious') {
    verdictBadgeClass = 'bg-rose-50 text-rose-700 border border-rose-200';
  } else if (verdict === 'Likely Benign') {
    verdictBadgeClass = 'bg-emerald-50 text-emerald-700 border border-emerald-200';
  } else if (verdict === 'Taken Down') {
    verdictBadgeClass = 'bg-slate-100 text-slate-600 border border-slate-200';
  } else if (verdict === 'Needs Review') {
    verdictBadgeClass = 'bg-yellow-50 text-yellow-800 border border-yellow-200';
  }

  return (
    <div className="fixed inset-0 bg-slate-900/40 z-50 flex items-center justify-center p-3 sm:p-4 backdrop-blur-xs animate-in fade-in duration-200">
      <div 
        className="bg-white w-full max-w-4xl rounded-2xl border border-slate-200 shadow-2xl overflow-hidden flex flex-col max-h-[92vh] text-slate-800"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-2xs">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900">CTI Investigation Dossier</h3>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-slate-100 text-slate-700 border border-slate-200 uppercase font-semibold">
                  {indicator.indicator_type}
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border ${verdictBadgeClass}`}>
                  {verdict}
                </span>
              </div>
              <p className="text-xs text-slate-500">Evidence correlation, scoring rationale, and OSINT verification</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onTriage(rawValue)}
              className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-1.5 transition-colors shadow-xs cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-100" />
              <span>AI Triage</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-200 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto custom-scroll flex-1 text-xs">
          {/* Main Observable Card */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                  Observable Under Investigation
                </span>
                <button
                  onClick={() => setShowRaw(!showRaw)}
                  className="text-[10px] px-2 py-0.5 rounded border border-slate-200 bg-white text-slate-700 hover:text-slate-900 flex items-center gap-1 shadow-2xs font-medium cursor-pointer"
                >
                  {showRaw ? <Eye className="w-3 h-3 text-amber-600" /> : <EyeOff className="w-3 h-3 text-slate-500" />}
                  <span>{showRaw ? 'Showing Raw' : 'Defanged'}</span>
                </button>
              </div>

              <div className="font-mono text-sm sm:text-base font-bold text-blue-700 break-all select-all">
                {displayValue}
              </div>

              <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-600 pt-1">
                <span>First Seen: <strong className="text-slate-900">{new Date(indicator.first_seen).toISOString().split('T')[0]}</strong></span>
                {indicator.last_checked && (
                  <span>Last Checked: <strong className="text-slate-900">{new Date(indicator.last_checked).toISOString().split('T')[0]}</strong></span>
                )}
                <span>Source: <strong className="text-indigo-600">{indicator.source}</strong></span>
                <span>TLP: <strong className="text-emerald-700 font-semibold">{indicator.tlp}</strong></span>
                <span>Status: <strong className="text-slate-800">{indicator.status || 'Active'}</strong></span>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0">
              <button
                onClick={handleCopyDefanged}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-xs font-medium text-slate-700 transition-colors shadow-2xs cursor-pointer"
                title="Copy Defanged indicator (Safe for tickets/chat)"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied Defanged' : 'Copy Defanged'}</span>
              </button>

              <button
                onClick={() => setRawWarningOpen(true)}
                className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-amber-50 hover:border-amber-400 border border-slate-300 text-xs font-semibold text-slate-600 hover:text-amber-800 transition-colors shadow-2xs cursor-pointer"
                title="Copy raw active link (Warning modal)"
              >
                Raw
              </button>

              <button
                onClick={handleAttachToDefaultCase}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-semibold text-blue-700 transition-colors cursor-pointer"
              >
                <FolderPlus className="w-3.5 h-3.5" />
                <span>Add to Case</span>
              </button>
            </div>
          </div>

          {/* Abused legitimate service banner */}
          {isAbusedLegit && (
            <div className="p-3.5 rounded-xl bg-blue-50 border border-blue-200 text-blue-950 space-y-1">
              <div className="flex items-center gap-2 font-bold text-blue-800">
                <AlertOctagon className="w-4 h-4 text-blue-600" />
                <span>Defensive Notice: Abused Legitimate Service</span>
              </div>
              <p className="text-[11px] text-blue-900 leading-relaxed">
                This indicator resides on a shared multi-tenant platform ({displayValue.split('/')[2] || 'host'}).
                <strong> Do NOT block the entire root domain in your DNS firewall</strong>, as this will disrupt legitimate business operations. Apply blocking at the URL proxy / HTTP path level only.
              </p>
            </div>
          )}

          {caseAttachedMsg && (
            <div className="p-2.5 rounded-lg bg-blue-50 border border-blue-200 text-xs text-blue-800 flex items-center gap-2 font-medium">
              <CheckCircle2 className="w-4 h-4 text-blue-600" />
              <span>{caseAttachedMsg}</span>
            </div>
          )}

          {/* Scoring Model & Verdict Rule Evaluation */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3 shadow-2xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-100">
              <div className="flex items-center space-x-2">
                <Scale className="w-4 h-4 text-blue-600" />
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  Transparent Scoring Model &bull; {scoring.verdict} ({scoring.totalScore}/100)
                </h4>
              </div>
              <div className="text-[11px] text-slate-500 font-mono">
                Rule: <strong className="text-slate-800">{scoring.verdictRuleMatched}</strong>
              </div>
            </div>

            <p className="text-slate-700 text-xs leading-relaxed bg-slate-50 p-2.5 rounded-lg border border-slate-200">
              {scoring.summaryExplanation}
            </p>

            {/* Contributing factors */}
            <div className="space-y-1.5 pt-1">
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Contributing Signal Breakdown</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {scoring.factors.map((f, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-800">{f.name}</div>
                      <div className="text-[10px] text-slate-500 leading-tight mt-0.5">{f.rationale}</div>
                    </div>
                    <span className={`font-mono text-xs font-bold px-1.5 py-0.5 rounded shrink-0 ${
                      f.scoreImpact > 0
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : f.scoreImpact < 0
                        ? 'bg-rose-50 text-rose-700 border border-rose-200'
                        : 'bg-slate-100 text-slate-600'
                    }`}>
                      {f.scoreImpact > 0 ? `+${f.scoreImpact}` : f.scoreImpact}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Missing info, conflicting evidence, limitations, and next steps */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Observed Behaviors & Missing Info */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2 shadow-2xs">
              <h5 className="font-semibold text-slate-800 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-600" />
                <span>Observed Behaviors &amp; Flags</span>
              </h5>
              <ul className="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
                {context.behaviors.map((b: string, i: number) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>

              <h5 className="font-semibold text-amber-800 pt-2 flex items-center gap-1.5 border-t border-slate-100">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                <span>Missing Information &amp; Gaps</span>
              </h5>
              <ul className="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
                {context.missingInfo.map((m: string, i: number) => (
                  <li key={i}>{m}</li>
                ))}
              </ul>
            </div>

            {/* Conflicting Evidence & Recommended Next Steps */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2 shadow-2xs">
              <h5 className="font-semibold text-slate-800 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                <span>Conflicting Evidence &amp; Limitations</span>
              </h5>
              <ul className="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
                {context.conflictingEvidence.concat(context.limitations).map((c: string, i: number) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>

              <h5 className="font-semibold text-blue-800 pt-2 flex items-center gap-1.5 border-t border-slate-100">
                <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                <span>Recommended Next Steps</span>
              </h5>
              <ul className="list-disc list-inside space-y-1 text-slate-700 text-[11px]">
                {context.nextSteps.map((s: string, i: number) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Related Indicators & Correlations */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3 shadow-2xs">
            <h5 className="font-semibold text-slate-800 flex items-center gap-1.5">
              <Network className="w-4 h-4 text-indigo-600" />
              <span>Related Infrastructure &amp; Pivots ({relatedIndicators.length})</span>
            </h5>
            {relatedIndicators.length > 0 ? (
              <div className="space-y-2">
                {relatedIndicators.slice(0, 5).map((rel, idx) => {
                  const targetInd = allIndicators.find(i => i.id === rel.targetIndicatorId);
                  return (
                    <div 
                      key={idx}
                      className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2"
                    >
                      <div>
                        <div className="font-mono text-xs text-blue-700 font-semibold">
                          {defang(rel.targetValue)}
                        </div>
                        <div className="text-[11px] text-slate-600">
                          {rel.evidence.map(e => e.explanation).join(' &bull; ')}
                        </div>
                        {rel.cautions.length > 0 && (
                          <div className="text-[10px] text-amber-700 pt-0.5 font-medium">
                            Caution: {rel.cautions[0]}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium ${
                          rel.relationshipType === 'confirmed_association'
                            ? 'bg-rose-50 text-rose-700 border border-rose-200'
                            : 'bg-amber-50 text-amber-800 border border-amber-200'
                        }`}>
                          {rel.relationshipType.replace(/_/g, ' ')}
                        </span>
                        {targetInd && onSelectIndicator && (
                          <button
                            onClick={() => onSelectIndicator(targetInd)}
                            className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-xs text-slate-700 shadow-2xs cursor-pointer font-medium"
                          >
                            Inspect
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-slate-500">
                No direct infrastructure links observed with other indicators in current feed.
              </div>
            )}
          </div>

          {/* External OSINT Links */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3 shadow-2xs">
            <h5 className="font-semibold text-slate-800 flex items-center gap-1.5">
              <ExternalLink className="w-4 h-4 text-blue-600" />
              <span>External OSINT Verification Links</span>
            </h5>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {evidenceLinks.map((link, i) => (
                <a
                  key={i}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 hover:border-blue-400 hover:bg-blue-50/50 transition-all flex flex-col justify-between group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-700 group-hover:text-blue-700">{link.label}</span>
                    <ExternalLink className="w-3 h-3 text-slate-400 group-hover:text-blue-600" />
                  </div>
                  <span className="text-[10px] text-slate-500 pt-1 truncate">{link.provider}</span>
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <button
            onClick={handleDownloadSingleStix}
            className="text-xs text-slate-600 hover:text-slate-900 font-medium flex items-center gap-1.5 cursor-pointer"
          >
            <span>Export STIX 2.1 JSON</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer"
          >
            Close Dossier
          </button>
        </div>
      </div>

      {/* Copy Raw Warning Modal */}
      {rawWarningOpen && (
        <div className="fixed inset-0 z-60 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white border border-amber-300 rounded-xl w-full max-w-md p-5 space-y-4 shadow-2xl text-slate-800">
            <div className="flex items-center gap-2 text-amber-700">
              <AlertOctagon className="w-5 h-5 shrink-0" />
              <h3 className="text-sm font-bold text-slate-900">Copy Raw Observable Warning</h3>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              Copying raw observable URLs to your clipboard may accidentally trigger automated browser link previews or prefetch requests. Proceed?
            </p>
            <div className="bg-rose-50 p-2.5 rounded font-mono text-xs text-rose-800 border border-rose-200 break-all select-all">
              {rawValue}
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-slate-200">
              <button
                onClick={() => setRawWarningOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-600 hover:text-slate-900 font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleCopyRawConfirmed}
                className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-amber-600 hover:bg-amber-700 text-white cursor-pointer shadow-xs"
              >
                Copy Raw
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
