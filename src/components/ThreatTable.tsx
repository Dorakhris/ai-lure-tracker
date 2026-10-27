import React, { useState, useMemo } from 'react';
import { 
  Rss, 
  Search, 
  Copy, 
  Check, 
  ExternalLink, 
  Sparkles, 
  Filter, 
  ArrowUpDown,
  AlertTriangle,
  FolderPlus,
  ShieldCheck,
  Eye,
  EyeOff,
  HelpCircle,
  Clock,
  Layers,
  AlertOctagon,
  ShieldAlert,
  Radio
} from 'lucide-react';
import { EnrichedIndicator, ThreatVerdict } from '../types/threat';
import { calculateEvidenceBasedScore } from '../services/scoringEngine';
import { getStoredCases, updateOrAddCase } from '../services/casebookService';
import { defang, refang, copyToClipboard } from '../utils/defang';
import { ScoreRationaleDrawer } from './ScoreRationaleDrawer';

interface ThreatTableProps {
  indicators: EnrichedIndicator[];
  onTriage: (indicatorValue: string, indicatorObj?: EnrichedIndicator) => void;
  onSelectIndicator: (indicator: EnrichedIndicator) => void;
}

export const ThreatTable: React.FC<ThreatTableProps> = ({
  indicators,
  onTriage,
  onSelectIndicator,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [brandFilter, setBrandFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [reviewFilter, setReviewFilter] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  
  // Modals & Drawers state
  const [drawerIndicator, setDrawerIndicator] = useState<EnrichedIndicator | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [attachedId, setAttachedId] = useState<string | null>(null);
  const [rawWarningItem, setRawWarningItem] = useState<string | null>(null);
  
  const [sortField, setSortField] = useState<'score' | 'time' | 'brand' | 'verdict'>('score');
  const [sortAsc, setSortAsc] = useState(false);

  // Score indicators with current rules
  const scoredIndicators = useMemo(() => {
    return indicators.map(ind => {
      const scoring = calculateEvidenceBasedScore(ind);
      return {
        ...ind,
        confidence_score: scoring.totalScore,
        confidence_level: scoring.confidenceLevel,
        verdict: scoring.verdict,
        verdict_rule_matched: scoring.verdictRuleMatched,
        scoring_breakdown: scoring,
        is_flagged_for_review: scoring.requiresManualReview,
      };
    });
  }, [indicators]);

  const handleCopyDefanged = async (e: React.MouseEvent, text: string, id: string) => {
    e.stopPropagation();
    const defangedText = defang(text);
    await copyToClipboard(defangedText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRequestCopyRaw = (e: React.MouseEvent, text: string) => {
    e.stopPropagation();
    setRawWarningItem(refang(text));
  };

  const handleConfirmCopyRaw = async () => {
    if (rawWarningItem) {
      await copyToClipboard(rawWarningItem);
      setRawWarningItem(null);
    }
  };

  const handleQuickAttachCase = (e: React.MouseEvent, ind: EnrichedIndicator) => {
    e.stopPropagation();
    const cases = getStoredCases();
    if (cases.length === 0) {
      alert('Please initialize an investigation in the Casebook tab first.');
      return;
    }
    const targetCase = cases[0];
    if (targetCase.indicatorIds.includes(ind.id)) {
      setAttachedId(ind.id);
      setTimeout(() => setAttachedId(null), 2000);
      return;
    }
    const updated = {
      ...targetCase,
      indicatorIds: [...targetCase.indicatorIds, ind.id],
      timeline: [
        ...targetCase.timeline,
        {
          id: `time-${Date.now()}`,
          timestamp: new Date().toISOString(),
          title: `Attached ${defang(ind.value)}`,
          description: `Added to case from Threat Feed table. Verdict: ${ind.verdict}. Score: ${ind.confidence_score}/100.`,
          indicatorValue: ind.value,
        }
      ]
    };
    updateOrAddCase(updated);
    setAttachedId(ind.id);
    setTimeout(() => setAttachedId(null), 2000);
  };

  const filteredIndicators = useMemo(() => {
    const term = searchTerm.toLowerCase().trim();

    return scoredIndicators
      .filter(item => {
        const val = (item.value || item.indicator || '').toLowerCase();
        const brand = (item.target_brand || '').toLowerCase();
        const malware = (item.associated_malware || '').toLowerCase();
        const lure = (item.lure_type || '').toLowerCase();
        const verdict = item.verdict || 'Suspected';

        const matchesSearch =
          !term ||
          val.includes(term) ||
          brand.includes(term) ||
          malware.includes(term) ||
          lure.includes(term);

        const matchesBrand =
          brandFilter === 'ALL' || brand === brandFilter.toLowerCase();

        const matchesVerdict =
          verdictFilter === 'ALL' || verdict === verdictFilter;

        const matchesReview = !reviewFilter || item.is_flagged_for_review;

        return matchesSearch && matchesBrand && matchesVerdict && matchesReview;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortField === 'score') {
          diff = a.confidence_score - b.confidence_score;
        } else if (sortField === 'brand') {
          diff = (a.target_brand || '').localeCompare(b.target_brand || '');
        } else if (sortField === 'time') {
          diff = new Date(a.first_seen).getTime() - new Date(b.first_seen).getTime();
        } else if (sortField === 'verdict') {
          diff = (a.verdict || '').localeCompare(b.verdict || '');
        }
        return sortAsc ? diff : -diff;
      });
  }, [scoredIndicators, searchTerm, brandFilter, verdictFilter, reviewFilter, sortField, sortAsc]);

  const toggleSort = (field: 'score' | 'time' | 'brand' | 'verdict') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  return (
    <>
      <div className="bg-white rounded-xl border border-slate-200/90 overflow-hidden shadow-xs">
        {/* Table Header & Filter Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-white">
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Rss className="w-4 h-4 text-emerald-600" />
              <span>Evidence-Driven Malicious Infrastructure Feed</span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Live observables defanged by default &bull; Click any indicator to inspect complete forensic dossier
            </p>
          </div>

          {/* Filters & Toggles */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search domain, brand, malware..."
                className="bg-white border border-slate-300 text-xs text-slate-900 pl-9 pr-3 py-2 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 w-48 sm:w-56 placeholder:text-slate-400 shadow-2xs"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-2.5 top-2.5 text-xs text-slate-400 hover:text-slate-600"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Brand Filter */}
            <select
              value={brandFilter}
              onChange={e => setBrandFilter(e.target.value)}
              className="bg-white border border-slate-300 text-xs text-slate-800 px-3 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs cursor-pointer font-medium"
            >
              <option value="ALL">All AI Brands</option>
              <option value="openai">OpenAI / ChatGPT</option>
              <option value="anthropic">Anthropic / Claude</option>
              <option value="google_ai">Google AI / Gemini</option>
              <option value="deepseek">DeepSeek</option>
              <option value="midjourney">Midjourney</option>
              <option value="ollama">Ollama</option>
              <option value="ai_ecosystem_library">Ecosystem Libraries</option>
              <option value="general_ai_terms">General AI Terms</option>
            </select>

            {/* 5-Verdict Filter */}
            <select
              value={verdictFilter}
              onChange={e => setVerdictFilter(e.target.value)}
              className="bg-white border border-slate-300 text-xs text-slate-800 px-3 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs cursor-pointer font-medium"
            >
              <option value="ALL">All Verdicts</option>
              <option value="Confirmed Malicious">Confirmed Malicious (&ge; 75)</option>
              <option value="Suspected">Suspected (40 - 74)</option>
              <option value="Needs Review">Needs Review (&lt; 40)</option>
              <option value="Likely Benign">Likely Benign (Allowlist)</option>
              <option value="Taken Down">Taken Down</option>
            </select>

            {/* Raw vs Defanged Toggle */}
            <button
              onClick={() => setShowRaw(!showRaw)}
              className={`px-2.5 py-2 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-all shadow-2xs cursor-pointer ${
                showRaw
                  ? 'bg-amber-100 text-amber-900 border-amber-300 font-semibold'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
              title={showRaw ? "Showing raw active links (CAUTION)" : "Defanged safely (default)"}
            >
              {showRaw ? <Eye className="w-3.5 h-3.5 text-amber-600" /> : <EyeOff className="w-3.5 h-3.5 text-slate-500" />}
              <span>{showRaw ? 'Raw Mode' : 'Defanged'}</span>
            </button>

            {/* Needs Review Filter toggle */}
            <button
              onClick={() => setReviewFilter(!reviewFilter)}
              className={`px-2.5 py-2 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-all shadow-2xs cursor-pointer ${
                reviewFilter
                  ? 'bg-amber-100 text-amber-900 border-amber-300 font-semibold'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              <span>Review Only</span>
            </button>
          </div>
        </div>

        {/* Horizontally scrollable table with sticky first column */}
        <div className="overflow-x-auto relative">
          <table className="w-full text-left text-xs whitespace-nowrap">
            <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider border-b border-slate-200 select-none text-[11px]">
              <tr>
                {/* Sticky First Column */}
                <th className="py-3 px-4 sticky left-0 z-20 bg-slate-50 shadow-[2px_0_5px_rgba(0,0,0,0.03)] border-r border-slate-200 min-w-[280px]">
                  Observable Indicator (Defanged)
                </th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-900"
                  onClick={() => toggleSort('verdict')}
                >
                  <div className="flex items-center gap-1">
                    <span>Verdict</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-400" />
                  </div>
                </th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-900"
                  onClick={() => toggleSort('score')}
                >
                  <div className="flex items-center gap-1">
                    <span>Score / Why</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-400" />
                  </div>
                </th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-900"
                  onClick={() => toggleSort('brand')}
                >
                  <div className="flex items-center gap-1">
                    <span>Target Brand</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-400" />
                  </div>
                </th>
                <th className="py-3 px-4">Lure Vector</th>
                <th className="py-3 px-4">Attributed Malware / Source</th>
                <th className="py-3 px-4">Discovery Source</th>
                <th className="py-3 px-4">Status</th>
                <th 
                  className="py-3 px-4 cursor-pointer hover:text-slate-900"
                  onClick={() => toggleSort('time')}
                >
                  <div className="flex items-center gap-1">
                    <span>First Seen / Checked</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-400" />
                  </div>
                </th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono bg-white">
              {filteredIndicators.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-slate-500 font-sans">
                    No indicators matched the selected filters.
                  </td>
                </tr>
              ) : (
                filteredIndicators.map(item => {
                  const rawVal = item.value || item.indicator || '';
                  const displayVal = showRaw ? refang(rawVal) : defang(rawVal);
                  const score = item.confidence_score;
                  const verdict = item.verdict || (score >= 75 ? 'Confirmed Malicious' : 'Suspected');

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

                  const brandFormatted = (item.target_brand || 'generic_ai')
                    .replace(/_/g, ' ')
                    .toUpperCase();

                  const isAttached = attachedId === item.id;
                  const isAbusedLegit = item.is_abused_legitimate_service;

                  return (
                    <tr
                      key={item.id}
                      onClick={() => onSelectIndicator(item)}
                      className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                    >
                      {/* Sticky Observable Indicator */}
                      <td className="py-3 px-4 text-slate-900 font-semibold sticky left-0 z-10 bg-white group-hover:bg-slate-50/80 shadow-[2px_0_5px_rgba(0,0,0,0.03)] border-r border-slate-200 max-w-xs transition-colors">
                        <div className="flex items-center space-x-2">
                          <span className="truncate select-all text-xs font-mono text-slate-900" title={displayVal}>
                            {displayVal}
                          </span>

                          {/* Quick Copy Defanged button */}
                          <button
                            onClick={e => handleCopyDefanged(e, rawVal, item.id)}
                            className="p-1 text-slate-400 hover:text-slate-700 rounded hover:bg-slate-100 transition-colors shrink-0"
                            title="Copy Defanged (Safe for tickets)"
                          >
                            {copiedId === item.id ? (
                              <Check className="w-3.5 h-3.5 text-emerald-600" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>

                          {/* Copy Raw button with warning */}
                          <button
                            onClick={e => handleRequestCopyRaw(e, rawVal)}
                            className="p-1 text-slate-400 hover:text-amber-700 rounded hover:bg-amber-50 transition-colors shrink-0 text-[10px] font-semibold"
                            title="Copy Raw (Warning modal)"
                          >
                            raw
                          </button>

                          {/* Review badge */}
                          {item.is_flagged_for_review && (
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded font-sans font-bold bg-amber-50 text-amber-800 border border-amber-200 shrink-0"
                              title="Flagged for analyst review"
                            >
                              REVIEW
                            </span>
                          )}

                          {/* Abused legitimate service tag */}
                          {isAbusedLegit && (
                            <span
                              className="text-[9px] px-1.5 py-0.5 rounded font-sans font-medium bg-blue-50 text-blue-700 border border-blue-200 shrink-0"
                              title="Abused multi-tenant service. Block URL path only, do NOT block whole apex domain!"
                            >
                              ABUSED SERVICE (PATH ONLY)
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Verdict */}
                      <td className="py-3 px-4 font-sans whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-bold ${verdictBadgeClass}`}>
                          {verdict}
                        </span>
                      </td>

                      {/* Score with "Why this score" drawer trigger */}
                      <td className="py-3 px-4 whitespace-nowrap font-sans">
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            setDrawerIndicator(item);
                          }}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-100 hover:bg-blue-50 hover:border-blue-300 border border-slate-200 text-slate-800 transition-all text-left cursor-pointer"
                          title="Click to view signal breakdown and scoring weights"
                        >
                          <span className="font-mono font-bold text-xs text-blue-700">{score}/100</span>
                          <span className="text-[10px] text-slate-500 flex items-center gap-0.5 font-medium">
                            Why?
                            <HelpCircle className="w-3 h-3 text-blue-600" />
                          </span>
                        </button>
                      </td>

                      {/* Target Brand */}
                      <td className="py-3 px-4 font-sans whitespace-nowrap">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                          {brandFormatted}
                        </span>
                      </td>

                      {/* Lure Vector */}
                      <td className="py-3 px-4 text-slate-600 font-sans whitespace-nowrap capitalize">
                        {(item.lure_type || 'lure').replace(/_/g, ' ')}
                      </td>

                      {/* Attributed Threat */}
                      <td className="py-3 px-4 font-sans whitespace-nowrap">
                        <div className="flex flex-col">
                          <span className="text-amber-800 font-medium">
                            {item.associated_malware || 'Family unknown'}
                          </span>
                          {item.malware_attribution_source && (
                            <span className="text-[10px] text-slate-500 font-mono">
                              Source: {item.malware_attribution_source}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Discovery Source & direct link */}
                      <td className="py-3 px-4 font-sans whitespace-nowrap">
                        {item.source_url ? (
                          <a
                            href={item.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={e => e.stopPropagation()}
                            className="text-blue-600 hover:text-blue-800 underline flex items-center gap-1 text-xs font-medium"
                            title={`Open evidence record on ${item.source}`}
                          >
                            <span>{item.source}</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ) : (
                          <span className="text-slate-600">{item.source}</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 font-sans whitespace-nowrap">
                        <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${
                          item.status === 'Taken Down'
                            ? 'bg-slate-100 text-slate-600 border border-slate-200'
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        }`}>
                          {item.status || 'Active'}
                        </span>
                      </td>

                      {/* First seen & last checked */}
                      <td className="py-3 px-4 text-slate-600 text-[11px] font-sans whitespace-nowrap">
                        <div title={`First seen: ${item.first_seen}`}>
                          {new Date(item.first_seen).toISOString().split('T')[0]}
                        </div>
                        {item.last_checked && (
                          <div className="text-[10px] text-slate-500">
                            Chk: {new Date(item.last_checked).toISOString().split('T')[0]}
                          </div>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right font-sans whitespace-nowrap">
                        <div className="flex items-center justify-end space-x-1.5" onClick={e => e.stopPropagation()}>
                          <button
                            onClick={() => onTriage(rawVal, item)}
                            className="p-1.5 rounded-lg bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 transition-all text-xs flex items-center gap-1 cursor-pointer font-medium"
                            title="Open Grounded AI Triage"
                          >
                            <Sparkles className="w-3.5 h-3.5" />
                            <span className="hidden sm:inline text-[11px]">Triage</span>
                          </button>

                          <button
                            onClick={e => handleQuickAttachCase(e, item)}
                            className={`p-1.5 rounded-lg border text-xs flex items-center gap-1 transition-all cursor-pointer font-medium ${
                              isAttached
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200 font-semibold'
                                : 'bg-slate-100 text-slate-700 border-slate-200 hover:bg-slate-200'
                            }`}
                            title="Attach to active investigation in Casebook"
                          >
                            <FolderPlus className="w-3.5 h-3.5" />
                            <span className="hidden sm:inline text-[11px]">
                              {isAttached ? 'Attached!' : 'Case'}
                            </span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table footer disclaimer */}
        <div className="px-5 py-3 border-t border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between text-[11px] text-slate-500 gap-2">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
            <span>TLP:CLEAR &bull; Defensive operational guidance &bull; Verify against internal DNS logs before blocking</span>
          </div>
          <div>
            Showing {filteredIndicators.length} of {scoredIndicators.length} indicators
          </div>
        </div>
      </div>

      {/* "Why This Score" Drawer */}
      <ScoreRationaleDrawer
        indicator={drawerIndicator}
        onClose={() => setDrawerIndicator(null)}
      />

      {/* Warning Modal for Copying Raw Indicator */}
      {rawWarningItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white border border-amber-300 rounded-xl w-full max-w-md overflow-hidden shadow-2xl p-5 space-y-4 text-slate-800">
            <div className="flex items-center gap-2.5 text-amber-700">
              <AlertOctagon className="w-6 h-6 shrink-0" />
              <h3 className="text-base font-bold text-slate-900">Copy Raw Indicator Warning</h3>
            </div>
            
            <p className="text-xs text-slate-700 leading-relaxed">
              You are about to copy the <strong>active, non-defanged</strong> indicator:
            </p>
            
            <div className="bg-rose-50 p-2.5 rounded font-mono text-xs text-rose-800 border border-rose-200 break-all select-all">
              {rawWarningItem}
            </div>

            <p className="text-[11px] text-slate-500 leading-relaxed">
              Pasting this raw URL or domain into chat platforms, incident tickets, or email clients may trigger automatic link prefetching or DNS lookups against attacker infrastructure.
            </p>

            <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-200">
              <button
                onClick={() => setRawWarningItem(null)}
                className="px-3 py-1.5 text-xs text-slate-600 hover:text-slate-900 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmCopyRaw}
                className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-amber-600 hover:bg-amber-700 text-white transition-all shadow-xs cursor-pointer"
              >
                Copy Raw Anyway
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
