import React from 'react';
import { Database, AlertOctagon, Cpu, Bug, Target, ShieldCheck } from 'lucide-react';
import { EnrichedIndicator } from '../types/threat';

interface MetricCardsProps {
  indicators: EnrichedIndicator[];
}

export const MetricCards: React.FC<MetricCardsProps> = ({ indicators }) => {
  const total = indicators.length;
  
  // Confirmed Malicious Blocks (Strict rule: Confirmed Malicious or Score >= 75 with payload)
  const confirmedBlocks = indicators.filter(
    i => i.verdict === 'Confirmed Malicious' || i.confidence_score >= 75
  ).length;
  
  // Exclude ecosystem libraries and general AI terms from genuine corporate brand count
  const nonBrandCategories = new Set(['ai_ecosystem_library', 'general_ai_terms', 'generic_ai', 'all']);
  const distinctBrands = new Set(
    indicators
      .map(i => (i.target_brand || '').toLowerCase().trim())
      .filter(b => b && !nonBrandCategories.has(b))
  );

  // Top Lure Delivery Vector
  const lureCounts: Record<string, number> = {};
  indicators.forEach(i => {
    const lure = i.lure_type || 'unclassified';
    let label = lure.replace(/_/g, ' ');
    if (label === 'fake installer') label = 'Fake Installer (.exe/.zip)';
    else if (label === 'credential phish') label = 'Credential Phishing Form';
    else if (label === 'lookalike package' || label === 'trojanized dependency') label = 'Lookalike Package';
    else if (label === 'suspicious registration') label = 'Staged Domain Candidate';
    
    lureCounts[label] = (lureCounts[label] || 0) + 1;
  });

  const sortedLures = Object.entries(lureCounts).sort((a, b) => b[1] - a[1]);
  const topLureName = sortedLures[0] ? sortedLures[0][0] : 'Fake Installer (.exe/.zip)';
  const topLureCount = sortedLures[0] ? sortedLures[0][1] : 0;

  // Confirmed malware families count (URLhaus/ThreatFox confirmed)
  const confirmedMalwareIocs = indicators.filter(
    i => i.associated_malware && 
    !i.associated_malware.toLowerCase().includes('unknown') && 
    !i.associated_malware.toLowerCase().includes('unattributed') &&
    !i.associated_malware.toLowerCase().includes('suspected')
  ).length;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Indicators */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 hover:border-slate-300 transition-all shadow-xs">
        <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
          <span>Tracked Indicators</span>
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <Database className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 text-3xl font-extrabold text-slate-900" id="statTotalIocs">
          {total}
        </div>
        <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
          <span>Active &amp; Staged AI Lures</span>
          <span className="text-[11px] text-emerald-600 font-mono font-medium">Deduplicated</span>
        </div>
      </div>

      {/* Confirmed Malicious Blocks */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 hover:border-slate-300 transition-all shadow-xs">
        <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
          <span>Confirmed Malicious</span>
          <div className="p-1.5 rounded-lg bg-rose-50 text-rose-600 border border-rose-100">
            <AlertOctagon className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 text-3xl font-extrabold text-rose-600" id="statHighConf">
          {confirmedBlocks}
        </div>
        <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
          <span>Authoritative / Corroborated</span>
          <span className="text-[11px] text-rose-600 font-mono font-medium">Score &ge; 75</span>
        </div>
      </div>

      {/* Targeted AI Brands */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 hover:border-slate-300 transition-all shadow-xs">
        <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
          <span>Impersonated Brands</span>
          <div className="p-1.5 rounded-lg bg-indigo-50 text-indigo-600 border border-indigo-100">
            <Cpu className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 text-3xl font-extrabold text-indigo-600" id="statBrandsCount">
          {distinctBrands.size}
        </div>
        <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
          <span title="ChatGPT, Claude, Gemini, DeepSeek, Midjourney, Ollama">Commercial AI Brands</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-medium">Excluded generic</span>
        </div>
      </div>

      {/* Top Lure Type */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 hover:border-slate-300 transition-all shadow-xs">
        <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
          <span>Top Lure Delivery Type</span>
          <div className="p-1.5 rounded-lg bg-amber-50 text-amber-600 border border-amber-100">
            <Target className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-3 text-lg font-bold text-slate-800 truncate" title={`${topLureName} (${topLureCount} indicators)`}>
          {topLureName}
        </div>
        <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
          <span>{topLureCount} observed lures</span>
          <span className="text-[11px] text-amber-700 font-mono font-medium">{confirmedMalwareIocs} with payload</span>
        </div>
      </div>
    </div>
  );
};
