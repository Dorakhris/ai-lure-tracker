import React from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Info, ArrowUpRight, ShieldCheck, Scale } from 'lucide-react';
import { EnrichedIndicator, ScoringBreakdown } from '../types/threat';
import { defang } from '../utils/defang';

interface ScoreRationaleDrawerProps {
  indicator: EnrichedIndicator | null;
  onClose: () => void;
}

export const ScoreRationaleDrawer: React.FC<ScoreRationaleDrawerProps> = ({
  indicator,
  onClose
}) => {
  if (!indicator) return null;

  const scoring = indicator.scoring_breakdown;
  const score = indicator.confidence_score;
  const verdict = indicator.verdict || (score >= 75 ? 'Confirmed Malicious' : 'Suspected');
  const rule = indicator.verdict_rule_matched || 'Scoring engine heuristic evaluation';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
      <div 
        className="w-full max-w-md bg-white border-l border-slate-200 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200 text-slate-800"
        onClick={e => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900">Why This Score?</h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-200 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Indicator Summary Banner */}
        <div className="p-4 bg-white border-b border-slate-200 space-y-2">
          <div className="text-[11px] text-slate-500 uppercase font-semibold tracking-wider">Observable</div>
          <div className="font-mono text-xs text-blue-700 font-bold break-all bg-slate-50 p-2.5 rounded-lg border border-slate-200">
            {defang(indicator.value)}
          </div>
          
          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center gap-1.5">
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold font-mono ${
                verdict === 'Confirmed Malicious' 
                  ? 'bg-rose-50 text-rose-700 border border-rose-200'
                  : verdict === 'Suspected'
                  ? 'bg-amber-50 text-amber-800 border border-amber-200'
                  : verdict === 'Likely Benign'
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'bg-slate-100 text-slate-700 border border-slate-200'
              }`}>
                {verdict}
              </span>
              <span className="text-xs font-bold text-slate-900 font-mono">{score}/100</span>
            </div>
            <span className="text-[11px] text-slate-500 font-mono">v1.0 Standard</span>
          </div>
        </div>

        {/* Rule Matched Banner */}
        <div className="p-4 bg-blue-50/60 border-b border-blue-100 text-xs">
          <div className="text-[11px] font-semibold text-blue-800 mb-1 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
            <span>Verdict Rule Evaluation</span>
          </div>
          <p className="text-slate-700 text-[11px] leading-relaxed">
            {rule}
          </p>
        </div>

        {/* Signals Breakdown List */}
        <div className="p-5 flex-1 overflow-y-auto space-y-3">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
            Contributing Evidence Signals ({scoring?.factors?.length || 0})
          </div>

          {scoring?.factors && scoring.factors.length > 0 ? (
            scoring.factors.map((factor, idx) => {
              const isPositive = factor.scoreImpact > 0;
              const isNegative = factor.scoreImpact < 0;

              return (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg border border-slate-200 bg-white shadow-2xs space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-800">{factor.name}</span>
                    <span className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${
                      isPositive
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : isNegative
                        ? 'bg-rose-50 text-rose-700 border border-rose-200'
                        : 'bg-slate-100 text-slate-700 border border-slate-200'
                    }`}>
                      {factor.scoreImpact > 0 ? `+${factor.scoreImpact}` : factor.scoreImpact}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed">
                    {factor.rationale}
                  </p>
                </div>
              );
            })
          ) : (
            <div className="text-xs text-slate-500">No scoring signals documented.</div>
          )}

          {/* Caveats & Manual Review Reasons */}
          {scoring?.reviewReasons && scoring.reviewReasons.length > 0 && (
            <div className="p-3.5 rounded-lg border border-amber-200 bg-amber-50/70 space-y-1.5 mt-4">
              <div className="text-xs font-semibold text-amber-800 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                <span>Analyst Caveats &amp; Limitations</span>
              </div>
              <ul className="list-disc list-inside text-[11px] text-amber-900 space-y-1">
                {scoring.reviewReasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-600">
          <span>Formula: Confirmed Malicious &ge; 75</span>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 font-medium transition-colors cursor-pointer shadow-2xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
