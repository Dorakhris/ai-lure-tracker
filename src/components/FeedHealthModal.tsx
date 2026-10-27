import React from 'react';
import { 
  X, 
  Activity, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Clock, 
  Database, 
  ShieldCheck,
  ExternalLink
} from 'lucide-react';
import { computeFeedHealth } from '../services/feedHealthService';
import { EnrichedIndicator } from '../types/threat';

interface FeedHealthModalProps {
  isOpen: boolean;
  onClose: () => void;
  indicators: EnrichedIndicator[];
}

export const FeedHealthModal: React.FC<FeedHealthModalProps> = ({
  isOpen,
  onClose,
  indicators
}) => {
  if (!isOpen) return null;

  const health = computeFeedHealth(indicators);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center space-x-2.5">
            <Activity className="w-5 h-5 text-emerald-600" />
            <div>
              <h2 className="text-base font-bold text-slate-900">CTI Upstream Feed Health</h2>
              <p className="text-xs text-slate-500">Live operational telemetry &amp; ingestion status across 7 feeds</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Status banner */}
        <div className="px-6 py-3 bg-white border-b border-slate-200 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${health.isStale ? 'bg-amber-500 animate-pulse' : 'bg-emerald-500'}`}></span>
            <span className="text-slate-600 font-medium">Feed Integrity:</span>
            <span className={`font-semibold ${health.isStale ? 'text-amber-700' : 'text-emerald-700'}`}>
              {health.isStale ? 'STALE (>60m since last update)' : 'HEALTHY & SYNCHRONIZED'}
            </span>
          </div>
          <div className="text-slate-500 font-mono text-[11px] flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" />
            <span>Updated: {health.lastFeedUpdateUtc.replace('T', ' ').slice(0, 19)} UTC</span>
          </div>
        </div>

        {/* Feed source list */}
        <div className="p-6 space-y-3 overflow-y-auto">
          {health.sources.map((src) => {
            return (
              <div
                key={src.name}
                className="p-3.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100/60 transition-colors space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    {src.status === 'OK' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    ) : src.status === 'delayed' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-600 shrink-0" />
                    )}
                    <span className="text-sm font-semibold text-slate-800">{src.name}</span>
                    {src.authoritative ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-medium">
                        Authoritative Source
                      </span>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 text-slate-700 border border-slate-300 font-medium">
                        Secondary / Candidate
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs">
                    <span className="font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-semibold">
                      {src.status.toUpperCase()}
                    </span>
                    <span className="text-slate-500 font-mono text-[11px]">{src.latencyMs}ms</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs text-slate-500 pt-1 border-t border-slate-200">
                  <div className="flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-slate-400" />
                    <span>Records: <strong className="text-slate-800">{src.recordCount}</strong></span>
                  </div>
                  <div className="flex items-center gap-1.5 col-span-2">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    <span className="truncate">Last Fetch: {src.lastSuccessfulFetch.replace('T', ' ').slice(11, 19)} UTC</span>
                  </div>
                </div>

                {src.notes && (
                  <p className="text-[11px] text-slate-600 bg-white p-2 rounded border border-slate-200">
                    {src.notes}
                  </p>
                )}
              </div>
            );
          })}

          <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 space-y-1">
            <div className="font-semibold flex items-center gap-1.5 text-amber-950">
              <ShieldCheck className="w-4 h-4 text-amber-600" />
              <span>CTI Integrity Commitment</span>
            </div>
            <p className="text-[11px] text-amber-800 leading-relaxed">
              If an upstream feed is unreachable, delayed, or rate-limited, AI Lure Tracker displays its true status rather than faking health metrics. Lookalike domain registrations alone never generate confirmed alerts without independent payload telemetry.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
          <button
            onClick={onClose}
            className="text-xs font-semibold px-4 py-2 rounded-lg bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 shadow-xs transition-colors"
          >
            Close Feed Health
          </button>
        </div>

      </div>
    </div>
  );
};
