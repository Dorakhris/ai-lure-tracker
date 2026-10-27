import React from 'react';
import { X, HelpCircle, Shield, AlertOctagon, CheckCircle2 } from 'lucide-react';

interface HeuristicGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const HeuristicGuideModal: React.FC<HeuristicGuideModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const rules = [
    { signal: 'Base Match', score: '+40', rationale: 'Verified match on monitored AI brand keyword regex.' },
    { signal: 'Domain Age ≤ 7 days', score: '+25', rationale: 'Newly Registered Domains (NRDs) represent prime throwaway infrastructure.' },
    { signal: 'Domain Age ≤ 14 days', score: '+15', rationale: 'High-risk window before takedowns or security classification.' },
    { signal: 'Suspicious TLD (.top, .icu, .buzz, .cfd, .lat, .xyz)', score: '+15', rationale: 'Common cheap, bulletproof TLDs favored by infostealer distributors.' },
    { signal: 'Executable Download Lure (.exe, .msi, .dmg, .zip, .iso)', score: '+30', rationale: 'Direct payload delivery mechanism for infostealer infections.' },
    { signal: 'Credential Phishing Form (login, signin, auth, portal)', score: '+25', rationale: 'Harvests user credentials or active AI session tokens.' },
    { signal: 'Threat Feed Corroboration (abuse.ch / VT ≥ 2)', score: '+30', rationale: 'Multi-source confirmation from community threat sensors.' },
    { signal: 'Package Typosquat (Levenshtein distance = 1)', score: '+35', rationale: 'Intentional dependency confusion / software supply-chain attack.' },
  ];

  return (
    <div className="fixed inset-0 bg-black/75 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="glass-panel w-full max-w-2xl rounded-2xl border border-gray-700 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between bg-gray-900/90">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <HelpCircle className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">CTI Confidence Scoring Methodology</h3>
              <p className="text-xs text-slate-400">Algorithmic scoring between 0 and 100 based on corroborated threat signals</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6 overflow-y-auto custom-scroll flex-1 text-xs">
          {/* Confidence Tiers */}
          <div>
            <h4 className="font-bold text-white uppercase tracking-wider mb-2.5">Confidence Tiers &amp; SOC Actions</h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-red-950/20 border border-red-800/40 space-y-1">
                <span className="font-bold text-red-400 flex items-center gap-1">
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>HIGH (Score ≥ 75)</span>
                </span>
                <p className="text-slate-300">
                  Immediate blocking recommended. High certainty of active malicious campaign.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 space-y-1">
                <span className="font-bold text-amber-400 flex items-center gap-1">
                  <Shield className="w-3.5 h-3.5" />
                  <span>MEDIUM (50 - 74)</span>
                </span>
                <p className="text-slate-300">
                  Suspicious infrastructure. Enforce proxy sandboxing, SSL inspection, and alerting.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-gray-900 border border-gray-800 space-y-1">
                <span className="font-bold text-slate-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>LOW (&lt; 50)</span>
                </span>
                <p className="text-slate-400">
                  Potential false positive or parked domain. Monitored for weaponization.
                </p>
              </div>
            </div>
          </div>

          {/* Scoring Heuristic Table */}
          <div>
            <h4 className="font-bold text-white uppercase tracking-wider mb-2.5">Signal Weighting Matrix</h4>
            <div className="rounded-lg border border-gray-800 overflow-hidden">
              <table className="w-full text-left">
                <thead className="bg-gray-900 text-slate-400 uppercase font-semibold border-b border-gray-800 text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Signal / Heuristic</th>
                    <th className="py-2.5 px-3">Impact</th>
                    <th className="py-2.5 px-3">Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono text-slate-300">
                  {rules.map((r, i) => (
                    <tr key={i} className="hover:bg-gray-800/30">
                      <td className="py-2.5 px-3 font-semibold text-white font-sans">{r.signal}</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">{r.score}</td>
                      <td className="py-2.5 px-3 font-sans text-slate-400">{r.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
