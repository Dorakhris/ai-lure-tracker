import React, { useState } from 'react';
import { 
  Scale, 
  RotateCcw, 
  Save, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  Info, 
  Sliders, 
  History, 
  Sparkles,
  BookOpen,
  Plus,
  Trash2
} from 'lucide-react';
import { 
  getActiveScoringConfig, 
  saveScoringConfig, 
  resetScoringConfig, 
  DEFAULT_SCORING_CONFIG,
  calculateEvidenceBasedScore 
} from '../services/scoringEngine';
import { ScoringRuleConfig, EnrichedIndicator } from '../types/threat';
import { defang } from '../utils/defang';

interface ScoringEngineViewProps {
  onWeightsUpdated?: () => void;
  indicators: EnrichedIndicator[];
}

export const ScoringEngineView: React.FC<ScoringEngineViewProps> = ({
  onWeightsUpdated,
  indicators
}) => {
  const [config, setConfig] = useState<ScoringRuleConfig>(getActiveScoringConfig());
  const [savedNotice, setSavedNotice] = useState<string | null>(null);
  const [simIndicatorValue, setSimIndicatorValue] = useState<string>('https://claude-35-sonnet-pro-free.icu/download/setup.exe');
  const [newAllowlistDomain, setNewAllowlistDomain] = useState<string>('');

  const handleWeightChange = (key: keyof ScoringRuleConfig['weights'], value: number) => {
    setConfig(prev => ({
      ...prev,
      weights: {
        ...prev.weights,
        [key]: value
      }
    }));
  };

  const handleSave = () => {
    const nextVersion = `Scoring v1.${(config.changelog.length).toString()}`;
    const newConfig: ScoringRuleConfig = {
      ...config,
      version: nextVersion,
      updatedAt: new Date().toISOString(),
      changelog: [
        {
          version: nextVersion,
          date: new Date().toISOString().split('T')[0],
          author: 'SOC Threat Investigator',
          description: `Custom weights updated: Authoritative (+${config.weights.authoritativeSourceConfirms}), Corroboration (+${config.weights.secondSourceAgrees}), Brand (+${config.weights.brandInHostname}).`
        },
        ...config.changelog
      ]
    };

    saveScoringConfig(newConfig);
    setConfig(newConfig);
    setSavedNotice(`Saved as ${nextVersion}!`);
    setTimeout(() => setSavedNotice(null), 3000);
    if (onWeightsUpdated) onWeightsUpdated();
  };

  const handleReset = () => {
    const def = resetScoringConfig();
    setConfig(def);
    setSavedNotice('Reset to default Scoring v1.0 baseline.');
    setTimeout(() => setSavedNotice(null), 3000);
    if (onWeightsUpdated) onWeightsUpdated();
  };

  const handleAddAllowlist = () => {
    if (!newAllowlistDomain.trim()) return;
    const clean = newAllowlistDomain.trim().toLowerCase();
    if (config.allowlist.includes(clean)) return;

    const updated = {
      ...config,
      allowlist: [...config.allowlist, clean]
    };
    saveScoringConfig(updated);
    setConfig(updated);
    setNewAllowlistDomain('');
    if (onWeightsUpdated) onWeightsUpdated();
  };

  const handleRemoveAllowlist = (domain: string) => {
    const updated = {
      ...config,
      allowlist: config.allowlist.filter(d => d !== domain)
    };
    saveScoringConfig(updated);
    setConfig(updated);
    if (onWeightsUpdated) onWeightsUpdated();
  };

  // Run simulation against simulated observable
  const simResult = calculateEvidenceBasedScore(
    {
      value: simIndicatorValue,
      source: 'ThreatFox',
      target_brand: 'anthropic',
      associated_malware: 'LummaC2 Stealer',
      first_seen: new Date().toISOString(),
      enrichment: {
        domain_age_days: 2,
        registration_date: new Date().toISOString(),
        registrar: 'Hostinger',
        resolved_ips: ['185.100.1.1'],
        asn: 'AS44444',
        asn_org: 'Bulletproof Services',
        country: 'NL',
        has_download_link: true,
        download_extensions: ['.exe'],
        has_login_form: false,
        urlscan_id: null,
        urlscan_screenshot_url: null,
        virustotal_detections: 14,
        virustotal_positives: 14,
        virustotal_link: null,
        shodan_ports: [],
        page_title: 'Claude Free Download'
      }
    },
    config
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
            <Scale className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-900">Configurable CTI Scoring Engine</h2>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                {config.version}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Transparent, evidence-driven signal weighting matrix with version history &amp; allowlist controls
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleReset}
            className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-100 border border-slate-300 shadow-xs flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
            <span>Reset Defaults</span>
          </button>

          <button
            onClick={handleSave}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 flex items-center gap-1.5 shadow-xs transition-all active:scale-95"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Weights</span>
          </button>
        </div>
      </div>

      {savedNotice && (
        <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          <span>{savedNotice}</span>
        </div>
      )}

      {/* Main Grid: Weights Editor + Simulator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left: Weights Configuration (2 Cols) */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Signal Weights Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Sliders className="w-4 h-4 text-blue-600" />
                <span>Evidence Signal Weights</span>
              </h3>
              <span className="text-xs text-slate-500 font-mono">Bands: &ge;75 High / 40-74 Suspected / &lt;40 Needs Review</span>
            </div>

            <div className="space-y-4 text-xs">
              {/* Authoritative Source */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Authoritative Source Confirms (+40)</div>
                  <div className="text-[11px] text-slate-500">ThreatFox, URLhaus, or verified OpenPhish active payload sensor</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="10"
                    max="60"
                    step="5"
                    value={config.weights.authoritativeSourceConfirms}
                    onChange={e => handleWeightChange('authoritativeSourceConfirms', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.authoritativeSourceConfirms}
                  </span>
                </div>
              </div>

              {/* Second Independent Source */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Second Independent Source Agrees (+20)</div>
                  <div className="text-[11px] text-slate-500">Multiple independent sensors or AV scanning engines agree on classification</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="5"
                    max="35"
                    step="5"
                    value={config.weights.secondSourceAgrees}
                    onChange={e => handleWeightChange('secondSourceAgrees', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.secondSourceAgrees}
                  </span>
                </div>
              </div>

              {/* Registered <= 7 days ago */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Newly Registered Domain &le; 7 Days (+10)</div>
                  <div className="text-[11px] text-slate-500">Recent RDAP/WHOIS creation date within disposable infostealer staging window</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="20"
                    step="5"
                    value={config.weights.registeredWithin7Days}
                    onChange={e => handleWeightChange('registeredWithin7Days', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.registeredWithin7Days}
                  </span>
                </div>
              </div>

              {/* AI Brand in Hostname */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">AI Brand in Hostname (+10)</div>
                  <div className="text-[11px] text-slate-500">Matches commercial AI brand naming (ChatGPT, Claude, Gemini, DeepSeek, etc.)</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="20"
                    step="5"
                    value={config.weights.brandInHostname}
                    onChange={e => handleWeightChange('brandInHostname', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.brandInHostname}
                  </span>
                </div>
              </div>

              {/* Download link / login form */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Download Link / Login Form Present (+10)</div>
                  <div className="text-[11px] text-slate-500">Direct payload weaponization (.exe/.zip) or credential harvesting form</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="25"
                    step="5"
                    value={config.weights.downloadOrLoginPresent}
                    onChange={e => handleWeightChange('downloadOrLoginPresent', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.downloadOrLoginPresent}
                  </span>
                </div>
              </div>

              {/* Known High-risk ASN */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Known High-Risk ASN (+5)</div>
                  <div className="text-[11px] text-slate-500">Hosted in bulletproof or frequently abused autonomous system</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="15"
                    step="5"
                    value={config.weights.knownHighRiskAsn}
                    onChange={e => handleWeightChange('knownHighRiskAsn', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.knownHighRiskAsn}
                  </span>
                </div>
              </div>

              {/* Campaign Cluster Match */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-800">Matches Campaign Cluster (+5)</div>
                  <div className="text-[11px] text-slate-500">Shares verified infrastructure pivots with tracked campaign cluster</div>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="range"
                    min="0"
                    max="15"
                    step="5"
                    value={config.weights.matchesCampaignCluster}
                    onChange={e => handleWeightChange('matchesCampaignCluster', parseInt(e.target.value))}
                    className="w-28 accent-blue-600"
                  />
                  <span className="font-mono font-bold text-emerald-700 text-xs w-10 text-right">
                    +{config.weights.matchesCampaignCluster}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Editable Official Allowlist */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-200">
              <div>
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  <span>Official Vendor Allowlist (FP Suppression)</span>
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Any indicator matching these authorized root domains automatically overrides to <strong className="text-slate-800">Likely Benign</strong>.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newAllowlistDomain}
                onChange={e => setNewAllowlistDomain(e.target.value)}
                placeholder="e.g. mistral.ai"
                className="bg-white border border-slate-300 text-xs text-slate-800 px-3 py-1.5 rounded-lg focus:outline-none focus:border-blue-500 w-48 font-mono shadow-xs"
              />
              <button
                type="button"
                onClick={handleAddAllowlist}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white flex items-center gap-1 shadow-xs transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Domain</span>
              </button>
            </div>

            <div className="flex flex-wrap gap-2 pt-2">
              {config.allowlist.map(domain => (
                <span
                  key={domain}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700"
                >
                  <span>{domain}</span>
                  <button
                    onClick={() => handleRemoveAllowlist(domain)}
                    className="text-slate-400 hover:text-rose-600 transition-colors"
                    title={`Remove ${domain} from allowlist`}
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* Version Changelog */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <History className="w-4 h-4 text-purple-600" />
              <span>Scoring Engine Version Changelog</span>
            </h3>

            <div className="space-y-2">
              {config.changelog.map((entry, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-blue-700">{entry.version}</span>
                    <span className="text-[11px] text-slate-500">{entry.date} &bull; {entry.author}</span>
                  </div>
                  <p className="text-slate-600 text-[11px] leading-relaxed">{entry.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Live Interactive Simulator */}
        <div className="space-y-5">
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-500" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Live Scoring Simulator
              </h3>
            </div>

            <p className="text-[11px] text-slate-500 leading-relaxed">
              Test how your active weights score an indicator in real time:
            </p>

            <div className="space-y-2">
              <label className="text-[11px] text-slate-600 font-semibold block">Test Observable URI:</label>
              <input
                type="text"
                value={simIndicatorValue}
                onChange={e => setSimIndicatorValue(e.target.value)}
                className="w-full bg-white border border-slate-300 text-xs font-mono text-slate-800 p-2 rounded-lg focus:outline-none focus:border-blue-500 break-all shadow-xs"
              />
            </div>

            {/* Simulation Output Card */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700">Computed Verdict:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                  simResult.verdict === 'Confirmed Malicious'
                    ? 'bg-rose-50 text-rose-700 border border-rose-200'
                    : 'bg-amber-50 text-amber-700 border border-amber-200'
                }`}>
                  {simResult.verdict}
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-600 font-medium">Confidence Score:</span>
                <span className="font-mono font-bold text-lg text-blue-700">{simResult.totalScore}/100</span>
              </div>

              <div className="text-[11px] text-slate-600 pt-2 border-t border-slate-200">
                <span className="font-semibold text-slate-800 block mb-1">Rule Matched:</span>
                <span className="text-blue-700 font-medium">{simResult.verdictRuleMatched}</span>
              </div>

              <div className="space-y-1 pt-2 border-t border-slate-200 text-[11px]">
                <span className="font-semibold text-slate-700 block mb-1">Applied Signals:</span>
                {simResult.factors.map((f, i) => (
                  <div key={i} className="flex justify-between text-slate-600">
                    <span className="truncate pr-2">{f.name}</span>
                    <span className="font-mono font-semibold text-emerald-700 shrink-0">+{f.scoreImpact}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
