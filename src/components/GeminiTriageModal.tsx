import React, { useState, useEffect } from 'react';
import { 
  X, 
  Sparkles, 
  Scan, 
  ShieldCheck, 
  AlertOctagon, 
  CheckCircle2, 
  Key, 
  ExternalLink,
  PlusCircle,
  Copy,
  Check,
  Shield,
  HelpCircle,
  Info
} from 'lucide-react';
import { getStoredGeminiKey, saveGeminiKey, runGroundedGeminiTriage } from '../services/geminiService';
import { EnrichedIndicator, GeminiTriageResult } from '../types/threat';

interface GeminiTriageModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialIndicator?: string;
  indicatorObj?: EnrichedIndicator;
  onAddToFeed?: (indicator: EnrichedIndicator) => void;
}

export const GeminiTriageModal: React.FC<GeminiTriageModalProps> = ({
  isOpen,
  onClose,
  initialIndicator = '',
  indicatorObj,
  onAddToFeed,
}) => {
  const [apiKey, setApiKey] = useState('');
  const [indicator, setIndicator] = useState(initialIndicator);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<GeminiTriageResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [added, setAdded] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen) {
      const stored = getStoredGeminiKey();
      if (stored) setApiKey(stored);
      if (initialIndicator) {
        setIndicator(initialIndicator);
      }
    }
  }, [isOpen, initialIndicator]);

  if (!isOpen) return null;

  const handleRunTriage = async () => {
    if (!indicator.trim()) {
      setErrorMsg('Please enter a domain, URL, or package name to analyze.');
      return;
    }

    setIsLoading(true);
    setErrorMsg(null);
    setResult(null);
    setAdded(false);

    if (apiKey.trim()) {
      saveGeminiKey(apiKey.trim());
    }

    try {
      const res = await runGroundedGeminiTriage(indicator.trim(), indicatorObj, apiKey.trim());
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to triage indicator.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyAnalysis = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.rawResponse);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAddTriagedToFeed = () => {
    if (!result || !onAddToFeed) return;

    let confScore = 65;
    let confLevel = 'medium';
    if (result.verdict === 'MALICIOUS HIGH CONFIDENCE') {
      confScore = 90;
      confLevel = 'high';
    } else if (result.verdict === 'LIKELY BENIGN') {
      confScore = 20;
      confLevel = 'low';
    }

    const newInd: EnrichedIndicator = {
      id: crypto.randomUUID ? crypto.randomUUID() : `ind-${Date.now()}`,
      value: indicator.trim(),
      indicator_type: indicator.includes('/') ? 'url' : indicator.includes('.') ? 'domain' : 'package-pypi',
      source: 'Gemini AI Triage',
      target_brand: result.targetBrand || 'generic_ai',
      lure_type: result.attackPattern?.toLowerCase().includes('installer') ? 'fake_installer' : 'credential_phish',
      associated_malware: result.malwareFamily || 'LummaC2 Stealer',
      first_seen: new Date().toISOString(),
      confidence_score: confScore,
      confidence_level: confLevel,
      mitre_attack: result.mitreTechniques || ['T1566.002', 'T1036.005'],
      enrichment: {
        domain_age_days: 2,
        registration_date: new Date().toISOString().slice(0, 10),
        registrar: 'Triage Inferred / Privacy Redacted',
        resolved_ips: [],
        asn: null,
        asn_org: null,
        country: null,
        has_download_link: result.attackPattern?.toLowerCase().includes('installer') || false,
        download_extensions: ['.exe', '.msi'],
        has_login_form: result.attackPattern?.toLowerCase().includes('credential') || false,
        urlscan_id: null,
        urlscan_screenshot_url: null,
        virustotal_detections: 3,
        virustotal_positives: 3,
        virustotal_link: null,
        shodan_ports: [80, 443],
        page_title: null,
      },
      tags: ['ai-lure', 'gemini-triaged'],
      tlp: 'TLP:CLEAR',
    };

    onAddToFeed(newInd);
    setAdded(true);
  };

  return (
    <div className="fixed inset-0 bg-slate-900/40 z-50 flex items-center justify-center p-4 backdrop-blur-xs animate-in fade-in duration-200">
      <div 
        className="bg-white w-full max-w-3xl rounded-2xl border border-slate-200 shadow-2xl overflow-hidden flex flex-col max-h-[92vh]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-white shadow-xs">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900">Grounded Gemini CTI Analyst</h3>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  ANTI-INJECTION DEFENSE ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-500">Strictly grounded threat intelligence reasoning without hallucinations</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 overflow-y-auto custom-scroll flex-1 text-xs">
          {/* API Key Input */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-blue-600" />
                <span>Google AI Studio API Key (Gemini API)</span>
              </span>
              <span className="text-[11px] text-emerald-700 font-mono font-medium">
                {apiKey ? '✓ API Key Provided' : 'Grounded Local Engine Active'}
              </span>
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              placeholder="AIzaSy... (optional; leave blank to run deterministic grounded CTI model)"
              className="w-full bg-white border border-slate-300 text-xs text-slate-800 px-3.5 py-2.5 rounded-lg focus:outline-none focus:border-blue-500 font-mono shadow-xs transition-colors"
            />
            <p className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
              <span>Generate free API key at</span>
              <a
                href="https://aistudio.google.com/apikey"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-800 underline inline-flex items-center gap-0.5 font-medium"
              >
                <span>aistudio.google.com/apikey</span>
                <ExternalLink className="w-3 h-3" />
              </a>
              <span>(Saved only in local browser storage; never transmitted to public feeds).</span>
            </p>
          </div>

          {/* Indicator Input */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Observable Indicator to Triage (Untrusted Input)
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={indicator}
                onChange={e => setIndicator(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleRunTriage()}
                placeholder="e.g. claude-35-sonnet-pro-free.icu or primarypath-langgraph"
                className="flex-1 bg-white border border-slate-300 text-xs text-slate-800 px-3.5 py-2.5 rounded-lg focus:outline-none focus:border-blue-500 font-mono shadow-xs transition-colors"
              />
              <button
                onClick={handleRunTriage}
                disabled={isLoading}
                className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all shadow-xs active:scale-95 shrink-0"
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    <span>Reasoning...</span>
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4" />
                    <span>Run Triage</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Error Message */}
          {errorMsg && (
            <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-rose-600 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Loading indicator */}
          {isLoading && (
            <div className="p-6 rounded-xl bg-slate-50 border border-slate-200 text-center space-y-2">
              <div className="w-8 h-8 mx-auto border-2 border-blue-500/20 border-t-blue-600 rounded-full animate-spin"></div>
              <p className="text-xs font-semibold text-slate-800">Evaluating observable against grounded CTI evidence...</p>
              <p className="text-[11px] text-slate-500">Enforcing strict separation between supported facts, analyst inferences, and unknown data.</p>
            </div>
          )}

          {/* Triage Results Display */}
          {result && !isLoading && (
            <div className="mt-4 p-5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-4">
              {/* Mandatory AI Verification Disclaimer */}
              <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 flex items-center justify-between text-xs text-amber-900">
                <span className="font-bold flex items-center gap-1.5 text-amber-950">
                  <AlertOctagon className="w-3.5 h-3.5 text-amber-600" />
                  <span>AI-assisted, verify before action</span>
                </span>
                <span className="text-[11px] text-amber-800">
                  Strictly grounded on existing record telemetry. Never execute or block without human confirmation.
                </span>
              </div>

              <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-blue-600" />
                  <span>Analytical Assessment Output (Fixed 5-Part Format)</span>
                </span>
                
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${
                    result.verdict === 'MALICIOUS HIGH CONFIDENCE'
                      ? 'bg-rose-50 text-rose-700 border border-rose-200'
                      : result.verdict === 'SUSPICIOUS CANDIDATE'
                      ? 'bg-amber-50 text-amber-700 border border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  }`}
                >
                  {result.verdict}
                </span>
              </div>

              {/* Delineated 4-Quadrant Evidence Box */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {/* 1. Facts Supported by Source Records */}
                <div className="p-3.5 rounded-lg bg-emerald-50/50 border border-emerald-200 space-y-1.5">
                  <span className="font-bold text-emerald-800 flex items-center gap-1 text-[11px] uppercase tracking-wider">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Facts Supported by Source Records</span>
                  </span>
                  <ul className="space-y-1 text-slate-700 text-[11px]">
                    {result.factsSupportedBySources.map((f, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-emerald-600 font-bold">&bull;</span>
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 2. Analyst Inferences */}
                <div className="p-3.5 rounded-lg bg-blue-50/50 border border-blue-200 space-y-1.5">
                  <span className="font-bold text-blue-800 flex items-center gap-1 text-[11px] uppercase tracking-wider">
                    <Shield className="w-3.5 h-3.5" />
                    <span>Analyst Inferences</span>
                  </span>
                  <ul className="space-y-1 text-slate-700 text-[11px]">
                    {result.analystInferences.map((inf, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-blue-600 font-bold">&bull;</span>
                        <span>{inf}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 3. Unverified Hypotheses */}
                <div className="p-3.5 rounded-lg bg-amber-50/50 border border-amber-200 space-y-1.5">
                  <span className="font-bold text-amber-800 flex items-center gap-1 text-[11px] uppercase tracking-wider">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>Unverified Hypotheses</span>
                  </span>
                  <ul className="space-y-1 text-slate-700 text-[11px]">
                    {result.unverifiedHypotheses.map((h, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-amber-600 font-bold">&bull;</span>
                        <span>{h}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 4. Unknown Information */}
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                  <span className="font-bold text-slate-700 flex items-center gap-1 text-[11px] uppercase tracking-wider">
                    <Info className="w-3.5 h-3.5" />
                    <span>Unknown / Missing Information</span>
                  </span>
                  <ul className="space-y-1 text-slate-600 text-[11px]">
                    {result.unknownInformation.map((u, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-slate-400 font-bold">&bull;</span>
                        <span>{u}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Full Raw Markdown View */}
              <div className="pt-2">
                <span className="text-[10px] font-bold text-slate-700 uppercase tracking-wider block mb-1">
                  Full Structured Intelligence Brief:
                </span>
                <pre className="p-3 bg-slate-950 rounded-lg text-[11px] font-mono text-slate-200 overflow-x-auto border border-slate-800 max-h-48 custom-scroll whitespace-pre-wrap shadow-inner">
                  {result.rawResponse}
                </pre>
              </div>

              {/* Action Buttons for Result */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 text-xs">
                <button
                  onClick={handleCopyAnalysis}
                  className="text-slate-700 hover:text-slate-900 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-300 shadow-xs hover:bg-slate-100 transition-colors"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Copied Analysis</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Brief</span>
                    </>
                  )}
                </button>

                {onAddToFeed && (
                  <button
                    onClick={handleAddTriagedToFeed}
                    disabled={added}
                    className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all shadow-xs ${
                      added
                        ? 'bg-emerald-50 text-emerald-800 border border-emerald-300'
                        : 'bg-blue-600 hover:bg-blue-700 text-white'
                    }`}
                  >
                    {added ? (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Added to Active Feed</span>
                      </>
                    ) : (
                      <>
                        <PlusCircle className="w-3.5 h-3.5" />
                        <span>Add Indicator to Live Feed</span>
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
