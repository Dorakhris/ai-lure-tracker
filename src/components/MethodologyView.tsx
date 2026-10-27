import React, { useState } from 'react';
import { 
  BookOpen, 
  ShieldCheck, 
  Scale, 
  AlertTriangle, 
  Send, 
  CheckCircle2, 
  Layers, 
  Activity, 
  ExternalLink,
  Lock,
  FileCheck
} from 'lucide-react';
import { defang } from '../utils/defang';

export const MethodologyView: React.FC = () => {
  const [fpIndicator, setFpIndicator] = useState('');
  const [fpReason, setFpReason] = useState('');
  const [fpSubmitted, setFpSubmitted] = useState(false);

  const handleSubmitFp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!fpIndicator.trim()) return;
    setFpSubmitted(true);
    setTimeout(() => {
      setFpSubmitted(false);
      setFpIndicator('');
      setFpReason('');
    }, 4000);
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-in fade-in duration-200 text-xs">
      {/* Header */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-2">
        <div className="flex items-center gap-2.5">
          <div className="w-10 h-10 rounded-lg bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-600">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-900">Methodology, Data Provenance &amp; Attribution Rules</h1>
            <p className="text-slate-500 text-xs">
              Evidence-based criteria, limitations, and operational standards of AI Lure Tracker
            </p>
          </div>
        </div>
      </div>

      {/* Mission & Purpose */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-3">
        <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600" />
          <span>Core Mission &amp; Defensive Use Statement</span>
        </h2>
        <p className="text-slate-600 leading-relaxed">
          <strong className="text-slate-900">AI Lure Tracker</strong> is an open-source Cyber Threat Intelligence (CTI) initiative dedicated to tracking, analyzing, and documenting malicious infrastructure weaponizing Generative AI brands. Cybercriminals frequently register typosquatted domains (e.g. <code className="bg-slate-100 px-1 py-0.5 rounded border border-slate-200 text-slate-800">chatgpt-4o-download[.]com</code>) or publish lookalike software packages to distribute infostealers (LummaC2, Stealc, Vidar) and harvest user credentials.
        </p>
        <p className="text-slate-500 leading-relaxed">
          All intelligence published on this platform is designated <strong className="text-slate-700">TLP:CLEAR</strong> and intended exclusively for defensive authorization: Security Operations Centers (SOC), Threat Intelligence Units, CSIRTs, and secure DNS/firewall filtering teams.
        </p>
      </div>

      {/* Strict Attribution Taxonomy & Rules */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
          <Scale className="w-4 h-4 text-blue-600" />
          <span>Standardized 5-Verdict Taxonomy &amp; Rules</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-rose-50/50 border border-rose-200 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-rose-700 text-xs">Confirmed Malicious (&ge; 75 pts)</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-semibold border border-rose-200">BLOCK</span>
            </div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              <strong className="text-slate-800">Requirement:</strong> Requires at least one authoritative threat feed (URLhaus verified payload, ThreatFox verified malware, PhishTank consensus) OR two independent corroborating security feeds.
            </p>
            <div className="text-[10px] text-rose-700 font-mono font-medium">
              Lookalike domain registrations alone are NEVER marked Confirmed Malicious.
            </div>
          </div>

          <div className="p-4 rounded-lg bg-amber-50/50 border border-amber-200 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-amber-800 text-xs">Suspected (40 - 74 pts)</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-semibold border border-amber-200">INVESTIGATE</span>
            </div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              <strong className="text-slate-800">Requirement:</strong> Exhibits weaponization patterns (brand keyword in hostname, newly registered &le; 7 days, suspicious TLD) but lacks independent active payload or sandboxed execution proof.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-amber-50/30 border border-amber-200 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-amber-700 text-xs">Needs Review (&lt; 40 pts)</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-100 text-amber-700 font-semibold border border-amber-200">MONITOR</span>
            </div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              <strong className="text-slate-800">Requirement:</strong> Inconclusive telemetry, ambiguous keywords, or solitary passive DNS observation without corroboration.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-emerald-50/50 border border-emerald-200 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-emerald-800 text-xs">Likely Benign (Allowlist Override)</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-semibold border border-emerald-200">PERMIT</span>
            </div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              <strong className="text-slate-800">Requirement:</strong> Domain is an authorized official root domain (e.g. openai.com, anthropic.com, claude.ai, google.com). High false-positive suppression prevents blocking legitimate vendors.
            </p>
          </div>
        </div>

        {/* Malware Attribution Discipline */}
        <div className="p-4 rounded-lg bg-amber-50 border border-amber-200 space-y-2 mt-4 text-slate-700">
          <div className="font-bold text-amber-900 text-xs flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            <span>Malware Family Attribution Discipline</span>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-600">
            Malware families (such as LummaC2 Stealer or Stealc) are strictly attributed <strong className="text-slate-800">only when an authoritative source provides explicit telemetry</strong> (e.g., URLhaus payload tag or sandbox execution report). Domains observed solely via SSL Certificate Transparency (CertStream) are explicitly designated:
          </p>
          <div className="font-mono text-[11px] bg-white p-2.5 rounded text-amber-900 border border-amber-300 shadow-xs">
            "Family unknown (Lure suspected, no malware link established)"
          </div>
        </div>
      </div>

      {/* Upstream Sources & Credits */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
          <Activity className="w-4 h-4 text-indigo-600" />
          <span>Upstream Intelligence Sources &amp; Public Feeds</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">abuse.ch ThreatFox</div>
            <div className="text-[11px] text-slate-500">Community and researcher shared IOCs associated with active malware campaigns.</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">abuse.ch URLhaus</div>
            <div className="text-[11px] text-slate-500">Database of verified malicious URLs being used for malware distribution.</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">OpenPhish</div>
            <div className="text-[11px] text-slate-500">Automated zero-day phishing detection feed with payload DOM analysis.</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">PhishTank (Cisco)</div>
            <div className="text-[11px] text-slate-500">Crowdsourced phishing verification community and clearinghouse.</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">CaliDog CertStream</div>
            <div className="text-[11px] text-slate-500">Real-time WebSocket stream of Certificate Transparency log issuances.</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-bold text-slate-800">PyPI &amp; npm Monitored Feeds</div>
            <div className="text-[11px] text-slate-500">Package registry indexes monitored for typosquats of AI libraries.</div>
          </div>
        </div>
      </div>

      {/* False Positive Reporting Form */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-emerald-600" />
              <span>False Positive &amp; Delisting Request</span>
            </h2>
            <p className="text-slate-500 text-[11px] mt-0.5">
              Are you the owner of an incorrectly flagged domain or open-source tool? Submit an expedited review request.
            </p>
          </div>
        </div>

        {fpSubmitted ? (
          <div className="p-4 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-600" />
            <div>
              <div className="font-bold">Review Request Received</div>
              <div className="text-[11px]">The observable has been queued for analyst re-investigation and allowlist assessment.</div>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmitFp} className="space-y-3">
            <div>
              <label className="text-slate-600 text-[11px] font-semibold block mb-1">Observable Value (URL or Domain):</label>
              <input
                type="text"
                required
                value={fpIndicator}
                onChange={e => setFpIndicator(e.target.value)}
                placeholder="e.g. hxxps://my-legitimate-ai-tool[.]com"
                className="w-full bg-white border border-slate-300 text-xs font-mono text-slate-800 p-2.5 rounded-lg focus:outline-none focus:border-blue-500 shadow-xs"
              />
            </div>

            <div>
              <label className="text-slate-600 text-[11px] font-semibold block mb-1">Reason for Delisting / Verification Evidence:</label>
              <textarea
                required
                rows={3}
                value={fpReason}
                onChange={e => setFpReason(e.target.value)}
                placeholder="Provide ownership details, security contact, or justification explaining why this observable is legitimate..."
                className="w-full bg-white border border-slate-300 text-xs text-slate-800 p-2.5 rounded-lg focus:outline-none focus:border-blue-500 shadow-xs"
              ></textarea>
            </div>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs flex items-center gap-1.5 shadow-xs transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Submit False Positive Report</span>
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
