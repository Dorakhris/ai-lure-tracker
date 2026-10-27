import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  Play, 
  Pause, 
  Trash2, 
  Sparkles, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink,
  Shield,
  Activity,
  Plus
} from 'lucide-react';
import { CertStreamEvent, EnrichedIndicator } from '../types/threat';
import { defang } from '../utils/defang';

interface CertStreamViewProps {
  onTriage: (domain: string) => void;
  onAddToFeed: (indicator: EnrichedIndicator) => void;
}

const SAMPLE_DOMAINS = [
  { domain: 'chatgpt-4o-desktop-installer.top', brand: 'openai', score: 85, isFlagged: true },
  { domain: 'claude-35-sonnet-pro-free.icu', brand: 'anthropic', score: 90, isFlagged: true },
  { domain: 'gemini-advanced-ai-setup.xyz', brand: 'google_ai', score: 85, isFlagged: true },
  { domain: 'deepseek-coder-client-win64.lat', brand: 'deepseek', score: 85, isFlagged: true },
  { domain: 'midjourney-v6-pc-crack.buzz', brand: 'midjourney', score: 95, isFlagged: true },
  { domain: 'ollama-ai-desktop-installer.site', brand: 'ollama', score: 85, isFlagged: true },
  { domain: 'openai-chatgpt-plus-token.cfd', brand: 'openai', score: 80, isFlagged: true },
  { domain: 'docs.anthropic.com', brand: 'anthropic', score: 10, isFlagged: false },
  { domain: 'gemini.google.com', brand: 'google_ai', score: 5, isFlagged: false },
  { domain: 'api.openai.com', brand: 'openai', score: 5, isFlagged: false },
  { domain: 'copilot-free-download-win11.xyz', brand: 'openai', score: 75, isFlagged: true },
  { domain: 'langchain-chroma-cloud.site', brand: 'ai_ecosystem_library', score: 65, isFlagged: true },
  { domain: 'chatgpt-enterprise-portal.buzz', brand: 'openai', score: 80, isFlagged: true },
  { domain: 'claude-ai-login-auth.top', brand: 'anthropic', score: 85, isFlagged: true },
  { domain: 'deepseek-r1-api-free.icu', brand: 'deepseek', score: 85, isFlagged: true }
];

const ISSUERS = [
  "Let's Encrypt Authority X3",
  'ZeroSSL ECC Domain CA',
  'Google Trust Services LLC',
  'DigiCert Global Root G2',
  'Cloudflare Inc ECC CA-3',
  'Sectigo Limited'
];

export const CertStreamView: React.FC<CertStreamViewProps> = ({ onTriage, onAddToFeed }) => {
  const [isRunning, setIsRunning] = useState(true);
  const [events, setEvents] = useState<CertStreamEvent[]>([]);
  const [totalInspected, setTotalInspected] = useState(1482);
  const [filterFlaggedOnly, setFilterFlaggedOnly] = useState(false);
  const [addedIds, setAddedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    // Populate initial batch
    const initialEvents: CertStreamEvent[] = SAMPLE_DOMAINS.slice(0, 6).map((item, idx) => ({
      id: `cert-${Date.now()}-${idx}`,
      timestamp: new Date(Date.now() - (6 - idx) * 4000).toLocaleTimeString(),
      domain: item.domain,
      matchedBrand: item.brand,
      issuer: ISSUERS[idx % ISSUERS.length],
      certType: 'Pre-Certificate (CT Log)',
      suspicionScore: item.score,
      isFlagged: item.isFlagged,
    }));
    setEvents(initialEvents);
  }, []);

  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      setTotalInspected(prev => prev + Math.floor(Math.random() * 4) + 1);

      // Random chance to produce an AI match
      if (Math.random() > 0.35) {
        const item = SAMPLE_DOMAINS[Math.floor(Math.random() * SAMPLE_DOMAINS.length)];
        const newEvent: CertStreamEvent = {
          id: `cert-${Date.now()}-${Math.random()}`,
          timestamp: new Date().toLocaleTimeString(),
          domain: item.domain,
          matchedBrand: item.brand,
          issuer: ISSUERS[Math.floor(Math.random() * ISSUERS.length)],
          certType: 'Pre-Certificate (CT Log)',
          suspicionScore: item.score,
          isFlagged: item.isFlagged,
        };

        setEvents(prev => [newEvent, ...prev.slice(0, 49)]);
      }
    }, 2800);

    return () => clearInterval(interval);
  }, [isRunning]);

  const flaggedCount = events.filter(e => e.isFlagged).length;

  const handleAddEventToFeed = (ev: CertStreamEvent) => {
    const newIndicator: EnrichedIndicator = {
      id: crypto.randomUUID ? crypto.randomUUID() : `ind-${Date.now()}`,
      value: ev.domain,
      indicator_type: 'domain',
      source: 'CertStream (CT Logs)',
      target_brand: ev.matchedBrand,
      lure_type: 'suspicious_registration',
      associated_malware: 'Family unknown (Lure suspected, no malware link established)',
      malware_attribution_source: 'None (CertStream CT Log)',
      first_seen: new Date().toISOString(),
      last_checked: new Date().toISOString(),
      confidence_score: Math.min(ev.suspicionScore, 65), // Capped below confirmed malicious
      confidence_level: 'medium',
      verdict: 'Suspected',
      verdict_rule_matched: 'CertStream CT Log candidate (no active payload confirmed)',
      mitre_attack: ['T1583.001', 'T1036.005'],
      enrichment: {
        domain_age_days: 0,
        registration_date: new Date().toISOString().slice(0, 10),
        registrar: ev.issuer,
        resolved_ips: [],
        asn: null,
        asn_org: null,
        country: null,
        has_download_link: false,
        download_extensions: [],
        has_login_form: false,
        urlscan_id: null,
        urlscan_screenshot_url: null,
        virustotal_detections: 0,
        virustotal_positives: 0,
        virustotal_link: null,
        shodan_ports: [],
        page_title: null,
      },
      tags: ['ai-lure', 'certstream-streamed', 'staging-candidate'],
      tlp: 'TLP:CLEAR',
    };

    onAddToFeed(newIndicator);
    setAddedIds(prev => new Set(prev).add(ev.id));
  };

  const displayedEvents = filterFlaggedOnly ? events.filter(e => e.isFlagged) : events;

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header Bar */}
      <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
            <Radio className={`w-5 h-5 ${isRunning ? 'animate-pulse' : ''}`} />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <span>Real-Time Certificate Transparency Monitor</span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                isRunning ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
              }`}>
                {isRunning ? 'STREAM CONNECTED' : 'STREAM PAUSED'}
              </span>
            </h2>
            <p className="text-xs text-slate-500">
              Observing global SSL/TLS certificates matching AI brand regex heuristics
            </p>
          </div>
        </div>

        {/* Stream Controls */}
        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-all shadow-xs ${
              isRunning
                ? 'bg-amber-50 text-amber-700 border border-amber-300 hover:bg-amber-100'
                : 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-emerald-500/20'
            }`}
          >
            {isRunning ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Resume Stream</span>
              </>
            )}
          </button>

          <button
            onClick={() => setEvents([])}
            className="p-2 rounded-lg bg-white hover:bg-slate-100 text-slate-500 hover:text-slate-800 border border-slate-300 shadow-xs transition-colors"
            title="Clear buffer"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stream Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Total Certificates Inspected
          </div>
          <div className="mt-1 text-2xl font-extrabold text-slate-900 font-mono">
            {totalInspected.toLocaleString()}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            AI Matches Detected
          </div>
          <div className="mt-1 text-2xl font-extrabold text-indigo-600 font-mono">
            {events.length}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 border border-slate-200 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            High-Risk Lures Flagged
          </div>
          <div className="mt-1 text-2xl font-extrabold text-rose-600 font-mono">
            {flaggedCount}
          </div>
        </div>
      </div>

      {/* CTI Operational Caution Banner */}
      <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 flex items-start gap-3 text-xs text-amber-900">
        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <strong className="text-amber-950 block font-semibold">CTI Analytic Discipline: Candidate Staging vs Malicious Delivery</strong>
          <p className="text-amber-800 leading-relaxed text-[11px]">
            Certificate Transparency logs observe SSL/TLS certificate requests at point of issuance. These represent <span className="font-semibold text-amber-950">candidate staging observables</span>. They do not constitute proof of active malware distribution or specific family execution until corroborated by live payload analysis or URLhaus/ThreatFox feed ingestion.
          </p>
        </div>
      </div>

      {/* Live Stream Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-emerald-600" />
            <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">Live Certificate Log</span>
          </div>

          <label className="flex items-center space-x-2 text-xs text-slate-600 cursor-pointer font-medium">
            <input
              type="checkbox"
              checked={filterFlaggedOnly}
              onChange={e => setFilterFlaggedOnly(e.target.checked)}
              className="rounded bg-white border-slate-300 text-blue-600 focus:ring-blue-500"
            />
            <span>Show Flagged Only</span>
          </label>
        </div>

        <div className="overflow-x-auto custom-scroll">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-700 font-semibold uppercase tracking-wider border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-4">Time</th>
                <th className="py-2.5 px-4">Subject Domain</th>
                <th className="py-2.5 px-4">AI Target</th>
                <th className="py-2.5 px-4">Issuer CA</th>
                <th className="py-2.5 px-4">Risk Rating</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {displayedEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                    Watching certificate transparency logs... new matches will appear here.
                  </td>
                </tr>
              ) : (
                displayedEvents.map(ev => {
                  const isAdded = addedIds.has(ev.id);

                  return (
                    <tr
                      key={ev.id}
                      className={`hover:bg-slate-50/80 transition-colors ${
                        ev.isFlagged ? 'bg-rose-50/40' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-slate-500 whitespace-nowrap">{ev.timestamp}</td>
                      <td className="py-2.5 px-4 text-slate-900 font-bold truncate max-w-xs" title={ev.domain}>{defang(ev.domain)}</td>
                      <td className="py-2.5 px-4 text-indigo-700 capitalize whitespace-nowrap font-sans font-medium">
                        {ev.matchedBrand.replace(/_/g, ' ')}
                      </td>
                      <td className="py-2.5 px-4 text-slate-600 truncate max-w-xs font-sans">{ev.issuer}</td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        {ev.isFlagged ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            {ev.suspicionScore} (HIGH)
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            {ev.suspicionScore} (BENIGN)
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-right whitespace-nowrap font-sans">
                        <div className="inline-flex items-center space-x-2">
                          <button
                            onClick={() => onTriage(ev.domain)}
                            className="text-blue-600 hover:text-blue-800 text-xs font-semibold inline-flex items-center gap-1"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>Triage</span>
                          </button>
                          {ev.isFlagged && (
                            <button
                              onClick={() => handleAddEventToFeed(ev)}
                              disabled={isAdded}
                              className={`text-xs px-2 py-0.5 rounded flex items-center gap-1 transition-colors ${
                                isAdded
                                  ? 'text-emerald-700 bg-emerald-50 border border-emerald-200'
                                  : 'text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border border-slate-300'
                              }`}
                            >
                              {isAdded ? (
                                <>
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>In Feed</span>
                                </>
                              ) : (
                                <>
                                  <Plus className="w-3 h-3" />
                                  <span>Add</span>
                                </>
                              )}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
