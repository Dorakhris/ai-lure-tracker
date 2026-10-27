import React, { useState } from 'react';
import { 
  X, 
  Download, 
  FileSpreadsheet, 
  FileCode, 
  Shield, 
  Filter, 
  Copy, 
  Check, 
  Globe, 
  FileText
} from 'lucide-react';
import { EnrichedIndicator, ThreatVerdict } from '../types/threat';
import { 
  generateCsvFeed, 
  generateStixBundle, 
  generateMispJson, 
  generatePlainBlocklist, 
  triggerDownload 
} from '../utils/exportUtils';
import { copyToClipboard } from '../utils/defang';
import { BRAND_LABELS } from '../data/initialFeed';

interface ExportFeedsModalProps {
  isOpen: boolean;
  onClose: () => void;
  indicators: EnrichedIndicator[];
}

export const ExportFeedsModal: React.FC<ExportFeedsModalProps> = ({
  isOpen,
  onClose,
  indicators
}) => {
  const [selectedFormat, setSelectedFormat] = useState<'csv' | 'json' | 'stix' | 'misp' | 'blocklist'>('csv');
  const [verdictFilter, setVerdictFilter] = useState<string>('all');
  const [brandFilter, setBrandFilter] = useState<string>('all');
  const [dateRange, setDateRange] = useState<'all' | '24h' | '7d' | '30d'>('all');
  const [blocklistDefanged, setBlocklistDefanged] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  if (!isOpen) return null;

  // Filter indicators based on criteria
  const filtered = indicators.filter(ind => {
    // Verdict filter
    if (verdictFilter !== 'all') {
      const v = ind.verdict || (ind.confidence_score >= 75 ? 'Confirmed Malicious' : 'Suspected');
      if (v !== verdictFilter) return false;
    }
    // Brand filter
    if (brandFilter !== 'all' && ind.target_brand !== brandFilter) {
      return false;
    }
    // Date filter
    if (dateRange !== 'all') {
      const now = Date.now();
      const firstSeen = new Date(ind.first_seen).getTime();
      const diffHours = (now - firstSeen) / (1000 * 3600);
      if (dateRange === '24h' && diffHours > 24) return false;
      if (dateRange === '7d' && diffHours > 168) return false;
      if (dateRange === '30d' && diffHours > 720) return false;
    }
    return true;
  });

  const handleDownload = () => {
    const timestamp = new Date().toISOString().split('T')[0];
    if (selectedFormat === 'csv') {
      const content = generateCsvFeed(filtered);
      triggerDownload(content, `ai_lures_${timestamp}.csv`, 'text/csv');
    } else if (selectedFormat === 'json') {
      const content = JSON.stringify(filtered, null, 2);
      triggerDownload(content, `ai_lures_${timestamp}.json`, 'application/json');
    } else if (selectedFormat === 'stix') {
      const bundle = generateStixBundle(filtered);
      triggerDownload(JSON.stringify(bundle, null, 2), `ai_lures_stix21_${timestamp}.json`, 'application/json');
    } else if (selectedFormat === 'misp') {
      const misp = generateMispJson(filtered);
      triggerDownload(JSON.stringify(misp, null, 2), `ai_lures_misp_${timestamp}.json`, 'application/json');
    } else if (selectedFormat === 'blocklist') {
      const blocklist = generatePlainBlocklist(filtered, {
        defanged: blocklistDefanged,
        confirmedOnly: verdictFilter === 'Confirmed Malicious'
      });
      triggerDownload(blocklist, `ai_lures_blocklist_${timestamp}.txt`, 'text/plain');
    }
  };

  const handleCopyPreview = async () => {
    let content = '';
    if (selectedFormat === 'blocklist') {
      content = generatePlainBlocklist(filtered, {
        defanged: blocklistDefanged,
        confirmedOnly: verdictFilter === 'Confirmed Malicious'
      });
    } else if (selectedFormat === 'json') {
      content = JSON.stringify(filtered.slice(0, 5), null, 2);
    } else {
      content = generatePlainBlocklist(filtered, { defanged: true, confirmedOnly: false });
    }
    await copyToClipboard(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center space-x-2">
            <Download className="w-5 h-5 text-blue-600" />
            <h2 className="text-base font-bold text-slate-900">Export Threat Intelligence Feeds</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* Format selection */}
          <div>
            <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider block mb-2">
              Select Export Format
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setSelectedFormat('csv')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedFormat === 'csv'
                    ? 'border-blue-600 bg-blue-50 text-blue-900 shadow-xs'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
                  <span className="text-sm font-semibold">CSV SOC Feed</span>
                </div>
                <div className="text-[11px] text-slate-500">22-column SIEM import format</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFormat('stix')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedFormat === 'stix'
                    ? 'border-blue-600 bg-blue-50 text-blue-900 shadow-xs'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="w-4 h-4 text-amber-600" />
                  <span className="text-sm font-semibold">STIX 2.1 Export</span>
                </div>
                <div className="text-[11px] text-slate-500">OASIS OpenCTI / MISP bundle</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFormat('misp')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedFormat === 'misp'
                    ? 'border-blue-600 bg-blue-50 text-blue-900 shadow-xs'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <FileCode className="w-4 h-4 text-indigo-600" />
                  <span className="text-sm font-semibold">MISP JSON</span>
                </div>
                <div className="text-[11px] text-slate-500">Standard MISP Event Schema</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFormat('json')}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedFormat === 'json'
                    ? 'border-blue-600 bg-blue-50 text-blue-900 shadow-xs'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <FileCode className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-semibold">Structured JSON</span>
                </div>
                <div className="text-[11px] text-slate-500">Full telemetry &amp; breakdown</div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFormat('blocklist')}
                className={`p-3 rounded-lg border text-left col-span-2 sm:col-span-1 transition-all ${
                  selectedFormat === 'blocklist'
                    ? 'border-blue-600 bg-blue-50 text-blue-900 shadow-xs'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <FileText className="w-4 h-4 text-rose-600" />
                  <span className="text-sm font-semibold">Plain Text Blocklist</span>
                </div>
                <div className="text-[11px] text-slate-500">Raw or defanged one-per-line</div>
              </button>
            </div>
          </div>

          {/* Pre-export filters */}
          <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 space-y-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700">
              <Filter className="w-3.5 h-3.5 text-blue-600" />
              <span>Pre-Export Filters</span>
              <span className="ml-auto text-xs text-blue-700 font-medium">
                {filtered.length} of {indicators.length} indicators matching
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] text-slate-600 font-medium block mb-1">Verdict</label>
                <select
                  value={verdictFilter}
                  onChange={e => setVerdictFilter(e.target.value)}
                  className="w-full bg-white border border-slate-300 rounded-md px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-500 shadow-xs"
                >
                  <option value="all">All Verdicts</option>
                  <option value="Confirmed Malicious">Confirmed Malicious Only</option>
                  <option value="Suspected">Suspected Only</option>
                  <option value="Needs Review">Needs Review</option>
                  <option value="Likely Benign">Likely Benign</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] text-slate-600 font-medium block mb-1">Target AI Brand</label>
                <select
                  value={brandFilter}
                  onChange={e => setBrandFilter(e.target.value)}
                  className="w-full bg-white border border-slate-300 rounded-md px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-500 shadow-xs"
                >
                  <option value="all">All AI Brands</option>
                  {Object.entries(BRAND_LABELS).filter(([k]) => k !== 'ALL').map(([key, label]) => (
                    <option key={key} value={key}>{label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] text-slate-600 font-medium block mb-1">Time Horizon</label>
                <select
                  value={dateRange}
                  onChange={e => setDateRange(e.target.value as any)}
                  className="w-full bg-white border border-slate-300 rounded-md px-2.5 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-500 shadow-xs"
                >
                  <option value="all">All Time History</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>
              </div>
            </div>

            {selectedFormat === 'blocklist' && (
              <div className="pt-2 border-t border-slate-200 flex items-center justify-between text-xs text-slate-700">
                <span className="text-[11px] text-slate-500 font-medium">Defang entries (safe for incident tickets / reports):</span>
                <label className="flex items-center gap-2 cursor-pointer font-medium">
                  <input
                    type="checkbox"
                    checked={blocklistDefanged}
                    onChange={e => setBlocklistDefanged(e.target.checked)}
                    className="rounded bg-white border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-mono">{blocklistDefanged ? 'hxxps:// & [.]' : 'Raw domain/URL'}</span>
                </label>
              </div>
            )}
          </div>

          {/* Public stable feed URL reference */}
          <div className="bg-blue-50 border border-blue-200 p-3.5 rounded-lg flex items-start gap-3">
            <Globe className="w-4 h-4 text-blue-600 mt-0.5 shrink-0" />
            <div className="text-xs text-slate-700 space-y-1">
              <div className="font-semibold text-blue-900">Automated Integration / Stable Public Endpoint</div>
              <div className="text-slate-600 text-[11px]">
                You can pull this live feed into MISP, OpenCTI, or Cortex XSOAR directly via HTTP GET:
              </div>
              <div className="font-mono text-[11px] bg-white px-2 py-1 rounded text-blue-800 select-all border border-blue-200 shadow-xs">
                /feeds/ai_lures_latest.json
              </div>
            </div>
          </div>
        </div>

        {/* Footer actions */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <button
            onClick={handleCopyPreview}
            className="flex items-center gap-1.5 text-xs text-slate-700 hover:text-slate-900 px-3 py-2 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 shadow-xs transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Preview!' : 'Copy Preview'}</span>
          </button>

          <div className="flex items-center space-x-3">
            <button
              onClick={onClose}
              className="text-xs text-slate-600 hover:text-slate-900 px-3.5 py-2 rounded-lg hover:bg-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-2 text-xs font-semibold px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white shadow-xs transition-all active:scale-95"
            >
              <Download className="w-4 h-4" />
              <span>Download {filtered.length} Indicators</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
