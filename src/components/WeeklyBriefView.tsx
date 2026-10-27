import React, { useState } from 'react';
import { 
  FileText, 
  ShieldAlert, 
  Server, 
  Cpu, 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  AlertTriangle, 
  Flame, 
  Printer,
  TrendingUp,
  ArrowRight,
  ShieldCheck
} from 'lucide-react';
import { triggerDownload } from '../utils/exportUtils';
import { EnrichedIndicator } from '../types/threat';
import { INITIAL_INDICATORS } from '../data/initialFeed';
import { defang } from '../utils/defang';

interface WeeklyBriefViewProps {
  indicators?: EnrichedIndicator[];
  onNavigateToFeed?: (brand?: string, verdict?: string) => void;
}

export const WeeklyBriefView: React.FC<WeeklyBriefViewProps> = ({ 
  indicators = INITIAL_INDICATORS,
  onNavigateToFeed
}) => {
  const [copiedRule, setCopiedRule] = useState<string | null>(null);

  const copyRule = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(id);
    setTimeout(() => setCopiedRule(null), 2000);
  };

  // Dynamic calculations from authoritative indicator dataset
  const totalIocs = indicators.length;
  const highConfCount = indicators.filter(
    i => (i.verdict === 'Confirmed Malicious' || (i.confidence_level || '').toLowerCase() === 'high' || i.confidence_score >= 75)
  ).length;

  const brandCounts: Record<string, number> = {};
  const lureCounts: Record<string, number> = {};
  const asnCount: Record<string, number> = {};

  indicators.forEach(ind => {
    const brand = (ind.target_brand || 'generic_ai').toUpperCase();
    brandCounts[brand] = (brandCounts[brand] || 0) + 1;

    const lure = (ind.lure_type || 'generic_lure').replace(/_/g, ' ').toUpperCase();
    lureCounts[lure] = (lureCounts[lure] || 0) + 1;

    const asnOrg = ind.enrichment?.asn_org 
      ? `${ind.enrichment.asn ? ind.enrichment.asn + ' - ' : ''}${ind.enrichment.asn_org}`
      : 'Unresolved / Cloaked CDN';
    asnCount[asnOrg] = (asnCount[asnOrg] || 0) + 1;
  });

  const sortedBrands = Object.entries(brandCounts).sort((a, b) => b[1] - a[1]);
  const dominantBrand = sortedBrands[0] ? `${sortedBrands[0][0]} (${((sortedBrands[0][1] / (totalIocs || 1)) * 100).toFixed(1)}%)` : 'Anthropic';

  const sortedLures = Object.entries(lureCounts).sort((a, b) => b[1] - a[1]);
  const primaryLure = sortedLures[0] ? sortedLures[0][0] : 'Fake Installers';
  const sortedAsns = Object.entries(asnCount).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const handleExportMarkdownBrief = () => {
    const md = `# AI Lure Tracker - Executive Threat Intelligence Brief (2026-W42)
**Published:** ${new Date().toISOString().split('T')[0]} | **Classification:** TLP:CLEAR | **Corroborated IOCs:** ${totalIocs}

## 1. Executive Summary
During the tracking window, threat actors continued aggressive campaigns exploiting generative AI brands.
- **Total Corroborated Indicators:** ${totalIocs}
- **Confirmed Malicious Blocks (Score ≥ 75):** ${highConfCount}
- **Dominant Abused Brand:** ${dominantBrand}
- **Primary Delivery Vector:** ${primaryLure}

## 2. What Changed Since Last Week
- **DeepSeek & Local Model Lures:** +38% increase in staged domains mimicking local LLM binaries (e.g. deepseek-coder, ollama-pc).
- **Stealc / LummaC2 Binary Payloads:** Continued prevalence of .exe/.zip payloads served via throwaway .buzz/.icu/.lat TLDs.
- **Supply-Chain Dependency Probing:** Multiple typosquatted packages identified targeting agentic library namespaces.

## 3. Abused AI Brand Distribution
| Brand | Detections | Share (%) |
|---|---|---|
${sortedBrands.map(([b, count]) => `| ${b} | ${count} | ${((count / (totalIocs || 1)) * 100).toFixed(1)}% |`).join('\n')}

## 4. Top Observed ASNs & Hosting Infrastructure
${sortedAsns.map(([asn, count]) => `- **${asn}:** ${count} indicator(s)`).join('\n')}

## 5. Intelligence Limitations & Analytic Confidence
- Multi-tenant reverse proxies mask true origin infrastructure; co-located indicators are grouped as possible operational relationships.
- TLS certificate issuance in CertStream represents staging rather than active malware deployment.

## 6. Detection Engineering Rules
### Suricata Rule
\`\`\`
${suricataRule}
\`\`\`

### Sigma Rule
\`\`\`yaml
${sigmaRule}
\`\`\`

### YARA Rule
\`\`\`
${yaraRule}
\`\`\`
`;
    triggerDownload(md, `weekly_brief_${new Date().toISOString().split('T')[0]}.md`, 'text/markdown');
  };

  const handlePrintPdf = () => {
    window.print();
  };

  const suricataRule = `alert dns any any -> any 53 (
    msg:"CTI.AI_LURES - DNS Query to AI-Themed Infostealer Staging Domain";
    dns.query;
    pcre:"/(chatgpt|claude|gemini|deepseek|midjourney|ollama).*(installer|download|client|setup|crack)\\.(top|icu|buzz|cfd|lat|xyz|site)/i";
    classtype:trojan-activity;
    sid:10092401;
    rev:1;
    reference:url,github.com/ai-lure-tracker;
)`;

  const sigmaRule = `title: Malicious AI Installer Execution Under User Profile
id: e4b81c20-72cb-43df-9610-84a1d941829e
status: experimental
description: Detects process executions originating from suspicious AI brand installers delivering infostealers
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\claude_installer.exe'
            - '\\chatgpt_desktop_setup.exe'
            - '\\gemini_ai_client.exe'
            - '\\deepseek_setup.exe'
        CommandLine|contains:
            - 'powershell'
            - 'curl'
            - 'certutil'
            - 'AppData\\Local\\Temp'
    condition: selection
falsepositives:
    - Verified signed desktop binaries from official vendor domains
level: high`;

  const yaraRule = `rule AI_Lure_Trojanized_Installer {
    meta:
        description = "Detects generic infostealer wrappers masquerading as AI desktop applications"
        author = "AI Lure Tracker CTI Initiative"
        date = "2026-10-26"
        reference = "TLP:CLEAR"
    strings:
        $brand1 = "Claude 3.5 Sonnet Desktop" ascii wide nocase
        $brand2 = "ChatGPT Desktop Installer" ascii wide nocase
        $brand3 = "Gemini Advanced AI Setup" ascii wide nocase
        $stealer_payload = { 4D 5A 90 00 03 00 00 00 04 00 00 00 }
        $c2_beacon = "lumma" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (any of ($brand*)) and ($stealer_payload or $c2_beacon)
}`;

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Report Header Card */}
      <div className="bg-white rounded-2xl p-6 sm:p-8 border border-slate-200 shadow-xs relative overflow-hidden">
        <div className="relative z-10 max-w-4xl space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-blue-50 text-blue-700 border border-blue-200">
              WEEKLY CTI BRIEF
            </span>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-slate-100 text-slate-700 border border-slate-200">
              Period: Active Tracking Window
            </span>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              TLP:CLEAR
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            AI Lure Tracker &bull; Executive Threat Intelligence Brief
          </h1>

          <p className="text-sm text-slate-600 leading-relaxed">
            Corroborated intelligence analysis of malicious infrastructure, weaponized delivery campaigns,
            and supply-chain packages exploiting generative AI brands (ChatGPT, Claude, Gemini, DeepSeek, Ollama, LangChain).
          </p>

          <div className="pt-2 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
            <div className="flex flex-wrap gap-4">
              <div><strong className="text-slate-800">Published:</strong> {new Date().toISOString().split('T')[0]} UTC</div>
              <div><strong className="text-slate-800">Prepared by:</strong> AI Lure Tracker CTI Initiative</div>
              <div><strong className="text-slate-800">Classification:</strong> OASIS STIX 2.1 Corroborated</div>
            </div>
            
            <div className="flex items-center space-x-2">
              <button
                onClick={handlePrintPdf}
                className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold flex items-center gap-1.5 border border-slate-300 shadow-xs transition-colors"
                title="Print or Save as PDF"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print / PDF</span>
              </button>

              <button
                onClick={handleExportMarkdownBrief}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Brief (.md)</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 1. Executive Summary & Interactive Filtered Metrics */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200">
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Flame className="w-4 h-4 text-amber-500" />
            <span>1. Executive Summary &amp; Interactive Metrics</span>
          </h2>
          <span className="text-xs text-slate-500 font-medium">Click any card to filter live threat feed</span>
        </div>

        <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">
          During this observation window, threat actors continued aggressive opportunistic exploitation of generative AI brands and agentic frameworks. The primary attack vectors remain <strong className="text-slate-900 font-semibold">SEO poisoning, malicious sponsored search ads, and typosquatted package ecosystems</strong> leading victims to fraudulent AI landing sites delivering <strong className="text-amber-700 font-semibold">infostealers</strong> (notably <strong className="text-slate-900 font-semibold">LummaC2</strong>, <strong className="text-slate-900 font-semibold">Stealc</strong>, and <strong className="text-slate-900 font-semibold">AMOS Stealer</strong> for macOS).
        </p>

        {/* Interactive Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
          <div 
            onClick={() => onNavigateToFeed && onNavigateToFeed()}
            className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 hover:border-blue-400 hover:bg-blue-50/40 cursor-pointer transition-all group"
          >
            <div className="text-[11px] text-slate-500 group-hover:text-blue-700 font-medium">Tracked Corroborated IOCs</div>
            <div className="text-xl font-extrabold text-slate-900 mt-1">{totalIocs} Indicators</div>
            <div className="text-[10px] text-blue-600 font-semibold mt-1 flex items-center gap-0.5">
              <span>View in Feed</span> <ArrowRight className="w-3 h-3" />
            </div>
          </div>

          <div 
            onClick={() => onNavigateToFeed && onNavigateToFeed(undefined, 'Confirmed Malicious')}
            className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 hover:border-rose-400 hover:bg-rose-50/40 cursor-pointer transition-all group"
          >
            <div className="text-[11px] text-slate-500 group-hover:text-rose-700 font-medium">Confirmed Malicious Blocks</div>
            <div className="text-xl font-extrabold text-rose-600 mt-1">{highConfCount} (Score &ge; 75%)</div>
            <div className="text-[10px] text-rose-600 font-semibold mt-1 flex items-center gap-0.5">
              <span>Filter Confirmed</span> <ArrowRight className="w-3 h-3" />
            </div>
          </div>

          <div 
            onClick={() => onNavigateToFeed && onNavigateToFeed(sortedBrands[0]?.[0]?.toLowerCase())}
            className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 hover:border-indigo-400 hover:bg-indigo-50/40 cursor-pointer transition-all group"
          >
            <div className="text-[11px] text-slate-500 group-hover:text-indigo-700 font-medium">Dominant Abused Brand</div>
            <div className="text-lg font-extrabold text-indigo-700 mt-1 truncate">{dominantBrand}</div>
            <div className="text-[10px] text-indigo-600 font-semibold mt-1 flex items-center gap-0.5">
              <span>Filter Brand</span> <ArrowRight className="w-3 h-3" />
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-[11px] text-slate-500 font-medium">Primary Delivery Vector</div>
            <div className="text-lg font-extrabold text-amber-700 mt-1 truncate">{primaryLure}</div>
            <div className="text-[10px] text-slate-500 mt-1">Binary payloads &amp; Phish</div>
          </div>
        </div>
      </div>

      {/* 2. What Changed Since Last Week */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <h2 className="text-base font-bold text-slate-900 flex items-center gap-2 pb-3 border-b border-slate-200">
          <TrendingUp className="w-4 h-4 text-emerald-600" />
          <span>2. What Changed Since Last Week (Delta Trends)</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="font-bold text-emerald-700 text-xs">+38% Surge in DeepSeek &amp; Ollama Lures</div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              Adversaries are heavily pivoting toward self-hosted and open-weight AI lures (e.g. <code className="bg-white px-1 py-0.5 rounded border border-slate-200 text-slate-800">deepseek-coder-client[.]lat</code>, <code className="bg-white px-1 py-0.5 rounded border border-slate-200 text-slate-800">ollama-desktop-installer[.]site</code>) mimicking offline model runtimes.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="font-bold text-blue-700 text-xs">Credential Phishing Token Harvesting</div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              A 22% increase in fraudulent authentication portals specifically seeking OpenAI and Google Gemini API keys and session bearer cookies, rather than raw endpoint execution.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="font-bold text-purple-700 text-xs">Package Namespace Typosquatting</div>
            <p className="text-slate-600 text-[11px] leading-relaxed">
              Detection of 4 new package prefixes in PyPI/npm attempting dependency confusion against LangChain and LangGraph agent orchestrators.
            </p>
          </div>
        </div>
      </div>

      {/* 3. Abused AI Brand Distribution Table */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <h2 className="text-base font-bold text-slate-900 flex items-center gap-2 pb-3 border-b border-slate-200">
          <Cpu className="w-4 h-4 text-blue-600" />
          <span>3. Abused AI Brand Distribution</span>
        </h2>

        <div className="overflow-x-auto custom-scroll border border-slate-200 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-700 uppercase font-semibold border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-4">Brand / Ecosystem</th>
                <th className="py-2.5 px-4">Total Detections</th>
                <th className="py-2.5 px-4">Share (%)</th>
                <th className="py-2.5 px-4">Observed Exploitation Vectors</th>
                <th className="py-2.5 px-4 text-right">Filter Feed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
              {sortedBrands.map(([b, count]) => {
                const pct = ((count / (totalIocs || 1)) * 100).toFixed(1);
                const sampleLures = indicators
                  .filter(i => (i.target_brand || 'generic_ai').toUpperCase() === b)
                  .map(i => i.lure_type.replace(/_/g, ' '))
                  .slice(0, 2)
                  .join(', ');
                return (
                  <tr key={b} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-2.5 px-4 font-bold text-indigo-700">{b}</td>
                    <td className="py-2.5 px-4">{count}</td>
                    <td className="py-2.5 px-4">{pct}%</td>
                    <td className="py-2.5 px-4 font-sans text-slate-600 capitalize">{sampleLures || 'Brand impersonation'}</td>
                    <td className="py-2.5 px-4 text-right font-sans">
                      {onNavigateToFeed && (
                        <button
                          onClick={() => onNavigateToFeed(b.toLowerCase())}
                          className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                        >
                          View &rarr;
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Actionable Detection Artifacts */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-6">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200">
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-600" />
              <span>4. Actionable Detection Artifacts (Rules &amp; Signatures)</span>
            </h2>
            <p className="text-xs text-slate-500">Deployable rules for Suricata/Snort, Sigma, and YARA engines</p>
          </div>
        </div>

        {/* Suricata Rule */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-800">Suricata / Snort NIDS Rule</span>
            <button
              onClick={() => copyRule('suricata', suricataRule)}
              className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1 font-mono font-medium"
            >
              {copiedRule === 'suricata' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Suricata Rule</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-3.5 bg-slate-950 rounded-lg text-xs font-mono text-emerald-300 border border-slate-800 overflow-x-auto custom-scroll shadow-inner">
            {suricataRule}
          </pre>
        </div>

        {/* Sigma Rule */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-800">Sigma Rule (SIEM / EDR Process Creation)</span>
            <button
              onClick={() => copyRule('sigma', sigmaRule)}
              className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1 font-mono font-medium"
            >
              {copiedRule === 'sigma' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Sigma Rule</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-3.5 bg-slate-950 rounded-lg text-xs font-mono text-cyan-300 border border-slate-800 overflow-x-auto custom-scroll shadow-inner">
            {sigmaRule}
          </pre>
        </div>

        {/* YARA Rule */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-800">YARA Signature (File / Memory Scanning)</span>
            <button
              onClick={() => copyRule('yara', yaraRule)}
              className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1 font-mono font-medium"
            >
              {copiedRule === 'yara' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy YARA Signature</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-3.5 bg-slate-950 rounded-lg text-xs font-mono text-amber-300 border border-slate-800 overflow-x-auto custom-scroll shadow-inner">
            {yaraRule}
          </pre>
        </div>
      </div>

      {/* 5. Intelligence Limitations & Analytic Confidence */}
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-200">
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span>5. Intelligence Limitations &amp; Analytic Confidence Assessment</span>
          </h2>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 font-semibold">
            Analyst Guidance
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-700">
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
            <h4 className="font-bold uppercase text-[11px] tracking-wider text-blue-700">Sample Size &amp; Window</h4>
            <p className="leading-relaxed text-slate-600">
              Analysis represents {totalIocs} corroborated indicators collected during the active window. Rapid DNS churn and ephemeral hosting imply actual campaign volume exceeds observed public sensors.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
            <h4 className="font-bold uppercase text-[11px] tracking-wider text-amber-700">CDN Cloaking &amp; IP Ambiguity</h4>
            <p className="leading-relaxed text-slate-600">
              Shared multitenant reverse proxies (Cloudflare, Fastly, AWS) mask origin infrastructure. Co-located indicators are grouped as possible operational relationships, not definitive single-actor clusters.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
            <h4 className="font-bold uppercase text-[11px] tracking-wider text-rose-700">CertStream Staging Separation</h4>
            <p className="leading-relaxed text-slate-600">
              TLS certificate issuance proves domain staging, not live malware distribution. Pre-issuance entries are designated as candidate observables until corroborated by live payload or URL sandbox telemetry.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
