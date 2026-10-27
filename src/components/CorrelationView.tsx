import React, { useState, useMemo } from 'react';
import { 
  Network, 
  Layers, 
  AlertTriangle, 
  Download, 
  Sparkles, 
  CheckCircle2, 
  FolderPlus, 
  Filter, 
  Eye, 
  Calendar,
  Share2,
  Table,
  Cpu,
  ShieldCheck
} from 'lucide-react';
import { EnrichedIndicator, CorrelationCluster } from '../types/threat';
import { generateCorrelationClusters } from '../services/correlationEngine';
import { triggerDownload } from '../utils/exportUtils';
import { getStoredCases, updateOrAddCase } from '../services/casebookService';
import { defang } from '../utils/defang';

interface CorrelationViewProps {
  indicators: EnrichedIndicator[];
  onInspectIndicator: (ind: EnrichedIndicator) => void;
  onTriageIndicator: (val: string) => void;
  onNavigateToCasebook?: () => void;
}

export const CorrelationView: React.FC<CorrelationViewProps> = ({
  indicators,
  onInspectIndicator,
  onTriageIndicator,
  onNavigateToCasebook,
}) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [selectedClusterId, setSelectedClusterId] = useState<string>('');
  const [viewMode, setViewMode] = useState<'graph' | 'table'>('graph');
  const [attachedSuccess, setAttachedSuccess] = useState<string | null>(null);

  const clusters = useMemo(() => {
    return generateCorrelationClusters(indicators);
  }, [indicators]);

  const filteredClusters = useMemo(() => {
    if (filterType === 'ALL') return clusters;
    return clusters.filter(c => c.pivotType === filterType);
  }, [clusters, filterType]);

  const activeCluster = clusters.find(c => c.id === selectedClusterId) || filteredClusters[0];

  // Calculate cluster properties: date range, targeted brands, link confidence
  const clusterMetadata = useMemo(() => {
    if (!activeCluster) return null;
    const inds = activeCluster.indicators;
    const timestamps = inds.map(i => new Date(i.first_seen).getTime()).filter(t => !isNaN(t));
    const minTime = timestamps.length ? new Date(Math.min(...timestamps)).toISOString().split('T')[0] : 'N/A';
    const maxTime = timestamps.length ? new Date(Math.max(...timestamps)).toISOString().split('T')[0] : 'N/A';
    
    const brands = Array.from(new Set(inds.map(i => (i.target_brand || 'generic_ai').replace(/_/g, ' ').toUpperCase())));
    
    let linkConfidence = 85;
    if (activeCluster.relationshipType === 'confirmed_association') linkConfidence = 95;
    else if (activeCluster.relationshipType === 'supported_association') linkConfidence = 75;
    else if (activeCluster.relationshipType === 'possible_association_shared_infra') linkConfidence = 45;

    return {
      dateRange: `${minTime} to ${maxTime}`,
      brands,
      linkConfidence
    };
  }, [activeCluster]);

  const handleCreateCaseFromCluster = (cluster: CorrelationCluster) => {
    const caseId = `CASE-${Date.now().toString().slice(-6)}`;
    const newCase = {
      id: caseId,
      title: `Campaign Investigation: ${cluster.title}`,
      investigationQuestion: `Is infrastructure pivot '${cluster.pivotValue}' controlled by a single coordinated threat operator?`,
      status: 'open' as const,
      priority: (cluster.relationshipType === 'confirmed_association' ? 'critical' : 'high') as any,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      leadAnalyst: 'SOC Lead Investigator',
      indicatorIds: cluster.indicators.map(i => i.id),
      hypotheses: [
        {
          id: `hyp-${Date.now()}-1`,
          statement: `Adversary is weaponizing pivot '${cluster.pivotValue}' to deploy malware mimicking AI brands.`,
          status: 'supported' as const,
          supportingEvidence: cluster.explanation,
          alternativeExplanation: cluster.caveatNotes || 'Independent users on shared infrastructure'
        }
      ],
      alternativeExplanations: [
        cluster.caveatNotes || 'Coincidental registration or shared multitenant host without direct attacker coordination'
      ],
      evidenceNotes: [
        {
          id: `note-${Date.now()}-1`,
          timestamp: new Date().toISOString(),
          title: `Initial Infrastructure Clustering Rationale`,
          content: `${cluster.explanation}\n\nRelationship strength: ${cluster.relationshipType}. Linked indicators count: ${cluster.indicators.length}.`,
          author: 'Automated Correlation Engine',
          tags: ['clustering', cluster.pivotType]
        }
      ],
      timeline: cluster.indicators.map((ind, idx) => ({
        id: `time-${Date.now()}-${idx}`,
        timestamp: ind.first_seen,
        title: `Observed ${defang(ind.value)}`,
        description: `Associated with cluster pivot ${cluster.pivotValue}. Brand: ${ind.target_brand}.`,
        indicatorValue: ind.value
      })),
      findings: [
        `Cluster identified ${cluster.indicators.length} related observables linked by ${cluster.pivotType.replace(/_/g, ' ')}.`,
        cluster.explanation
      ],
      unresolvedQuestions: [
        'Is WHOIS registrant email linked to additional historical malicious campaigns?',
        'Are payload binaries compiled with matching build timestamps or digital signatures?'
      ],
      recommendedActions: [
        'Pivot on passive DNS history for newly discovered sibling subdomains.',
        'Review web proxy logs for any corporate outbound connections to cluster members.'
      ],
      finalSummary: `Cluster created from pivot ${cluster.pivotValue} containing ${cluster.indicators.length} indicators.`
    };

    updateOrAddCase(newCase);
    setAttachedSuccess(`Created case ${newCase.id} with ${cluster.indicators.length} indicators!`);
    setTimeout(() => setAttachedSuccess(null), 4000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shadow-2xs">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <span>Threat Infrastructure Correlation Engine</span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                {clusters.length} TRACKED CLUSTERS
              </span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Auto-clustering across apex domains, shared non-CDN IPs, registrar patterns, and package namespaces
            </p>
          </div>
        </div>

        {/* Pivot Filter */}
        <div className="flex items-center space-x-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="bg-white border border-slate-300 text-xs text-slate-800 px-3 py-1.5 rounded-lg focus:outline-none focus:border-indigo-500 shadow-2xs font-medium cursor-pointer"
          >
            <option value="ALL">All Pivot Types ({clusters.length})</option>
            <option value="shared_domain">Shared Apex Domain</option>
            <option value="package_ecosystem">Package Namespace Prefix</option>
            <option value="shared_ip">Shared Dedicated IP</option>
            <option value="shared_malware">Threat Actor / Campaign</option>
          </select>
        </div>
      </div>

      {attachedSuccess && (
        <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center justify-between gap-2 animate-in fade-in font-medium">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{attachedSuccess}</span>
          </div>
          {onNavigateToCasebook && (
            <button
              onClick={onNavigateToCasebook}
              className="text-xs font-semibold underline hover:text-emerald-950 cursor-pointer"
            >
              Open Casebook &rarr;
            </button>
          )}
        </div>
      )}

      {/* Main Layout: Cluster List + Cluster Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Clusters List */}
        <div className="lg:col-span-1 space-y-2.5">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider px-1">
            Correlated Clusters ({filteredClusters.length})
          </h3>

          <div className="space-y-2">
            {filteredClusters.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 text-center">
                No clusters found matching the selected pivot filter.
              </div>
            ) : (
              filteredClusters.map(cluster => {
                const isSelected = activeCluster?.id === cluster.id;
                let badgeClass = 'bg-yellow-50 text-yellow-800 border-yellow-200';
                if (cluster.relationshipType === 'confirmed_association') {
                  badgeClass = 'bg-rose-50 text-rose-700 border-rose-200';
                } else if (cluster.relationshipType === 'possible_association_shared_infra') {
                  badgeClass = 'bg-amber-50 text-amber-800 border-amber-200';
                }

                return (
                  <div
                    key={cluster.id}
                    onClick={() => setSelectedClusterId(cluster.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50/60 border-blue-500 shadow-xs ring-1 ring-blue-500/20'
                        : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] mb-1.5">
                      <span className="font-mono uppercase text-slate-500 font-bold">
                        {cluster.pivotType.replace('_', ' ')}
                      </span>
                      <span className={`px-2 py-0.5 rounded font-semibold text-[10px] border ${badgeClass}`}>
                        {cluster.relationshipType === 'confirmed_association' ? 'CONFIRMED' : cluster.relationshipType === 'supported_association' ? 'SUPPORTED' : 'POSSIBLE (CDN)'}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-slate-900 line-clamp-1">{cluster.title}</h4>
                    <p className="text-[11px] text-slate-600 mt-1 line-clamp-2">{cluster.explanation}</p>

                    <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                      <span>{cluster.indicators.length} Linked Observables</span>
                      <span className="text-blue-600 font-bold">Inspect &rarr;</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Active Cluster Dossier */}
        {activeCluster && clusterMetadata ? (
          <div className="lg:col-span-2 space-y-5">
            {/* Cluster Header Card */}
            <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs px-2.5 py-0.5 rounded font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                      Pivot: {activeCluster.pivotValue}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded font-semibold bg-slate-100 text-slate-700 border border-slate-200 capitalize">
                      {activeCluster.pivotType.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                      Link Confidence: {clusterMetadata.linkConfidence}%
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-slate-900">{activeCluster.title}</h2>
                </div>

                {/* Primary Action: Create Casebook Entry from Cluster */}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleCreateCaseFromCluster(activeCluster)}
                    className="px-3.5 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-1.5 shadow-xs transition-all active:scale-95 cursor-pointer"
                    title="Initialize full investigation case with hypotheses, timeline, and indicators"
                  >
                    <FolderPlus className="w-4 h-4 text-blue-100" />
                    <span>Create Casebook Entry</span>
                  </button>

                  <button
                    onClick={() => {
                      const payload = {
                        cluster: activeCluster,
                        metadata: clusterMetadata,
                        exportedAt: new Date().toISOString()
                      };
                      triggerDownload(JSON.stringify(payload, null, 2), `cluster-${activeCluster.id}.json`, 'application/json');
                    }}
                    className="px-3 py-2 rounded-lg text-xs bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 flex items-center gap-1.5 transition-colors shadow-2xs cursor-pointer font-medium"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Export</span>
                  </button>
                </div>
              </div>

              {/* Cluster Metadata Bar */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-100 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-500 uppercase block font-semibold">Active Date Range</span>
                  <span className="font-mono text-slate-800 text-xs font-medium">{clusterMetadata.dateRange}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-500 uppercase block font-semibold">Targeted AI Brands</span>
                  <span className="text-indigo-700 text-xs font-medium">{clusterMetadata.brands.join(', ')}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-500 uppercase block font-semibold">Attribution Strength</span>
                  <span className="text-slate-800 text-xs capitalize font-medium">{activeCluster.relationshipType.replace(/_/g, ' ')}</span>
                </div>
              </div>

              {/* Plain-English Correlation Analysis Rationale */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-1">
                <span className="text-[10px] uppercase font-bold text-indigo-700 block tracking-wider">
                  Plain-English Correlation Rationale:
                </span>
                <p className="leading-relaxed">{activeCluster.explanation}</p>
              </div>

              {/* Shared CDN Caution Notice if applicable */}
              {activeCluster.caveatNotes && (
                <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <div>
                    <strong className="block text-amber-800">Shared Infrastructure Caution:</strong>
                    <span>{activeCluster.caveatNotes}</span>
                  </div>
                </div>
              )}
            </div>

            {/* View Mode Switcher: Visual Node Graph vs Table */}
            <div className="bg-white rounded-xl border border-slate-200/90 overflow-hidden shadow-xs">
              <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-white">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                    Cluster Topology &bull; {activeCluster.indicators.length} Members
                  </span>
                </div>
                <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
                  <button
                    onClick={() => setViewMode('graph')}
                    className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer ${
                      viewMode === 'graph' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" />
                    <span>Visual Graph</span>
                  </button>
                  <button
                    onClick={() => setViewMode('table')}
                    className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer ${
                      viewMode === 'table' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Table className="w-3.5 h-3.5" />
                    <span>Table View</span>
                  </button>
                </div>
              </div>

              {/* Visual Node-Link Graph View */}
              {viewMode === 'graph' ? (
                <div className="p-6 bg-slate-50/70 min-h-[320px] flex items-center justify-center relative">
                  <svg className="w-full h-80" viewBox="0 0 600 320">
                    <defs>
                      <linearGradient id="linkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#2563eb" stopOpacity="0.8" />
                        <stop offset="100%" stopColor="#6366f1" stopOpacity="0.5" />
                      </linearGradient>
                    </defs>

                    {/* Central Pivot Hub */}
                    <g transform="translate(300, 160)">
                      <circle r="36" fill="#eff6ff" stroke="#2563eb" strokeWidth="2.5" className="animate-pulse" />
                      <text textAnchor="middle" dy="-5" fill="#1d4ed8" fontSize="10" fontWeight="bold">
                        PIVOT HUB
                      </text>
                      <text textAnchor="middle" dy="10" fill="#0f172a" fontSize="9" fontFamily="monospace">
                        {activeCluster.pivotValue.length > 15 ? activeCluster.pivotValue.slice(0, 13) + '..' : activeCluster.pivotValue}
                      </text>
                    </g>

                    {/* Surrounding Connected Member Nodes */}
                    {activeCluster.indicators.map((ind, idx, arr) => {
                      const count = arr.length;
                      const angle = (idx / count) * 2 * Math.PI;
                      const radius = 115;
                      const x = 300 + radius * Math.cos(angle);
                      const y = 160 + radius * Math.sin(angle);
                      const isHigh = ind.confidence_score >= 75;

                      return (
                        <g key={ind.id} className="cursor-pointer group" onClick={() => onInspectIndicator(ind)}>
                          {/* Connection Link Line */}
                          <line
                            x1="300"
                            y1="160"
                            x2={x}
                            y2={y}
                            stroke="url(#linkGrad)"
                            strokeWidth="1.5"
                            strokeDasharray={activeCluster.relationshipType === 'possible_association_shared_infra' ? '4,4' : undefined}
                          />

                          {/* Member Node Circle */}
                          <circle
                            cx={x}
                            cy={y}
                            r="22"
                            fill="#ffffff"
                            stroke={isHigh ? '#e11d48' : '#d97706'}
                            strokeWidth="2"
                            className="group-hover:scale-110 transition-transform shadow-xs"
                          />

                          {/* Member Node Label */}
                          <text
                            x={x}
                            y={y - 2}
                            textAnchor="middle"
                            fill="#0f172a"
                            fontSize="8"
                            fontWeight="bold"
                            fontFamily="monospace"
                          >
                            {ind.confidence_score}
                          </text>
                          <text
                            x={x}
                            y={y + 8}
                            textAnchor="middle"
                            fill="#475569"
                            fontSize="7"
                          >
                            {ind.target_brand ? ind.target_brand.slice(0, 6) : 'AI'}
                          </text>

                          {/* Tooltip on hover */}
                          <title>{`Observable: ${defang(ind.value)}\nBrand: ${ind.target_brand}\nScore: ${ind.confidence_score}\nMalware: ${ind.associated_malware || 'Unknown'}`}</title>
                        </g>
                      );
                    })}
                  </svg>
                  <div className="absolute bottom-2 right-4 text-[11px] text-slate-500 font-mono">
                    Click any satellite node to inspect indicator details
                  </div>
                </div>
              ) : (
                /* Table View */
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs whitespace-nowrap">
                    <thead className="bg-slate-50 text-slate-600 uppercase font-semibold border-b border-slate-200">
                      <tr>
                        <th className="py-2.5 px-4">Observable (Defanged)</th>
                        <th className="py-2.5 px-4">Brand</th>
                        <th className="py-2.5 px-4">Score</th>
                        <th className="py-2.5 px-4">Attributed Threat</th>
                        <th className="py-2.5 px-4">Discovery Source</th>
                        <th className="py-2.5 px-4 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono bg-white">
                      {activeCluster.indicators.map(item => (
                        <tr
                          key={item.id}
                          onClick={() => onInspectIndicator(item)}
                          className="hover:bg-slate-50/80 transition-colors cursor-pointer"
                        >
                          <td className="py-2.5 px-4 text-slate-900 font-bold truncate max-w-xs" title={item.value}>
                            {defang(item.value)}
                          </td>
                          <td className="py-2.5 px-4 text-indigo-700 font-sans capitalize whitespace-nowrap">
                            {item.target_brand.replace(/_/g, ' ')}
                          </td>
                          <td className="py-2.5 px-4 whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              item.confidence_score >= 75 ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-amber-50 text-amber-800 border border-amber-200'
                            }`}>
                              {item.confidence_score}/100
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-amber-800 font-sans truncate max-w-xs font-medium">
                            {item.associated_malware || 'Family unknown'}
                          </td>
                          <td className="py-2.5 px-4 text-slate-600 font-sans whitespace-nowrap">
                            {item.source}
                          </td>
                          <td className="py-2.5 px-4 text-right font-sans whitespace-nowrap">
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                onTriageIndicator(item.value);
                              }}
                              className="text-blue-600 hover:text-blue-800 text-xs font-semibold inline-flex items-center gap-1 cursor-pointer"
                            >
                              <Sparkles className="w-3 h-3" />
                              <span>Triage</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="lg:col-span-2 bg-white rounded-xl p-12 text-center text-slate-500 text-xs border border-slate-200">
            Select a cluster on the left to inspect correlated infrastructure.
          </div>
        )}
      </div>
    </div>
  );
};
