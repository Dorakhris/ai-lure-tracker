import React, { useState } from 'react';
import { 
  FolderLock, 
  Plus, 
  FileText, 
  Download, 
  Trash2, 
  AlertCircle, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  HelpCircle, 
  ShieldAlert, 
  Tag, 
  ExternalLink,
  ChevronRight,
  Sparkles,
  BookOpen,
  ArrowRight,
  Shield,
  FileCode,
  Layers,
  Share2
} from 'lucide-react';
import { InvestigationCase, EnrichedIndicator } from '../types/threat';
import { 
  getStoredCases, 
  updateOrAddCase, 
  deleteCase, 
  exportCaseAsMarkdown, 
  exportCaseAsStix21, 
  validateStix21Bundle 
} from '../services/casebookService';
import { triggerDownload } from '../utils/exportUtils';
import { defang, copyToClipboard } from '../utils/defang';

interface CasebookViewProps {
  indicators: EnrichedIndicator[];
  onInspectIndicator: (ind: EnrichedIndicator) => void;
  onTriageIndicator: (val: string) => void;
}

export const CasebookView: React.FC<CasebookViewProps> = ({
  indicators,
  onInspectIndicator,
  onTriageIndicator,
}) => {
  const [cases, setCases] = useState<InvestigationCase[]>(getStoredCases());
  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.id || '');
  const [isCreating, setIsCreating] = useState(false);
  const [sharedNotice, setSharedNotice] = useState<string | null>(null);

  // New Case form state
  const [newTitle, setNewTitle] = useState('');
  const [newQuestion, setNewQuestion] = useState('');
  const [newPriority, setNewPriority] = useState<InvestigationCase['priority']>('high');
  const [newAnalyst, setNewAnalyst] = useState('CTI Investigator');

  // Quick addition states
  const [selectedIndicatorToAdd, setSelectedIndicatorToAdd] = useState('');
  const [newFindingText, setNewFindingText] = useState('');
  const [newUnresolvedText, setNewUnresolvedText] = useState('');
  const [newActionText, setNewActionText] = useState('');
  const [newHypothesisStatement, setNewHypothesisStatement] = useState('');
  const [newHypothesisEvidence, setNewHypothesisEvidence] = useState('');
  const [newAltExplanation, setNewAltExplanation] = useState('');

  const activeCase = cases.find(c => c.id === selectedCaseId);

  const handleCreateCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newQuestion.trim()) return;

    const newCase: InvestigationCase = {
      id: `CASE-2026-${String(cases.length + 1).padStart(3, '0')}`,
      title: newTitle.trim(),
      investigationQuestion: newQuestion.trim(),
      status: 'in_progress',
      priority: newPriority,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      leadAnalyst: newAnalyst.trim() || 'CTI Investigator',
      indicatorIds: [],
      hypotheses: [],
      alternativeExplanations: [],
      evidenceNotes: [],
      timeline: [
        {
          id: `time-${Date.now()}`,
          timestamp: new Date().toISOString(),
          title: 'Case Opened',
          description: `Investigation initiated: "${newQuestion.trim()}"`,
        }
      ],
      findings: [],
      unresolvedQuestions: [],
      recommendedActions: [],
      finalSummary: 'Investigation active. Documenting preliminary evidence and hypothesis testing.',
    };

    const updated = updateOrAddCase(newCase);
    setCases(updated);
    setSelectedCaseId(newCase.id);
    setIsCreating(false);
    setNewTitle('');
    setNewQuestion('');
  };

  const handleDeleteCase = (id: string) => {
    if (confirm(`Are you sure you want to delete case ${id}?`)) {
      const updated = deleteCase(id);
      setCases(updated);
      if (selectedCaseId === id) {
        setSelectedCaseId(updated[0]?.id || '');
      }
    }
  };

  const handleAddIndicatorToActiveCase = () => {
    if (!activeCase || !selectedIndicatorToAdd) return;
    if (activeCase.indicatorIds.includes(selectedIndicatorToAdd)) return;

    const indObj = indicators.find(i => i.id === selectedIndicatorToAdd);
    const updatedCase: InvestigationCase = {
      ...activeCase,
      indicatorIds: [...activeCase.indicatorIds, selectedIndicatorToAdd],
      timeline: [
        ...activeCase.timeline,
        {
          id: `time-${Date.now()}`,
          timestamp: new Date().toISOString(),
          title: 'Indicator Added to Case',
          description: `Added ${indObj?.value} (${indObj?.target_brand}) for active correlation.`,
          indicatorValue: indObj?.value,
        }
      ]
    };

    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setSelectedIndicatorToAdd('');
  };

  const handleRemoveIndicator = (indId: string) => {
    if (!activeCase) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      indicatorIds: activeCase.indicatorIds.filter(id => id !== indId),
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
  };

  const handleAddHypothesis = () => {
    if (!activeCase || !newHypothesisStatement.trim()) return;
    const newHyp = {
      id: `hyp-${Date.now()}`,
      statement: newHypothesisStatement.trim(),
      status: 'unverified' as const,
      supportingEvidence: newHypothesisEvidence.trim() || 'Awaiting telemetry corroboration.',
      alternativeExplanation: 'Coincidental overlap or benign testing activity.'
    };
    const updatedCase: InvestigationCase = {
      ...activeCase,
      hypotheses: [...activeCase.hypotheses, newHyp],
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setNewHypothesisStatement('');
    setNewHypothesisEvidence('');
  };

  const handleToggleHypothesisStatus = (hypId: string) => {
    if (!activeCase) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      hypotheses: activeCase.hypotheses.map(h => {
        if (h.id !== hypId) return h;
        const nextStatus = h.status === 'unverified' ? 'supported' : h.status === 'supported' ? 'refuted' : 'unverified';
        return { ...h, status: nextStatus };
      })
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
  };

  const handleAddFinding = () => {
    if (!activeCase || !newFindingText.trim()) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      findings: [...activeCase.findings, newFindingText.trim()],
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setNewFindingText('');
  };

  const handleAddUnresolved = () => {
    if (!activeCase || !newUnresolvedText.trim()) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      unresolvedQuestions: [...activeCase.unresolvedQuestions, newUnresolvedText.trim()],
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setNewUnresolvedText('');
  };

  const handleAddAction = () => {
    if (!activeCase || !newActionText.trim()) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      recommendedActions: [...activeCase.recommendedActions, newActionText.trim()],
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setNewActionText('');
  };

  const handleAddAltExplanation = () => {
    if (!activeCase || !newAltExplanation.trim()) return;
    const updatedCase: InvestigationCase = {
      ...activeCase,
      alternativeExplanations: [...activeCase.alternativeExplanations, newAltExplanation.trim()],
    };
    const updated = updateOrAddCase(updatedCase);
    setCases(updated);
    setNewAltExplanation('');
  };

  // Exports
  const handleExportMarkdown = () => {
    if (!activeCase) return;
    const md = exportCaseAsMarkdown(activeCase, indicators);
    triggerDownload(md, `${activeCase.id}-investigation-dossier.md`, 'text/markdown');
  };

  const handleExportJson = () => {
    if (!activeCase) return;
    const jsonStr = JSON.stringify(activeCase, null, 2);
    triggerDownload(jsonStr, `${activeCase.id}.json`, 'application/json');
  };

  const handleExportStix = () => {
    if (!activeCase) return;
    const stixBundle = exportCaseAsStix21(activeCase, indicators);
    const validation = validateStix21Bundle(stixBundle);
    if (!validation.isValid) {
      alert(`STIX 2.1 Validation Warning: ${validation.errors.join(', ')}`);
    }
    triggerDownload(JSON.stringify(stixBundle, null, 2), `${activeCase.id}-stix21.json`, 'application/json');
  };

  const caseIndicators = indicators.filter(i => activeCase?.indicatorIds.includes(i.id));

  const handleShareCaseDefanged = async () => {
    if (!activeCase) return;
    const caseSummary = [
      `# [TLP:CLEAR] Incident Case Summary: ${activeCase.id}`,
      `**Title:** ${activeCase.title}`,
      `**Status:** ${activeCase.status.toUpperCase()} | **Priority:** ${activeCase.priority.toUpperCase()}`,
      `**Lead Analyst:** ${activeCase.leadAnalyst}`,
      `**Primary Question:** ${activeCase.investigationQuestion}`,
      '',
      `## Corroborated Indicators (${caseIndicators.length})`,
      ...caseIndicators.map(i => `- \`${defang(i.value)}\` | Target: ${i.target_brand} | Verdict: ${i.verdict || 'Suspected'} | Score: ${i.confidence_score}/100`),
      '',
      `## Key Hypotheses`,
      ...activeCase.hypotheses.map(h => `- [${h.status.toUpperCase()}] ${h.statement}`),
      '',
      `## Findings`,
      ...activeCase.findings.map(f => `- ${f}`),
      '',
      `## Recommended Actions`,
      ...activeCase.recommendedActions.map(a => `- ${a}`)
    ].join('\n');

    await copyToClipboard(caseSummary);
    setSharedNotice('Copied Defanged Case Summary to Clipboard!');
    setTimeout(() => setSharedNotice(null), 3000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Banner */}
      <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-2xs">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <span>CTI Investigation Casebook</span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                {cases.length} CASES
              </span>
            </h2>
            <p className="text-xs text-slate-500">
              Structured analytical workflow for hypothesis testing, evidence logging, and STIX 2.1 reporting
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsCreating(true)}
          className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 shadow-xs transition-all shrink-0 cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* New Case Modal / Drawer */}
      {isCreating && (
        <div className="rounded-xl p-6 border border-blue-300 bg-white shadow-xl space-y-4 text-slate-800">
          <div className="flex items-center justify-between pb-2 border-b border-slate-200">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-blue-600" />
              <span>Initiate New Threat Intelligence Case</span>
            </h3>
            <button
              onClick={() => setIsCreating(false)}
              className="text-xs text-slate-500 hover:text-slate-800 cursor-pointer"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleCreateCase} className="space-y-4 text-xs">
            <div>
              <label className="block font-semibold text-slate-700 mb-1">Case Title</label>
              <input
                type="text"
                required
                value={newTitle}
                onChange={e => setNewTitle(e.target.value)}
                placeholder="e.g. LummaC2 Stealer Fake Claude Installer Campaign"
                className="w-full bg-white border border-slate-300 text-slate-900 px-3.5 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-700 mb-1">Investigation Question (PIR / Threat Hypothesis)</label>
              <textarea
                required
                rows={2}
                value={newQuestion}
                onChange={e => setNewQuestion(e.target.value)}
                placeholder="e.g. Are the newly registered domains in .icu and .lat operated by the same LummaC2 distribution cluster?"
                className="w-full bg-white border border-slate-300 text-slate-900 px-3.5 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Priority</label>
                <select
                  value={newPriority}
                  onChange={e => setNewPriority(e.target.value as any)}
                  className="w-full bg-white border border-slate-300 text-slate-800 px-3 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs font-medium cursor-pointer"
                >
                  <option value="critical">Critical (Active Enterprise Compromise)</option>
                  <option value="high">High (Brand Impersonation / Active Staging)</option>
                  <option value="medium">Medium (Candidate Threat Activity)</option>
                  <option value="low">Low (Monitoring / Reconnaissance)</option>
                </select>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Lead Analyst</label>
                <input
                  type="text"
                  value={newAnalyst}
                  onChange={e => setNewAnalyst(e.target.value)}
                  placeholder="Analyst Name or Callout"
                  className="w-full bg-white border border-slate-300 text-slate-900 px-3.5 py-2 rounded-lg focus:outline-none focus:border-blue-500 shadow-2xs"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsCreating(false)}
                className="px-3.5 py-1.5 rounded-lg text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 transition-colors font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg text-white font-semibold bg-blue-600 hover:bg-blue-700 shadow-xs transition-colors cursor-pointer"
              >
                Create Case
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Main Layout: Case Selector + Active Case Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Column: Case List */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider px-1">Active Cases</h3>
          <div className="space-y-2">
            {cases.map(c => {
              const isSelected = c.id === selectedCaseId;
              let priorityColor = 'border-blue-200 text-blue-700 bg-blue-50';
              if (c.priority === 'critical') priorityColor = 'border-rose-200 text-rose-700 bg-rose-50';
              if (c.priority === 'high') priorityColor = 'border-amber-200 text-amber-800 bg-amber-50';

              return (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseId(c.id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-blue-50/60 border-blue-500 shadow-xs ring-1 ring-blue-500/20'
                      : 'bg-white border-slate-200 hover:border-slate-300 shadow-2xs'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="font-mono font-bold text-slate-700">{c.id}</span>
                    <span className={`px-2 py-0.2 rounded uppercase font-semibold text-[10px] border ${priorityColor}`}>
                      {c.priority}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-900 line-clamp-2">{c.title}</h4>
                  <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 font-medium">
                    <span>{c.indicatorIds.length} Indicators</span>
                    <span className="capitalize">{c.status.replace('_', ' ')}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Case Workspace */}
        {activeCase ? (
          <div className="lg:col-span-3 space-y-6">
            {/* Case Dossier Header */}
            <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center space-x-2.5">
                  <span className="text-xs px-2.5 py-0.5 rounded font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                    {activeCase.id}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded font-semibold uppercase bg-slate-100 text-slate-700 border border-slate-200">
                    Status: {activeCase.status.replace('_', ' ')}
                  </span>
                  <span className="text-xs text-slate-500">
                    Lead: <strong className="text-slate-800">{activeCase.leadAnalyst}</strong>
                  </span>
                </div>

                {/* Export Actions */}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={handleShareCaseDefanged}
                    className="px-2.5 py-1.5 rounded-lg text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold flex items-center gap-1.5 shadow-xs transition-colors cursor-pointer"
                    title="Copy Defanged Incident Summary to Clipboard"
                  >
                    <Share2 className="w-3.5 h-3.5" />
                    <span>Share Case</span>
                  </button>

                  <button
                    onClick={handleExportMarkdown}
                    className="px-2.5 py-1.5 rounded-lg text-xs bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 flex items-center gap-1.5 transition-colors shadow-2xs font-medium cursor-pointer"
                    title="Export Markdown Brief"
                  >
                    <FileText className="w-3.5 h-3.5 text-blue-600" />
                    <span>Markdown</span>
                  </button>

                  <button
                    onClick={handleExportJson}
                    className="px-2.5 py-1.5 rounded-lg text-xs bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 flex items-center gap-1.5 transition-colors shadow-2xs font-medium cursor-pointer"
                    title="Export JSON Dossier"
                  >
                    <FileCode className="w-3.5 h-3.5 text-emerald-600" />
                    <span>JSON</span>
                  </button>

                  <button
                    onClick={handleExportStix}
                    className="px-2.5 py-1.5 rounded-lg text-xs bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 flex items-center gap-1.5 transition-colors shadow-2xs font-medium cursor-pointer"
                    title="Export OASIS STIX 2.1 Bundle"
                  >
                    <Shield className="w-3.5 h-3.5 text-amber-600" />
                    <span>STIX 2.1</span>
                  </button>

                  <button
                    onClick={() => handleDeleteCase(activeCase.id)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors cursor-pointer"
                    title="Delete Case"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {sharedNotice && (
                <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2 font-medium">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  <span>{sharedNotice}</span>
                </div>
              )}

              <h2 className="text-lg font-bold text-slate-900">{activeCase.title}</h2>
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700">
                <span className="text-[10px] uppercase font-bold text-blue-700 block mb-0.5">Primary Investigation Question:</span>
                <p className="italic">{activeCase.investigationQuestion}</p>
              </div>
            </div>

            {/* Indicators Under Investigation */}
            <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-100">
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-600" />
                  <span>Indicators Under Investigation ({caseIndicators.length})</span>
                </h3>

                {/* Quick Add from Feed */}
                <div className="flex items-center space-x-2">
                  <select
                    value={selectedIndicatorToAdd}
                    onChange={e => setSelectedIndicatorToAdd(e.target.value)}
                    className="bg-white border border-slate-300 text-xs text-slate-800 px-2.5 py-1.5 rounded-lg max-w-xs truncate shadow-2xs font-medium cursor-pointer"
                  >
                    <option value="">Select indicator to attach...</option>
                    {indicators
                      .filter(i => !activeCase.indicatorIds.includes(i.id))
                      .map(i => (
                        <option key={i.id} value={i.id}>
                          {defang(i.value)} ({i.target_brand})
                        </option>
                      ))}
                  </select>
                  <button
                    onClick={handleAddIndicatorToActiveCase}
                    disabled={!selectedIndicatorToAdd}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-xs font-semibold rounded-lg shadow-2xs cursor-pointer"
                  >
                    Attach
                  </button>
                </div>
              </div>

              {caseIndicators.length === 0 ? (
                <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-center text-xs text-slate-500">
                  No indicators currently attached to this case. Select an indicator above or click "Add to Case" in the Threat Feed.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  {caseIndicators.map(ind => (
                    <div
                      key={ind.id}
                      className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-2 group hover:border-slate-300 transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="font-mono font-bold text-slate-900 truncate" title={ind.value}>{defang(ind.value)}</div>
                        <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5">
                          <span className="capitalize">{ind.target_brand}</span>
                          <span>&bull;</span>
                          <span className="text-amber-800 font-medium">{ind.associated_malware || 'Lure'}</span>
                          <span>&bull;</span>
                          <span className="text-rose-600 font-bold">{ind.confidence_score}/100</span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-1 shrink-0">
                        <button
                          onClick={() => onInspectIndicator(ind)}
                          className="px-2 py-1 rounded text-[11px] bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 shadow-2xs font-medium cursor-pointer"
                          title="Inspect Dossier"
                        >
                          Dossier
                        </button>
                        <button
                          onClick={() => onTriageIndicator(ind.value)}
                          className="px-2 py-1 rounded text-[11px] bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200 font-medium cursor-pointer"
                          title="Triage"
                        >
                          Triage
                        </button>
                        <button
                          onClick={() => handleRemoveIndicator(ind.id)}
                          className="p-1 rounded text-slate-400 hover:text-rose-600 cursor-pointer"
                          title="Detach from Case"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Hypotheses & Counter-Hypotheses (Structured Analysis) */}
            <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs space-y-4">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2 pb-2 border-b border-slate-100">
                <HelpCircle className="w-4 h-4 text-amber-600" />
                <span>Analytical Hypotheses &amp; Alternative Explanations</span>
              </h3>

              {/* Existing hypotheses list */}
              <div className="space-y-2.5">
                {activeCase.hypotheses.map(hyp => {
                  let statusBadge = 'bg-yellow-50 text-yellow-800 border-yellow-200';
                  if (hyp.status === 'supported') statusBadge = 'bg-emerald-50 text-emerald-700 border-emerald-200';
                  if (hyp.status === 'refuted') statusBadge = 'bg-rose-50 text-rose-700 border border-rose-200';

                  return (
                    <div
                      key={hyp.id}
                      className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-semibold text-slate-900">
                          {hyp.statement}
                        </div>
                        <button
                          onClick={() => handleToggleHypothesisStatus(hyp.id)}
                          className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border cursor-pointer ${statusBadge}`}
                          title="Click to toggle status (Unverified -> Supported -> Refuted)"
                        >
                          {hyp.status}
                        </button>
                      </div>
                      <div className="text-[11px] text-slate-600">
                        <strong className="text-slate-800">Supporting Evidence:</strong> {hyp.supportingEvidence}
                      </div>
                      {hyp.alternativeExplanation && (
                        <div className="text-[11px] text-slate-500 italic">
                          <strong>Alternative Explanation:</strong> {hyp.alternativeExplanation}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Add Hypothesis form */}
              <div className="pt-2 flex flex-col sm:flex-row gap-2 text-xs">
                <input
                  type="text"
                  value={newHypothesisStatement}
                  onChange={e => setNewHypothesisStatement(e.target.value)}
                  placeholder="New Hypothesis (e.g. Actor is using bulletproof hosting ASXXXXX)..."
                  className="flex-1 bg-white border border-slate-300 px-3 py-1.5 rounded-lg text-slate-900 focus:outline-none focus:border-blue-500 shadow-2xs"
                />
                <input
                  type="text"
                  value={newHypothesisEvidence}
                  onChange={e => setNewHypothesisEvidence(e.target.value)}
                  placeholder="Evidence reference..."
                  className="w-56 bg-white border border-slate-300 px-3 py-1.5 rounded-lg text-slate-900 focus:outline-none focus:border-blue-500 shadow-2xs"
                />
                <button
                  onClick={handleAddHypothesis}
                  className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold shrink-0 shadow-2xs cursor-pointer"
                >
                  Add Hypothesis
                </button>
              </div>

              {/* Alternative Explanations section */}
              <div className="pt-3 border-t border-slate-100 space-y-2">
                <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                  Alternative Explanations (Countering Confirmation Bias):
                </span>
                <ul className="list-disc list-inside text-xs text-slate-700 space-y-1">
                  {activeCase.alternativeExplanations.map((alt, i) => (
                    <li key={i}>{alt}</li>
                  ))}
                </ul>
                <div className="flex gap-2 text-xs pt-1">
                  <input
                    type="text"
                    value={newAltExplanation}
                    onChange={e => setNewAltExplanation(e.target.value)}
                    placeholder="Document competing alternative explanation (e.g. benign test, parked domain)..."
                    className="flex-1 bg-white border border-slate-300 px-3 py-1.5 rounded-lg text-slate-900 focus:outline-none focus:border-blue-500 shadow-2xs"
                  />
                  <button
                    onClick={handleAddAltExplanation}
                    className="px-3.5 py-1.5 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 rounded-lg shrink-0 font-medium shadow-2xs cursor-pointer"
                  >
                    Add Alternative
                  </button>
                </div>
              </div>
            </div>

            {/* Findings & Action Items */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Findings */}
              <div className="bg-white rounded-xl p-4 border border-slate-200/90 shadow-xs space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Key Findings</span>
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-700">
                  {activeCase.findings.map((f, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-emerald-600 font-bold">&bull;</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <div className="flex gap-2 pt-1 text-xs">
                  <input
                    type="text"
                    value={newFindingText}
                    onChange={e => setNewFindingText(e.target.value)}
                    placeholder="Add verified finding..."
                    className="flex-1 bg-white border border-slate-300 px-2.5 py-1.5 rounded-lg text-slate-900 shadow-2xs"
                  />
                  <button
                    onClick={handleAddFinding}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg font-medium shadow-2xs cursor-pointer"
                  >
                    Add
                  </button>
                </div>
              </div>

              {/* Recommended Actions */}
              <div className="bg-white rounded-xl p-4 border border-slate-200/90 shadow-xs space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-blue-600" />
                  <span>Actionable Mitigations</span>
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-700">
                  {activeCase.recommendedActions.map((a, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-blue-600 font-bold">{i + 1}.</span>
                      <span>{a}</span>
                    </li>
                  ))}
                </ul>
                <div className="flex gap-2 pt-1 text-xs">
                  <input
                    type="text"
                    value={newActionText}
                    onChange={e => setNewActionText(e.target.value)}
                    placeholder="Add defensive mitigation..."
                    className="flex-1 bg-white border border-slate-300 px-2.5 py-1.5 rounded-lg text-slate-900 shadow-2xs"
                  />
                  <button
                    onClick={handleAddAction}
                    className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium shadow-2xs cursor-pointer"
                  >
                    Add
                  </button>
                </div>
              </div>
            </div>

            {/* Case Timeline */}
            <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs space-y-3">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2 pb-2 border-b border-slate-100">
                <Clock className="w-4 h-4 text-slate-500" />
                <span>Observation Timeline</span>
              </h3>
              <div className="space-y-2 text-xs">
                {activeCase.timeline.map((ev, i) => (
                  <div
                    key={ev.id || i}
                    className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-50 border border-slate-200"
                  >
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap pt-0.5">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <div>
                      <div className="font-semibold text-slate-900">{ev.title}</div>
                      <p className="text-slate-600 text-[11px]">{ev.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="lg:col-span-3 bg-white rounded-xl p-12 text-center text-slate-500 text-xs border border-slate-200">
            Select a case on the left or create a new one to begin structured threat intelligence investigation.
          </div>
        )}
      </div>
    </div>
  );
};
