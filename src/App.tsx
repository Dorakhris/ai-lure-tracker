import React, { useState, useEffect, useMemo } from 'react';
import { Header, NavigationTab } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { ThreatCharts } from './components/ThreatCharts';
import { ThreatTable } from './components/ThreatTable';
import { IndicatorDetailsModal } from './components/IndicatorDetailsModal';
import { GeminiTriageModal } from './components/GeminiTriageModal';
import { WeeklyBriefView } from './components/WeeklyBriefView';
import { CertStreamView } from './components/CertStreamView';
import { CasebookView } from './components/CasebookView';
import { CorrelationView } from './components/CorrelationView';
import { ScoringEngineView } from './components/ScoringEngineView';
import { MethodologyView } from './components/MethodologyView';
import { TestsView } from './components/TestsView';
import { INITIAL_INDICATORS } from './data/initialFeed';
import { EnrichedIndicator } from './types/threat';
import { calculateEvidenceBasedScore, getActiveScoringConfig } from './services/scoringEngine';

export const App: React.FC = () => {
  const [indicators, setIndicators] = useState<EnrichedIndicator[]>(INITIAL_INDICATORS);
  const [activeTab, setActiveTab] = useState<NavigationTab>('feed');
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [triageTarget, setTriageTarget] = useState<string>('');
  const [triageIndicatorObj, setTriageIndicatorObj] = useState<EnrichedIndicator | undefined>(undefined);
  const [selectedIndicator, setSelectedIndicator] = useState<EnrichedIndicator | null>(null);
  const [scoringConfigVersion, setScoringConfigVersion] = useState<number>(0);

  // Sync with live static feed if available
  useEffect(() => {
    async function fetchFeeds() {
      try {
        const res = await fetch('/feeds/ai_lures_latest.json');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            setIndicators(data);
          }
        }
      } catch {
        // Fall back gracefully to initialized seed data
      }
    }
    fetchFeeds();
  }, []);

  // Compute uniform evidence-based scores across entire application with active scoring configuration
  const scoredIndicators = useMemo(() => {
    const config = getActiveScoringConfig();
    return indicators.map(ind => {
      const scoring = calculateEvidenceBasedScore(ind, config);
      return {
        ...ind,
        confidence_score: scoring.totalScore,
        confidence_level: scoring.confidenceLevel,
        verdict: scoring.verdict,
        verdict_rule_matched: scoring.verdictRuleMatched,
        scoring_breakdown: scoring,
        is_flagged_for_review: scoring.requiresManualReview,
      };
    });
  }, [indicators, scoringConfigVersion]);

  const handleOpenAiModal = (target = '', indObj?: EnrichedIndicator) => {
    setTriageTarget(target);
    setTriageIndicatorObj(indObj);
    setIsAiModalOpen(true);
  };

  const handleAddToFeed = (newIndicator: EnrichedIndicator) => {
    setIndicators(prev => [newIndicator, ...prev]);
  };

  const handleWeightsUpdated = () => {
    setScoringConfigVersion(v => v + 1);
  };

  return (
    <div className="min-h-screen flex flex-col bg-white text-slate-900">
      {/* Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAiModal={() => handleOpenAiModal('')}
        indicators={scoredIndicators}
      />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex-1 w-full space-y-8">
        {activeTab === 'feed' && (
          <>
            {/* KPI Metric Cards */}
            <MetricCards indicators={scoredIndicators} />

            {/* CTI Visualizations */}
            <ThreatCharts indicators={scoredIndicators} />

            {/* Malicious Infrastructure Table */}
            <ThreatTable
              indicators={scoredIndicators}
              onTriage={(target, indObj) => handleOpenAiModal(target, indObj)}
              onSelectIndicator={ind => setSelectedIndicator(ind)}
            />
          </>
        )}

        {activeTab === 'correlation' && (
          <CorrelationView
            indicators={scoredIndicators}
            onInspectIndicator={ind => setSelectedIndicator(ind)}
            onTriageIndicator={target => {
              const obj = scoredIndicators.find(i => i.value === target);
              handleOpenAiModal(target, obj);
            }}
            onNavigateToCasebook={() => setActiveTab('casebook')}
          />
        )}

        {activeTab === 'casebook' && (
          <CasebookView
            indicators={scoredIndicators}
            onInspectIndicator={ind => setSelectedIndicator(ind)}
            onTriageIndicator={target => {
              const obj = scoredIndicators.find(i => i.value === target);
              handleOpenAiModal(target, obj);
            }}
          />
        )}

        {activeTab === 'brief' && (
          <WeeklyBriefView 
            indicators={scoredIndicators} 
            onNavigateToFeed={() => setActiveTab('feed')}
          />
        )}

        {activeTab === 'certstream' && (
          <CertStreamView
            onTriage={target => {
              const obj = scoredIndicators.find(i => i.value === target);
              handleOpenAiModal(target, obj);
            }}
            onAddToFeed={handleAddToFeed}
          />
        )}

        {activeTab === 'scoring' && (
          <ScoringEngineView
            indicators={scoredIndicators}
            onWeightsUpdated={handleWeightsUpdated}
          />
        )}

        {activeTab === 'methodology' && (
          <MethodologyView />
        )}

        {activeTab === 'tests' && (
          <TestsView />
        )}
      </main>

      {/* Indicator Dossier / Investigation Modal */}
      {selectedIndicator && (
        <IndicatorDetailsModal
          indicator={selectedIndicator}
          allIndicators={scoredIndicators}
          onClose={() => setSelectedIndicator(null)}
          onTriage={target => {
            const current = selectedIndicator;
            setSelectedIndicator(null);
            handleOpenAiModal(target, current || undefined);
          }}
          onSelectIndicator={ind => setSelectedIndicator(ind)}
        />
      )}

      {/* Grounded Gemini AI Triage Modal */}
      <GeminiTriageModal
        isOpen={isAiModalOpen}
        onClose={() => setIsAiModalOpen(false)}
        initialIndicator={triageTarget}
        indicatorObj={triageIndicatorObj}
        onAddToFeed={handleAddToFeed}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 py-6 text-center text-xs text-slate-500 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>
            AI Lure Tracker &bull; Evidence-Driven Threat Intelligence Investigation Portal &bull; TLP:CLEAR
          </p>
          <div className="flex items-center space-x-4 text-[11px]">
            <button onClick={() => setActiveTab('methodology')} className="hover:text-slate-900 transition-colors font-medium">
              Methodology &amp; Standards
            </button>
            <button onClick={() => setActiveTab('scoring')} className="hover:text-slate-900 transition-colors font-medium">
              Scoring Weights
            </button>
            <button onClick={() => setActiveTab('tests')} className="hover:text-slate-900 transition-colors font-medium">
              Verification Tests
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
