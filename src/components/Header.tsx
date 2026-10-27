import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Sparkles, 
  Download, 
  Activity,
  Radio, 
  FileText, 
  Layers,
  HelpCircle,
  Network,
  FolderLock,
  BookOpen,
  CheckCircle,
  Clock,
  FlaskConical
} from 'lucide-react';
import { EnrichedIndicator } from '../types/threat';
import { computeFeedHealth } from '../services/feedHealthService';
import { FeedHealthModal } from './FeedHealthModal';
import { ExportFeedsModal } from './ExportFeedsModal';

export type NavigationTab = 
  | 'feed' 
  | 'correlation' 
  | 'casebook' 
  | 'brief' 
  | 'certstream' 
  | 'scoring' 
  | 'methodology' 
  | 'tests';

interface HeaderProps {
  activeTab: NavigationTab;
  setActiveTab: (tab: NavigationTab) => void;
  onOpenAiModal: () => void;
  onOpenGuideModal?: () => void;
  indicators: EnrichedIndicator[];
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onOpenAiModal,
  indicators
}) => {
  const [isFeedHealthOpen, setIsFeedHealthOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  const feedHealth = computeFeedHealth(indicators);
  const hasDemoData = indicators.some(i => i.is_demo_data);
  const timeUtcStr = feedHealth.lastFeedUpdateUtc.slice(11, 16) + ' UTC';

  return (
    <>
      <header className="border-b border-slate-200 bg-white/95 sticky top-0 z-40 backdrop-blur-md shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-2">
          
          {/* Brand Identity */}
          <div 
            className="flex items-center space-x-3 cursor-pointer shrink-0" 
            onClick={() => setActiveTab('feed')}
          >
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-2xs">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-slate-900 whitespace-nowrap">
                  AI Lure Tracker
                </span>
                
                {/* Dynamic UTC Status Badge */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setIsFeedHealthOpen(true);
                  }}
                  className={`text-[11px] px-2 py-0.5 rounded-full border font-mono font-semibold tracking-wide flex items-center gap-1.5 transition-colors cursor-pointer ${
                    feedHealth.isStale
                      ? 'bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                  }`}
                  title="Click to view Upstream Feed Health"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${feedHealth.isStale ? 'bg-amber-500' : 'bg-emerald-500 animate-pulse'}`}></span>
                  <span>{feedHealth.isStale ? 'STALE' : 'LIVE'} ({timeUtcStr})</span>
                </button>

                {/* DEMO DATA badge if any synthetic records exist */}
                {hasDemoData && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 font-bold tracking-wider">
                    DEMO DATA
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-500 hidden sm:block truncate">
                Evidence-driven cyber threat intelligence investigation portal
              </p>
            </div>
          </div>

          {/* Navigation Tabs (Desktop & Tablet) */}
          <nav className="hidden xl:flex items-center space-x-1 bg-slate-100/90 p-1 rounded-xl border border-slate-200 text-xs">
            <button
              onClick={() => setActiveTab('feed')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'feed'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Threat Feed</span>
            </button>

            <button
              onClick={() => setActiveTab('correlation')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'correlation'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <Network className="w-3.5 h-3.5 text-indigo-600" />
              <span>Correlation</span>
            </button>

            <button
              onClick={() => setActiveTab('casebook')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'casebook'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <FolderLock className="w-3.5 h-3.5 text-amber-600" />
              <span>Casebook</span>
            </button>

            <button
              onClick={() => setActiveTab('brief')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'brief'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Weekly Brief</span>
            </button>

            <button
              onClick={() => setActiveTab('certstream')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'certstream'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <Radio className="w-3.5 h-3.5 text-emerald-600" />
              <span>CertStream</span>
            </button>

            <button
              onClick={() => setActiveTab('scoring')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'scoring'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <HelpCircle className="w-3.5 h-3.5 text-blue-600" />
              <span>Scoring Engine</span>
            </button>

            <button
              onClick={() => setActiveTab('methodology')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'methodology'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5 text-purple-600" />
              <span>Methodology</span>
            </button>

            <button
              onClick={() => setActiveTab('tests')}
              className={`px-2.5 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition-all ${
                activeTab === 'tests'
                  ? 'bg-white text-blue-600 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
              title="Run in-app CTI verification test suite"
            >
              <FlaskConical className="w-3.5 h-3.5 text-cyan-600" />
              <span>Tests</span>
            </button>
          </nav>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2 shrink-0">
            {/* Feed Health trigger */}
            <button
              onClick={() => setIsFeedHealthOpen(true)}
              className="flex items-center space-x-1.5 text-xs text-slate-700 hover:text-slate-900 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 transition-colors shadow-2xs font-medium cursor-pointer"
              title="Inspect 7 Upstream Feed Ingestion Health"
            >
              <Activity className="w-3.5 h-3.5 text-emerald-600" />
              <span className="hidden md:inline">Feed Health</span>
            </button>

            {/* AI Triage Trigger */}
            <button
              onClick={onOpenAiModal}
              className="flex items-center space-x-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white shadow-xs transition-all active:scale-95 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-100" />
              <span>AI Triage</span>
            </button>

            {/* Export Feeds Trigger */}
            <button
              onClick={() => setIsExportModalOpen(true)}
              className="flex items-center space-x-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 transition-colors shadow-2xs cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export Feeds</span>
            </button>
          </div>
        </div>

        {/* Responsive Secondary Tab Bar (for smaller viewports < 1280px) */}
        <div className="xl:hidden flex items-center px-4 py-2 bg-slate-50/95 border-t border-slate-200 text-xs overflow-x-auto gap-1 scrollbar-none">
          <button
            onClick={() => setActiveTab('feed')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'feed' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Layers className="w-3 h-3" />
            <span>Feed</span>
          </button>
          <button
            onClick={() => setActiveTab('correlation')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'correlation' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Network className="w-3 h-3 text-indigo-600" />
            <span>Correlation</span>
          </button>
          <button
            onClick={() => setActiveTab('casebook')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'casebook' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FolderLock className="w-3 h-3 text-amber-600" />
            <span>Casebook</span>
          </button>
          <button
            onClick={() => setActiveTab('brief')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'brief' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileText className="w-3 h-3" />
            <span>Brief</span>
          </button>
          <button
            onClick={() => setActiveTab('certstream')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'certstream' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Radio className="w-3 h-3 text-emerald-600" />
            <span>CertStream</span>
          </button>
          <button
            onClick={() => setActiveTab('scoring')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'scoring' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <HelpCircle className="w-3 h-3 text-blue-600" />
            <span>Scoring</span>
          </button>
          <button
            onClick={() => setActiveTab('methodology')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'methodology' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <BookOpen className="w-3 h-3 text-purple-600" />
            <span>Methodology</span>
          </button>
          <button
            onClick={() => setActiveTab('tests')}
            className={`px-2.5 py-1 rounded whitespace-nowrap font-medium flex items-center gap-1 ${
              activeTab === 'tests' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FlaskConical className="w-3 h-3 text-cyan-600" />
            <span>Tests</span>
          </button>
        </div>
      </header>

      {/* Upstream Feed Health Modal */}
      <FeedHealthModal
        isOpen={isFeedHealthOpen}
        onClose={() => setIsFeedHealthOpen(false)}
        indicators={indicators}
      />

      {/* Advanced Export Feeds Modal */}
      <ExportFeedsModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        indicators={indicators}
      />
    </>
  );
};
