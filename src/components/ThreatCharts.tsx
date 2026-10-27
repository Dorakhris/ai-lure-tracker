import React, { useState, useMemo } from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import { PieChart, BarChart3, Clock, AlertCircle } from 'lucide-react';
import { EnrichedIndicator } from '../types/threat';
import { BRAND_LABELS } from '../data/initialFeed';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
);

interface ThreatChartsProps {
  indicators: EnrichedIndicator[];
  selectedBrandFilter?: string;
  onSelectBrand?: (brand: string) => void;
}

export const ThreatCharts: React.FC<ThreatChartsProps> = ({ 
  indicators,
  selectedBrandFilter = 'ALL',
  onSelectBrand
}) => {
  const [timeRange, setTimeRange] = useState<'all' | '24h' | '7d' | '30d'>('all');

  // Filter indicators by time range
  const filteredIndicators = useMemo(() => {
    if (timeRange === 'all') return indicators;
    const now = Date.now();
    return indicators.filter(ind => {
      const firstSeen = new Date(ind.first_seen).getTime();
      const diffHours = (now - firstSeen) / (1000 * 3600);
      if (timeRange === '24h') return diffHours <= 24;
      if (timeRange === '7d') return diffHours <= 168;
      if (timeRange === '30d') return diffHours <= 720;
      return true;
    });
  }, [indicators, timeRange]);

  // Brand distribution calculation with counts and percentages
  const { brandLabels, brandValues, brandPercentages } = useMemo(() => {
    const counts: Record<string, number> = {};
    const total = filteredIndicators.length || 1;

    filteredIndicators.forEach(i => {
      const bKey = (i.target_brand || 'generic_ai').toLowerCase();
      const label = BRAND_LABELS[bKey] || bKey.toUpperCase();
      counts[label] = (counts[label] || 0) + 1;
    });

    // Sort brands descending by frequency
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const labels = sorted.map(([l]) => l);
    const values = sorted.map(([, v]) => v);
    const percentages = sorted.map(([, v]) => Math.round((v / total) * 100));

    return { brandLabels: labels, brandValues: values, brandPercentages: percentages };
  }, [filteredIndicators]);

  // Lure Delivery Vectors sorted descending
  const { lureLabels, lureValues } = useMemo(() => {
    const counts: Record<string, number> = {};
    filteredIndicators.forEach(i => {
      let l = (i.lure_type || 'unclassified').replace(/_/g, ' ');
      if (l === 'fake installer') l = 'Fake Installer (.exe/.msi)';
      else if (l === 'credential phish') l = 'Credential Phishing Form';
      else if (l === 'suspicious registration') l = 'Staged Domain Candidate';
      else if (l === 'lookalike package') l = 'Lookalike Package';
      counts[l] = (counts[l] || 0) + 1;
    });

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return {
      lureLabels: sorted.map(([k]) => k),
      lureValues: sorted.map(([, v]) => v)
    };
  }, [filteredIndicators]);

  const doughnutData = {
    labels: brandLabels,
    datasets: [
      {
        data: brandValues,
        backgroundColor: [
          '#3b82f6', // blue
          '#6366f1', // indigo
          '#10b981', // emerald
          '#f59e0b', // amber
          '#ef4444', // crimson
          '#8b5cf6', // purple
          '#ec4899', // pink
          '#14b8a6', // teal
          '#06b6d4', // cyan
        ],
        borderWidth: 2,
        borderColor: '#ffffff',
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: {
          color: '#475569',
          font: { size: 11, family: 'sans-serif' },
          boxWidth: 12,
          padding: 10,
          generateLabels: (chart: any) => {
            const data = chart.data;
            if (data.labels.length && data.datasets.length) {
              return data.labels.map((label: string, i: number) => {
                const count = data.datasets[0].data[i];
                const pct = brandPercentages[i];
                return {
                  text: `${label}: ${count} (${pct}%)`,
                  fillStyle: data.datasets[0].backgroundColor[i],
                  hidden: false,
                  index: i,
                };
              });
            }
            return [];
          }
        },
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#ffffff',
        bodyColor: '#cbd5e1',
        borderColor: '#334155',
        borderWidth: 1,
        callbacks: {
          label: (context: any) => {
            const val = context.parsed;
            const pct = brandPercentages[context.dataIndex];
            return ` ${context.label}: ${val} indicators (${pct}%)`;
          }
        }
      },
    },
    cutout: '62%',
  };

  const barData = {
    labels: lureLabels,
    datasets: [
      {
        label: 'Detected Indicators',
        data: lureValues,
        backgroundColor: '#2563eb',
        hoverBackgroundColor: '#1d4ed8',
        borderRadius: 4,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        ticks: {
          color: '#64748b',
          font: { size: 10, family: 'sans-serif' },
        },
        grid: { display: false },
      },
      y: {
        ticks: {
          color: '#64748b',
          stepSize: 1,
          font: { size: 10, family: 'sans-serif' },
        },
        grid: {
          color: '#f1f5f9',
        },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#ffffff',
        bodyColor: '#cbd5e1',
        borderColor: '#334155',
        borderWidth: 1,
        callbacks: {
          label: (context: any) => ` ${context.parsed.y} indicators observed`
        }
      },
    },
  };

  return (
    <div className="space-y-4">
      {/* Time Horizon Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 bg-white p-3 rounded-xl border border-slate-200/90 text-xs shadow-xs">
        <div className="flex items-center gap-2 text-slate-700">
          <Clock className="w-4 h-4 text-blue-600" />
          <span className="font-semibold">Observation Horizon:</span>
        </div>
        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
          <button
            type="button"
            onClick={() => setTimeRange('24h')}
            className={`px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${
              timeRange === '24h' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Last 24 Hours
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('7d')}
            className={`px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${
              timeRange === '7d' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Last 7 Days
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('30d')}
            className={`px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${
              timeRange === '30d' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Last 30 Days
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('all')}
            className={`px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${
              timeRange === 'all' ? 'bg-white text-blue-700 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All History ({indicators.length})
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Brand Distribution Donut */}
        <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs lg:col-span-2">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <PieChart className="w-4 h-4 text-blue-600" />
              <span>Targeted AI Brand Distribution (Counts &amp; %)</span>
            </h3>
            <span className="text-xs text-slate-500 font-mono">
              {filteredIndicators.length} Lures Analyzed
            </span>
          </div>
          <div className="h-64 relative flex items-center justify-center">
            {brandLabels.length > 0 ? (
              <Doughnut data={doughnutData} options={doughnutOptions} />
            ) : (
              <div className="text-xs text-slate-500">No brand data for selected range</div>
            )}
          </div>
        </div>

        {/* Lure Delivery Vectors Bar Chart */}
        <div className="bg-white rounded-xl p-5 border border-slate-200/90 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-emerald-600" />
                <span>Delivery Vectors (Ranked)</span>
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">Ranked</span>
            </div>
            <div className="h-56 relative flex items-center justify-center">
              {lureLabels.length > 0 ? (
                <Bar data={barData} options={barOptions} />
              ) : (
                <div className="text-xs text-slate-500">No vector data available</div>
              )}
            </div>
          </div>
          
          {/* Honest CTI attribution notice */}
          <div className="mt-4 p-2.5 bg-amber-50/70 rounded-lg border border-amber-200/70 flex items-start gap-2 text-[11px] text-amber-900">
            <AlertCircle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
            <span>
              <strong>Attribution note:</strong> Staged domain candidates and uncorroborated lookalikes are classified as suspected until active payload delivery is validated.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
