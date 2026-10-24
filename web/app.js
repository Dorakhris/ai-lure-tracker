// AI Lure Tracker - Frontend Logic & Google AI Studio Gemini API Integration

let allIndicators = [];
let brandChart = null;
let lureChart = null;

// Fallback seed indicators if running statically before pipeline fetch
const fallbackSeedData = [
  {
    "value": "midjourney-v6-pc-crack.buzz",
    "target_brand": "midjourney",
    "lure_type": "fake_installer",
    "confidence_score": 100,
    "confidence_level": "high",
    "associated_malware": "Stealc",
    "source": "ThreatFox"
  },
  {
    "value": "https://gemini-advanced-ai-setup.xyz/login.php",
    "target_brand": "google_ai",
    "lure_type": "fake_installer",
    "confidence_score": 100,
    "confidence_level": "high",
    "associated_malware": "LummaC2 Stealer",
    "source": "OpenPhish"
  },
  {
    "value": "https://claude-35-sonnet-pro-free.icu/download/claude_installer.exe",
    "target_brand": "anthropic",
    "lure_type": "fake_installer",
    "confidence_score": 100,
    "confidence_level": "high",
    "associated_malware": "LummaC2 Stealer",
    "source": "URLhaus"
  },
  {
    "value": "chatgpt-4o-desktop-installer.top",
    "target_brand": "openai",
    "lure_type": "fake_installer",
    "confidence_score": 85,
    "confidence_level": "high",
    "associated_malware": "LummaC2 Stealer",
    "source": "CertStream"
  },
  {
    "value": "ollama-ai-desktop-installer.site",
    "target_brand": "ollama",
    "lure_type": "fake_installer",
    "confidence_score": 85,
    "confidence_level": "high",
    "associated_malware": "LummaC2 Stealer",
    "source": "CertStream"
  },
  {
    "value": "deepseek-coder-client-win64.lat",
    "target_brand": "deepseek",
    "lure_type": "fake_installer",
    "confidence_score": 85,
    "confidence_level": "high",
    "associated_malware": "LummaC2 Stealer",
    "source": "CertStream"
  },
  {
    "value": "https://openai-chatgpt-plus-token.cfd/auth/signin",
    "target_brand": "openai",
    "lure_type": "credential_phish",
    "confidence_score": 80,
    "confidence_level": "high",
    "associated_malware": "Unattributed AI Lure",
    "source": "PhishTank"
  },
  {
    "value": "langchain-copilot-plugin",
    "target_brand": "ai_ecosystem_library",
    "lure_type": "typosquat_dependency",
    "confidence_score": 60,
    "confidence_level": "medium",
    "associated_malware": "Trojanized PyPI/npm Dependency",
    "source": "PyPI"
  }
];

document.addEventListener("DOMContentLoaded", () => {
  lucide.createIcons();
  setupEventListeners();
  loadFeedData();
});

function setupEventListeners() {
  // Dropdown toggle
  const exportBtn = document.getElementById("exportDropdownBtn");
  const exportMenu = document.getElementById("exportMenu");
  exportBtn.addEventListener("click", () => {
    exportMenu.classList.toggle("hidden");
  });
  document.addEventListener("click", (e) => {
    if (!exportBtn.contains(e.target) && !exportMenu.contains(e.target)) {
      exportMenu.classList.add("hidden");
    }
  });

  // Search & Filter
  document.getElementById("searchInput").addEventListener("input", filterAndRenderTable);
  document.getElementById("brandFilter").addEventListener("change", filterAndRenderTable);
  document.getElementById("confidenceFilter").addEventListener("change", filterAndRenderTable);

  // Gemini AI Modal
  const modal = document.getElementById("aiModal");
  const openModalBtn = document.getElementById("openAiModalBtn");
  const closeModalBtn = document.getElementById("closeAiModalBtn");
  const runAiBtn = document.getElementById("runAiTriageBtn");

  openModalBtn.addEventListener("click", () => {
    modal.classList.remove("hidden");
    const savedKey = localStorage.getItem("GEMINI_API_KEY");
    if (savedKey) {
      document.getElementById("geminiApiKeyInput").value = savedKey;
    }
  });

  closeModalBtn.addEventListener("click", () => {
    modal.classList.add("hidden");
  });

  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });

  runAiBtn.addEventListener("click", runGeminiTriage);
}

async function loadFeedData() {
  try {
    // Attempt to load from feeds/ directory
    const response = await fetch("feeds/ai_lures_latest.json");
    if (!response.ok) throw new Error("Local feed fetch failed");
    allIndicators = await response.json();
  } catch (err) {
    console.warn("Using fallback seed data for offline preview:", err);
    allIndicators = fallbackSeedData;
  }

  updateMetrics();
  renderCharts();
  filterAndRenderTable();
}

function updateMetrics() {
  const total = allIndicators.length;
  const highConf = allIndicators.filter(i => (i.confidence_level || "").toLowerCase() === "high").length;
  const brands = new Set(allIndicators.map(i => i.target_brand)).size;

  document.getElementById("statTotalIocs").innerText = total;
  document.getElementById("statHighConf").innerText = highConf;
  document.getElementById("statBrandsCount").innerText = brands;
}

function renderCharts() {
  // Brand distribution counts
  const brandCounts = {};
  const lureCounts = {};

  allIndicators.forEach(i => {
    const b = (i.target_brand || "unknown").toUpperCase();
    brandCounts[b] = (brandCounts[b] || 0) + 1;

    const l = (i.lure_type || "unknown").replace("_", " ").toUpperCase();
    lureCounts[l] = (lureCounts[l] || 0) + 1;
  });

  // Chart 1: Brand Distribution (Doughnut)
  const ctxBrand = document.getElementById("brandChart").getContext("2d");
  if (brandChart) brandChart.destroy();
  brandChart = new Chart(ctxBrand, {
    type: "doughnut",
    data: {
      labels: Object.keys(brandCounts),
      datasets: [{
        data: Object.values(brandCounts),
        backgroundColor: [
          "#3b82f6", "#6366f1", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#94a3b8", font: { size: 11 } } }
      }
    }
  });

  // Chart 2: Lure Vectors (Bar)
  const ctxLure = document.getElementById("lureTypeChart").getContext("2d");
  if (lureChart) lureChart.destroy();
  lureChart = new Chart(ctxLure, {
    type: "bar",
    data: {
      labels: Object.keys(lureCounts),
      datasets: [{
        label: "Detections",
        data: Object.values(lureCounts),
        backgroundColor: "#10b981",
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "#1f2937" } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function filterAndRenderTable() {
  const searchTerm = document.getElementById("searchInput").value.toLowerCase().trim();
  const brandVal = document.getElementById("brandFilter").value;
  const confVal = document.getElementById("confidenceFilter").value;

  const filtered = allIndicators.filter(item => {
    const val = (item.value || item.indicator || "").toLowerCase();
    const brand = (item.target_brand || "").toLowerCase();
    const malware = (item.associated_malware || "").toLowerCase();
    const confLevel = (item.confidence_level || "").toLowerCase();

    // Text search
    const matchesSearch = !searchTerm || val.includes(searchTerm) || brand.includes(searchTerm) || malware.includes(searchTerm);
    // Brand filter
    const matchesBrand = brandVal === "ALL" || brand === brandVal.toLowerCase();
    // Confidence filter
    const matchesConf = confVal === "ALL" || confLevel === confVal.toLowerCase();

    return matchesSearch && matchesBrand && matchesConf;
  });

  const tbody = document.getElementById("feedTableBody");
  tbody.innerHTML = "";

  filtered.forEach(item => {
    const row = document.createElement("tr");
    row.className = "hover:bg-gray-800/40 transition-colors";

    const indicatorVal = item.value || item.indicator;
    const score = item.confidence_score || 50;
    const level = (item.confidence_level || "medium").toUpperCase();

    let badgeClass = "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";
    if (level === "HIGH") badgeClass = "bg-red-500/10 text-red-400 border border-red-500/20";
    if (level === "LOW") badgeClass = "bg-gray-500/10 text-gray-400 border border-gray-500/20";

    row.innerHTML = `
      <td class="py-3 px-4 font-semibold text-slate-100 truncate max-w-xs" title="${indicatorVal}">${indicatorVal}</td>
      <td class="py-3 px-4 text-slate-300 font-sans">${item.target_brand || "AI Brand"}</td>
      <td class="py-3 px-4 text-slate-400 font-sans">${(item.lure_type || "lure").replace("_", " ")}</td>
      <td class="py-3 px-4">
        <span class="px-2 py-0.5 rounded-full text-[11px] font-bold ${badgeClass}">
          ${score} (${level})
        </span>
      </td>
      <td class="py-3 px-4 text-amber-400 font-sans font-medium">${item.associated_malware || "Generic"}</td>
      <td class="py-3 px-4 text-slate-500 font-sans">${item.source || "Feed"}</td>
      <td class="py-3 px-4 text-right">
        <button onclick="triageIndicator('${indicatorVal}')" class="text-blue-400 hover:text-blue-300 font-sans font-semibold text-xs inline-flex items-center gap-1">
          <span>Triage</span> &rarr;
        </button>
      </td>
    `;
    tbody.appendChild(row);
  });

  document.getElementById("tableCountDisplay").innerText = `Showing ${filtered.length} of ${allIndicators.length} indicators`;
}

// Quick triage helper from table
window.triageIndicator = function(val) {
  document.getElementById("targetIndicatorInput").value = val;
  document.getElementById("aiModal").classList.remove("hidden");
  runGeminiTriage();
};

// Google AI Studio Gemini API Integration
async function runGeminiTriage() {
  const apiKey = document.getElementById("geminiApiKeyInput").value.trim();
  const indicator = document.getElementById("targetIndicatorInput").value.trim();
  const resultDiv = document.getElementById("aiTriageResult");
  const badge = document.getElementById("aiVerdictBadge");
  const content = document.getElementById("aiVerdictContent");

  if (!indicator) {
    alert("Please enter a domain, URL, or package name to analyze.");
    return;
  }

  if (!apiKey) {
    alert("Please provide a Google AI Studio API key. You can generate one in 10 seconds for free at aistudio.google.com/apikey");
    return;
  }

  localStorage.setItem("GEMINI_API_KEY", apiKey);

  resultDiv.classList.remove("hidden");
  badge.className = "text-xs px-2.5 py-0.5 rounded-full font-bold bg-blue-500/20 text-blue-400 animate-pulse";
  badge.innerText = "TRIAGING WITH GEMINI...";
  content.innerHTML = `<p class="italic text-slate-400">Consulting Google Gemini CTI reasoning models...</p>`;

  const prompt = `You are a Senior Cyber Threat Intelligence (CTI) and Malware Analyst specializing in infrastructure abusing AI brands (ChatGPT, Claude, Gemini, DeepSeek, Ollama, LangChain).
Analyze this candidate indicator: "${indicator}"

Provide a structured assessment with:
1. Verdict: [MALICIOUS HIGH CONFIDENCE | SUSPICIOUS | LIKELY BENIGN]
2. Abused AI Brand / Library: identify the impersonated brand.
3. Observed Delivery / Attack Pattern: (e.g. Fake Desktop Installer delivering Infostealer, Credential Harvesting, Typosquatted Dependency).
4. Likely Malware Family: (e.g. LummaC2, Stealc, Vidar, AMOS Stealer).
5. Relevant MITRE ATT&CK Techniques: (e.g. T1566.002, T1204.002, T1036.005, T1195.001).
6. Recommended Defensive Action: (Immediate DNS Sinkhole/Block, Proxy Alerting, Token Revocation).

Keep your response concise, bulleted, and ready for an analyst brief.`;

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
    const payload = {
      contents: [{
        parts: [{ text: prompt }]
      }]
    };

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error?.message || "Failed to reach Gemini API");
    }

    const data = await resp.json();
    const reply = data.candidates?.[0]?.content?.parts?.[0]?.text || "No analysis generated.";

    // Format Markdown to clean HTML paragraphs
    const formatted = reply
      .replace(/### (.*?)\n/g, '<h4 class="font-bold text-white mt-2 mb-1">$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>')
      .replace(/\* (.*?)\n/g, '<li class="ml-4 list-disc">$1</li>')
      .replace(/\n\n/g, '<br/>');

    badge.className = "text-xs px-2.5 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
    badge.innerText = "TRIAGE COMPLETE";
    content.innerHTML = `<div class="space-y-1.5">${formatted}</div>`;
  } catch (error) {
    badge.className = "text-xs px-2.5 py-0.5 rounded-full font-bold bg-red-500/20 text-red-400 border border-red-500/30";
    badge.innerText = "TRIAGE FAILED";
    content.innerHTML = `<p class="text-red-400 font-semibold">${error.message}</p><p class="text-[11px] text-slate-500">Verify your API key at aistudio.google.com/apikey</p>`;
  }
}
