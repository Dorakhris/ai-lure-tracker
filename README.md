# 🛡️ AI Lure Tracker: Threat Intelligence & OSINT Investigation Platform

[![CTI](https://img.shields.io/badge/CTI-Threat%20Intelligence-blue.svg)](https://github.com/Dorakhris/ai-lure-tracker)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6-646cff.svg)](https://vitejs.dev/)
[![Vitest](https://img.shields.io/badge/Tests-13%2F13%20Passing-emerald.svg)](https://vitest.dev/)
[![STIX 2.1](https://img.shields.io/badge/Format-OASIS%20STIX%202.1-orange.svg)](https://oasis-open.github.io/cti-documentation/)
[![MITRE ATT&CK](https://img.shields.io/badge/Matrix-Enterprise%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **A practical, evidence-driven Cyber Threat Intelligence (CTI) investigation platform tracking malicious infrastructure, trojanized fake desktop installers, credential phishing portals, and supply-chain typosquats weaponizing AI brands (ChatGPT, Claude, Gemini, DeepSeek, Midjourney, Ollama, LangChain).**

---

## 🎯 Threat Landscape & Investigative Focus

Adversaries aggressively exploit user search intent and developer workflows around artificial intelligence:
1. **Trojanized Desktop Installers:** Deceptive lookalike domains masquerading as "Claude 3.5 Sonnet Setup", "ChatGPT Desktop", or "Midjourney PC Crack" distributing information stealers (**LummaC2**, **Stealc**, **AMOS Stealer**, **Vidar**).
2. **Credential & OAuth Harvesting:** Deceptive portals impersonating AI sign-in interfaces to compromise enterprise tokens and developer credentials.
3. **Software Supply Chain Typosquatting:** Coordinated rogue packages published on **PyPI** and **npm** with namespaces adjacent to AI libraries (`primarypath-langgraph`, `primarypath-claude-agent`, `langchain-copilot-plugin`) executing reverse shells and exfiltration routines.

---

## 🔬 Core Capabilities

### 1. Evidence-Driven Indicator Dossier
- **Observable Breakdown:** Detailed view of indicator type, first-seen timestamps, and original reporting sensors.
- **Direct Public OSINT Links:** One-click pivots into `crt.sh` (Certificate Transparency history), `VirusTotal` (antivirus detection ratios), `urlscan.io` (DOM screenshots and payloads), `URLhaus` / `ThreatFox` (abuse.ch records), `PyPI` / `npm` registries, and `Shodan` / `AbuseIPDB`.
- **Live DNS-over-HTTPS (DoH) Resolver:** In-browser query engine resolving real-time `A` records via Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) with zero API keys and zero cost.
- **Transparent Evidence vs Gaps:** Explicitly documents observed behaviors, missing information, conflicting signals, and investigative limitations.

### 2. Transparent Confidence Scoring Model
Separates scoring into independent, corroborated components:
- **Source Reliability (0–30):** Verified abuse.ch feeds, OpenPhish, PhishTank, CertStream, or registry feeds.
- **Quality of Observed Evidence (0–35):** Direct executable download lure (`.exe`, `.msi`), login form presence, and multi-engine VT corroboration.
- **Independent Corroboration (0–20):** Multi-sensor corroboration vs single-observer reporting.
- **Behavioral Indicators (0–25):** AI brand typosquatting, suspicious throwaway TLDs (`.top`, `.icu`, `.buzz`, `.cfd`, `.lat`), and known malware family links.
- **Penalties & Caveats:** Suppresses false positives for legitimate vendor domains (`openai.com`, `anthropic.com`, `google.com`) and applies shared CDN notices.
- **Manual Review Flags:** Automatically flags ambiguous or uncorroborated indicators (`REVIEW REQUIRED`).

### 3. Infrastructure Correlation Engine
Groups indicators by empirical infrastructure linkages:
- **Shared Apex Domains:** Groups subdomains and URLs sharing an identical parent domain (`confirmed_association`).
- **Coordinated Package Namespaces:** Groups supply-chain packages sharing author prefixes (`confirmed_association`).
- **Shared IP Addresses:** Detects IP co-location while distinguishing dedicated hosts from multitenant CDNs (`Cloudflare AS13335`, `AWS CloudFront AS16509`, `Fastly AS54113`), flagging CDNs as `possible_association_shared_infra` with caution banners.
- **Threat Actor / Malware Campaigns:** Correlates indicators distributing identical malware families.
- **One-Click Case Attachment:** Directly import correlation clusters into investigation cases.

### 4. Investigation Casebook & STIX 2.1 Reporting
- **Case Management:** Create and manage CTI cases with Priority, Status, Priority Intelligence Requirements (PIRs), and Lead Analyst.
- **Hypothesis Testing:** Formulate and test hypotheses (`Supported`, `Refuted`, `Unverified`) with supporting evidence.
- **Alternative Explanations:** Document competing alternative explanations to counter analyst confirmation bias.
- **Timeline & Findings:** Track chronological observation milestones, findings, and actionable mitigations.
- **Validated STIX 2.1 Export:** Generates schema-compliant OASIS STIX 2.1 bundles (`report`, `indicator`, `identity`, `relationship` SDOs/SROs).
- **Markdown & JSON Export:** Instant download of investigation briefs.

### 5. Grounded Gemini AI Triage
- **Prompt Injection Defense:** Strict sanitization of untrusted observable inputs and delimiters.
- **Grounded 4-Quadrant Delineation:** Strictly separates:
  1. *Facts Supported by Source Records*
  2. *Analyst Inferences*
  3. *Unverified Hypotheses*
  4. *Unknown / Missing Information*
- **Offline Fallback Engine:** Deterministic grounded CTI evaluation when no API key is provided.

---

## 🚀 Local Development & Reproduction

### Prerequisites
- Node.js 22+
- npm

### 1. Installation
```bash
npm install
```

### 2. Start Development Server
```bash
npm run dev
```
Navigate to `http://localhost:3000`.

### 3. Execute Automated Tests (Vitest)
```bash
npm run test
```
Runs 13 test suites covering malformed indicators, scoring edge cases, CDN correlation, prompt injection defense, and STIX 2.1 validation.

### 4. Run CTI Feed Quality Audit
```bash
npm run validate:feed
```
Validates schema conformity, detects duplicates and malformed IOCs, and writes `reports/feed_quality_report.json`.

### 5. Production Build
```bash
npm run build
```

---

## 🌐 Deploying to GitHub Pages

The application is structured as a zero-backend React Single Page Application (SPA), fully compatible with GitHub Pages:

1. **Build the production assets:**
   ```bash
   npm run build
   ```
   This generates static HTML, CSS, JavaScript, feeds, and reports into `dist/`.
2. **Deploy via GitHub Actions:**
   - Under your repository **Settings > Pages**, set **Source** to **GitHub Actions**.
   - The pre-configured `.github/workflows/daily_feed_update.yml` validates feeds, executes tests, and builds the distribution bundle on push and schedule.
3. **Manual Deploy via gh-pages:**
   ```bash
   npx gh-pages -d dist
   ```

---

## 🔑 Configuration & API Credentials

| Feature | Key / Credential | Required? | Description |
| :--- | :--- | :--- | :--- |
| **Live DNS Resolution** | None (Cloudflare/Google DoH) | **No** (100% Free) | In-browser DNS queries require zero credentials. |
| **Evidence Links** | Public Web URLs | **No** (100% Free) | Pre-computed pivot links to crt.sh, VirusTotal, urlscan, PyPI, and npm. |
| **Gemini AI Triage** | Google AI Studio Key | **Optional** | Free tier at [aistudio.google.com/apikey](https://aistudio.google.com/apikey). If omitted, the platform uses its built-in grounded CTI engine. Keys remain in local browser storage only. |
| **Backend Feed Sync** | URLSCAN / VT / Shodan | **Optional** | Only used for optional external backend sync scripts in `.env.example`. |

---

## ⚠️ Analytical Caveats & Limitations

- **Shared Infrastructure:** Indicators sharing an IP or ASN hosted behind Cloudflare, AWS CloudFront, or Fastly are explicitly tagged as `possible_association_shared_infra` with caution banners. Shared CDNs do not prove common threat actor control.
- **Passive Telemetry:** In-browser OSINT queries do not probe or detonate untrusted servers directly to avoid notifying adversaries.
- **Manual Review:** Indicators with conflicting signals (e.g., established domain age with unverified phishing report) are flagged with `REVIEW REQUIRED` rather than silently rejected or artificially boosted.

---

## ⚖️ License
Released under the [MIT License](LICENSE). Indicators shared under [TLP:CLEAR](https://www.first.org/tlp/).
