# 🛡️ AI Lure Tracker: Malicious Infrastructure Intelligence Feed

[![Threat Intelligence](https://img.shields.io/badge/CTI-Threat%20Intelligence-blue.svg)](https://github.com/ai-lure-tracker)
[![STIX 2.1](https://img.shields.io/badge/Format-STIX%202.1-orange.svg)](https://oasis-open.github.io/cti-documentation/)
[![MITRE ATT&CK](https://img.shields.io/badge/Matrix-Enterprise%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

> **A real-world Cyber Threat Intelligence (CTI) engine that ingests, filters, enriches, and publishes a live feed of malicious infrastructure and supply-chain packages exploiting AI brands (ChatGPT, Claude, Gemini, Copilot, DeepSeek, Ollama, LangChain, etc.) as bait.**

---

## 🎯 Threat Landscape & Motivation

Attackers aggressively capitalize on market hype. Right now, this centers on generative AI and autonomous agent frameworks:
1. **Fake Desktop Installers:** Threat actors set up lookalike domains offering "ChatGPT Desktop", "Claude Sonnet Mac Setup", or "Midjourney PC Edition" that deliver information stealers (**LummaC2**, **Stealc**, **Vidar**, **Rhadamanthys**, and **AMOS Stealer** for macOS).
2. **Credential Phishing & Token Traps:** Deceptive portals offering "Free GPT-4o Plus Access" or "Unlimited Claude Pro" designed to harvest corporate credentials or compromise active AI session tokens.
3. **Package Supply Chain Typosquatting:** Rogue packages published on **PyPI** and **npm** with names adjacent to popular AI libraries (e.g. `langchain`, `openai`, `transformers`, `chromadb`) delivering malicious `setup.py` payloads, reverse shells, and cryptominers.

**AI Lure Tracker** is an end-to-end CTI platform that continuously monitors, filters, enriches, scores, stores, and distributes indicators of compromise (IOCs) across public feeds, STIX 2.1 bundles, and local CTI instances (MISP / OpenCTI).

---

## 🏗️ Architecture & Processing Pipeline

```
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   1. COLLECTION PHASE                                  │
 └──────┬──────────────────────┬──────────────────────┬──────────────────────┬────────────┘
        │                      │                      │                      │
 ┌──────▼───────┐       ┌──────▼───────┐       ┌──────▼───────┐       ┌──────▼───────────┐
 │   Abuse.ch   │       │  PhishTank   │       │  CertStream  │       │ Package Watchers │
 │  - URLhaus   │       │  & OpenPhish │       │ (CT Logs &   │       │   - PyPI RSS     │
 │  - ThreatFox │       │ (Active URLs)│       │   crt.sh)    │       │   - npm Changes  │
 │  - M.Bazaar  │       └──────┬───────┘       └──────┬───────┘       └──────┬───────────┘
 └──────┬───────┘              │                      │                      │
        └──────────────────────┼──────────────────────┴──────────────────────┘
                               │ Raw Candidates
 ┌─────────────────────────────▼──────────────────────────────────────────────────────────┐
 │                                    2. FILTERING PHASE                                  │
 │ - AI Brand Keyword Matcher (ChatGPT, Claude, Gemini, Copilot, DeepSeek, Ollama, etc.)  │
 │ - Typosquatting & Edit Distance (Damerau-Levenshtein <= 2 on libraries & domains)      │
 │ - Punycode / IDN Homoglyph Normalization                                              │
 │ - False Positive Suppression Whitelist (openai.com, claude.ai, google.com, CDNs)      │
 └─────────────────────────────┬──────────────────────────────────────────────────────────┘
                               │ Matched Candidates
 ┌─────────────────────────────▼──────────────────────────────────────────────────────────┐
 │                                  3. ENRICHMENT PHASE                                   │
 │ - DNS & ASN Resolution (ip-api / Cymru): Resolved IPs, ASN, ISP, Hosting Provider      │
 │ - WHOIS & RDAP: Registration timestamp, registrar name, domain age calculation (days)  │
 │ - urlscan.io Integration: Automated page analysis, screenshots, download/login lures   │
 │ - VirusTotal v3 API: Malicious engine detection ratios & threat categories             │
 │ - Shodan API: Open ports, exposed services, banners                                    │
 │ - Heuristic Scorer: High-confidence rating (Domain age < 14d + download link/login)   │
 └─────────────────────────────┬──────────────────────────────────────────────────────────┘
                               │ Enriched Indicators
 ┌─────────────────────────────▼──────────────────────────────────────────────────────────┐
 │                                4. STORAGE & DISTRIBUTION                               │
 ├─────────────────────────────┬──────────────────────────────┬───────────────────────────┤
 │     SQLite Threat DB        │    Public Feed Exporters     │  Local CTI Deployments    │
 │ (Deduplication, State,      │  - feeds/ai_lures_latest.csv │  - MISP (PyMISP / REST)   │
 │  First/Last Seen tracking)  │  - feeds/ai_lures_latest.json│  - OpenCTI (STIX / GraphQL│
 │                             │  - feeds/ai_lures_stix21.json│    via Docker Compose)    │
 └─────────────────────────────┴──────────────┬───────────────┴───────────────────────────┘
                                              │
 ┌────────────────────────────────────────────▼───────────────────────────────────────────┐
 │                          5. REPORTING & MITRE ATT&CK MAPPING                           │
 │ - Weekly Threat Intelligence Brief (Markdown & HTML)                                   │
 │ - Infrastructure Clustering (Top ASNs, Registrars, TLDs, Malware Families)             │
 │ - ATT&CK Matrix Alignment (Initial Access -> Execution -> Credential Access -> C2)     │
 │ - Actionable Detection Artifacts (Snort/Suricata, Sigma, and YARA rules)               │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.10+ (or [uv](https://github.com/astral-sh/uv))
- Docker & Docker Compose (optional, for local MISP/OpenCTI)

### 1. Installation
```powershell
# Clone the repository
git clone https://github.com/ai-lure-tracker/ai-lure-tracker.git
cd ai-lure-tracker

# Create virtual environment and install dependencies
uv venv
uv pip install -r pyproject.toml
```

### 2. Configure Environment (Optional API Keys)
Copy `.env.example` to `.env` and provide your free-tier API keys for enhanced enrichment:
```bash
cp .env.example .env
```
Key configuration parameters:
- `URLSCAN_API_KEY`: For scanning new lures on urlscan.io.
- `VIRUSTOTAL_API_KEY`: For VT v3 engine detection ratios.
- `SHODAN_API_KEY`: For exposed service lookups.
- `OPENCTI_ENABLE=true` / `MISP_ENABLE=true`: Enables direct syncing to local instances.

### 3. Run the End-to-End Pipeline
Execute collection, filtering, enrichment, feed publishing, and report generation in one command:
```powershell
python -m src.cli run-pipeline
```

### 4. Monitor Live Certificate Transparency Streams
Watch live SSL/TLS certificate issuances matching AI brand keywords in real-time via CertStream:
```powershell
python -m src.cli certstream-live
```

---

## 📊 Confidence Scoring & CTI Heuristic

The engine scores every candidate between **0 and 100** using corroborated empirical signals:

| Signal / Heuristic | Score Impact | Rationale |
| :--- | :--- | :--- |
| **Base Score** | `+40` | Initial baseline for matching verified AI brand lure. |
| **Domain Age ≤ 7 days** | `+25` | Newly Registered Domains (NRDs) represent prime throwaway infrastructure. |
| **Domain Age ≤ 14 days** | `+15` | High-risk window before takedowns or security classification. |
| **Suspicious TLD** (`.top`, `.icu`, `.buzz`, `.cfd`, `.lat`, `.xyz`) | `+15` | Common cheap/bulletproof TLDs favored by infostealer distributors. |
| **Executable Download Lure** (`.exe`, `.msi`, `.dmg`, `.zip`, `.iso`) | `+30` | Direct payload delivery mechanism for infostealer infections. |
| **Credential Phishing Form** (`login`, `signin`, `auth`, `portal`) | `+25` | Harvests user accounts or OAuth session tokens. |
| **Threat Feed Confirmation** (abuse.ch / VT ≥ 2) | `+30` | Multi-source corroboration from community sensors. |
| **Package Typosquat** (Levenshtein distance = 1) | `+35` | Intentional dependency confusion / supply-chain attack. |

### Confidence Tiers:
- 🔴 **HIGH (Score ≥ 75):** Immediate blocking recommended. High certainty of malicious infrastructure.
- 🟡 **MEDIUM (Score 50-74):** Suspicious infrastructure; enforce proxy sandboxing and alerting.
- ⚪ **LOW (Score < 50):** Potential false positive or parked domain; monitor for weaponization.

---

## 📦 Feed Schema & Output Artifacts

The system continuously outputs standard threat sharing formats into `feeds/`:

### 1. STIX 2.1 Bundle (`feeds/ai_lures_stix21.json`)
OASIS STIX 2.1 compliant containing:
- `identity`: AI Lure Tracker CTI Initiative.
- `indicator`: Typed pattern (e.g., `[domain-name:value = 'chatgpt-desktop-installer.top']`), confidence score, and labels.
- `malware`: Associated families (**LummaC2**, **Stealc**, **AMOS**, **Vidar**).
- `attack-pattern`: MITRE ATT&CK technique IDs with official references.
- `relationship`: `indicates` relationships correlating indicators to malware and TTPs.

### 2. Clean CSV Feed (`feeds/ai_lures_latest.csv`)
Columns:
`id`, `indicator`, `type`, `target_brand`, `lure_type`, `confidence_score`, `confidence_level`, `associated_malware`, `source`, `first_seen`, `domain_age_days`, `registrar`, `asn`, `asn_org`, `resolved_ips`, `country`, `has_download`, `has_login`, `vt_detections`, `mitre_techniques`, `tags`, `tlp`

### 3. Rich JSON Feed (`feeds/ai_lures_latest.json`)
Structured JSON array suitable for SOAR playbooks, Splunk, Elastic, and Microsoft Sentinel ingestion.

---

## 🐳 Local CTI Stack (MISP & OpenCTI via Docker)

AI Lure Tracker includes complete Docker Compose setups for hosting local CTI platforms.

### To start MISP:
```powershell
docker compose --profile misp up -d
```
Access MISP at `https://localhost:8443` (Default Admin: `admin@admin.test` / `admin`).

### To start OpenCTI:
```powershell
docker compose --profile opencti up -d
```
Access OpenCTI at `http://localhost:8080` (Default Admin: `admin@opencti.io` / `admin_password_123`).

To sync indicators directly to your local instances, set `MISP_ENABLE=true` and `OPENCTI_ENABLE=true` in `.env`.

---

## 📑 Automated Weekly Intelligence Brief

The platform automatically produces an executive threat intelligence brief in both **Markdown** (`reports/weekly_brief_YYYY-WW.md`) and **Dark-Mode HTML** (`reports/weekly_brief_YYYY-WW.html`), featuring:
- **Executive Summary & Key Threat Metrics**
- **Abused Brand Distribution** (ChatGPT vs. Claude vs. Gemini vs. Copilot)
- **Infrastructure Clusters** (Top ASNs, Registrars, Bulletproof Hosting, NRD analysis)
- **Malware Family Correlation** (Fake Installers delivering LummaC2, Stealc, AMOS)
- **MITRE ATT&CK Matrix Alignment** (T1566.002, T1204.002, T1036.005, T1195.001)
- **Diamond Model of Intrusion Analysis & Admiralty Code**
- **Actionable Detection Artifacts** (Snort/Suricata, Sigma, YARA).

---

## 🤖 Automated Daily GitHub Actions Workflow

A pre-configured GitHub Actions workflow (`.github/workflows/daily_feed_update.yml`) runs daily at `02:00 UTC` to:
1. Pull fresh data from URLhaus, ThreatFox, MalwareBazaar, OpenPhish, PhishTank, CertStream, PyPI, and npm.
2. Filter and enrich newly observed indicators.
3. Commit updated `ai_lures_latest.csv`, `ai_lures_latest.json`, and `ai_lures_stix21.json` directly to the repository.
4. Publish weekly briefs.

---

## 🧪 Testing

Run the full pytest suite:
```powershell
pytest -v
```

---

## ⚖️ License
Released under the [MIT License](LICENSE). Data and indicators shared under [TLP:CLEAR](https://www.first.org/tlp/).
