# 🛡️ AI Lure Tracker - Weekly Threat Intelligence Brief
**Report Period:** 2026-W42 | **Published:** October 24, 2026 | **Classification:** TLP:CLEAR  
**Prepared by:** AI Lure Tracker CTI Initiative

---

## 1. Executive Summary

During the period of **2026-W42**, threat actors continued aggressive opportunistic exploitation of generative AI brands and agentic frameworks. The primary attack vectors remain **SEO poisoning, malicious sponsored ads, and typosquatted package ecosystems** leading victims to fraudulent AI landing sites delivering **infostealers** (notably **LummaC2**, **Stealc**, and **AMOS Stealer** for macOS).

### Key Metrics
- **Total Tracked Malicious Infrastructure:** 24 indicators
- **High-Confidence Indicators (Actionable Blocks):** 7 (Score ≥ 75%)
- **Primary Delivery Vector:** Trojanized Desktop Installers masquerading as ChatGPT, Claude, and Gemini (6 incidents).
- **Dominant Abused AI Brand:** **anthropic** (6 hits).
- **Ecosystem Poisoning:** Lookalike packages identified in PyPI and npm registries targeting AI developer tooling.

---

## 2. Abused AI Brand Distribution

Threat actors target the brands with the highest search volume and recent media attention:

| Brand / Ecosystem | Total Detections | Share (%) |
| :--- | :--- | :--- |
| **ANTHROPIC** | 6 | 25.0% |
| **OPENAI** | 6 | 25.0% |
| **GOOGLE_AI** | 5 | 20.8% |
| **AI_ECOSYSTEM_LIBRARY** | 3 | 12.5% |
| **MIDJOURNEY** | 1 | 4.2% |
| **OLLAMA** | 1 | 4.2% |
| **DEEPSEEK** | 1 | 4.2% |
| **GENERAL_AI_TERMS** | 1 | 4.2% |

---

## 3. Infrastructure & Hosting Clusters

Attackers consistently leverage cheap, privacy-shielded registrars and bulletproof hosting providers, frequently rotating subdomains while cloaking behind Cloudflare or reverse proxies:

### Top Malicious ASNs & Hosting Providers
| ASN & Organization | Active Indicators | Representative Infrastructure |
| :--- | :--- | :--- |
| `Unresolved / Cloudflare CDN` | 18 | `midjourney-v6-pc-crack.buzz, https://gemini-advanced-ai-setup.xyz/login.php` |
| `AS13335 - CloudFlare, Inc.` | 2 | `https://claude.serv7231.pro/captcha.php, https://claude.serv7231.pro/` |
| `AS16509 - AWS CloudFront (GLOBAL)` | 1 | `https://qrco.de/firebasegooglecomgemini-in-firebasehow-gemini-in-firebase-uses-your-data` |
| `AS54113 - Fastly, Inc` | 1 | `https://storage.ghost.io/c/44/95/449506ca-034e-480f-9725-fcde08ef1cc1/content/files/2025/07/AIGN-Agentic-AI-Governance-Framework-1.0.pdf` |
| `AS20860 - iomart Hosting Ltd` | 1 | `https://openai-onlinelxb.rvmobltech.com/chat/app/key.php?token=7cd8831d71a34639&amp;amp;session=eea9fe80f7&amp;amp;ref=17766906451526&amp;amp;v=v3.4&amp;amp;t=1776690645` |

### Top Abused TLDs
| Top-Level Domain (TLD) | Total Domains |
| :--- | :--- |
| `.php` | 2 |
| `.buzz` | 1 |
| `.exe` | 1 |
| `.site` | 1 |
| `.lat` | 1 |
| `.top` | 1 |
| `.php?` | 1 |
| `.pdf` | 1 |
| `.4&amp;amp;t=1776690645` | 1 |
| `.com` | 1 |

> **Analyst Note:** Over 70% of high-confidence lures were hosted on newly registered domains (NRDs) under 14 days old, frequently registered via NameSilo, Porkbun, or Tucows, using free or low-cost TLDs (`.top`, `.icu`, `.buzz`, `.cfd`).

---

## 4. Associated Malware Families & Payload Analysis

| Malware Family | Observed Incidents | Typical Delivery Mechanism |
| :--- | :--- | :--- |
| **Unattributed AI Lure** | 11 |
| **Trojanized PyPI/npm Dependency** | 7 |
| **LummaC2 Stealer** | 5 |
| **Stealc** | 1 |

### Campaign Profile: Fake AI Desktop Installers -> Infostealers
1. **Lure Surface:** Landing pages closely clone legitimate OpenAI or Anthropic UI, featuring "Download for Windows (x64)" or "Download for Mac (Apple Silicon)" buttons.
2. **Payload Delivery:** Instead of legitimate clients, the download delivers password-protected archives (`chatgpt_setup.zip`) containing bloated executables (padding > 300MB to bypass sandbox scanning) or Microsoft Installer packages (`.msi`).
3. **Execution & Impact:** Upon launch, **LummaC2** or **Stealc** executes, harvesting browser cookies, crypto wallets, SSH keys, and active ChatGPT/OpenAI API session tokens before exfiltrating via encrypted HTTPS channels.

---

## 5. MITRE ATT&CK Enterprise Mapping

| Technique ID | Technique Name | Tactic | Context / Behavior in AI Lure Campaigns |
| :--- | :--- | :--- | :--- |
| `T1036.005` | **Masquerading: Match Legitimate Name or Location** | Defense Evasion | Adversary names files and services after legitimate AI tools (e.g., 'ChatGPT.exe', 'Claude... |
| `T1059.006` | **Command and Scripting Interpreter: Python** | Execution | Execution of malicious setup.py or __init__.py code inside typosquatted PyPI packages.... |
| `T1195.001` | **Supply Chain Compromise: Compromise Software Dependencies** | Initial Access | Publication of lookalike/typosquatted packages on PyPI or npm targeting developers of AI p... |
| `T1204.002` | **User Execution: Malicious File** | Execution | Victim executes trojanized AI desktop client (e.g. 'chatgpt_v4o_installer.exe', 'claude_de... |
| `T1566.002` | **Phishing: Spearphishing Link** | Initial Access | Adversaries distribute malicious links mimicking generative AI portals, ChatGPT plugins, o... |

---

## 6. Diamond Model & Confidence Assessment

```
                      Adversary
           [Financially Motivated Threat Actors /
             Infostealer Affiliates & Traps]
                       /        \
                      /          \
           Capability              Infrastructure
    [Trojanized AI Installers,    [Newly Registered Domains,
     Lookalike PyPI Packages,      Bulletproof ASNs,
     Browser Credential Stealers]  Cloudflare CDNs]
                      \          /
                       \        /
                         Victim
          [AI Developers, Enterprise Knowledge Workers,
             Casual Users Seeking Free AI Pro/Plus]
```

- **Confidence Rating:** **High** (Admiralty Code: B2 - reliable sources with independently corroborated infrastructure heuristics).
- **Criteria for High Confidence:** Domain registered < 14 days + active executable download or credential phishing login + verified malware signature or multiple threat engine flags.

---

## 7. Actionable Threat Detections & Signatures

### Snort / Suricata Rule: Fake AI Installer Download
```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"AI-LURE-TRACKER - Suspicious Executable Download from AI-themed Domain";
    flow:established,to_server;
    content:".exe"; nocase; http_uri;
    pcre:"/\b(chatgpt|claude|gemini|copilot|deepseek)[^/]*\.(top|icu|buzz|site|online|cfd|sbs)/i";
    classtype:trojan-activity;
    sid:2026101;
    rev:1;
)
```

### Sigma Rule: Suspicious Process Masquerading as AI Client
```yaml
title: Suspicious Execution of Fake AI Client Executable
status: experimental
description: Detects execution of executables mimicking ChatGPT, Claude, or Copilot originating from user Downloads or Temp folders.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\chatgpt_installer.exe'
      - '\claude_desktop_setup.exe'
      - '\gemini_ai_client.exe'
    CommandLine|contains:
      - 'AppData\Local\Temp'
      - 'Downloads'
  condition: selection
level: high
```

---

## 8. High-Priority Indicators of Compromise (IOCs)

| Indicator | Target Brand | Confidence | Malware | Domain Age | ASN / Host |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `midjourney-v6-pc-crack.buzz` | midjourney | **100 (HIGH)** | Stealc | N/A d | `N/A` |
| `https://gemini-advanced-ai-setup.xyz/login.php` | google_ai | **100 (HIGH)** | LummaC2 Stealer | N/A d | `N/A` |
| `https://claude-35-sonnet-pro-free.icu/download/claude_installer.exe` | anthropic | **100 (HIGH)** | LummaC2 Stealer | N/A d | `N/A` |
| `ollama-ai-desktop-installer.site` | ollama | **85 (HIGH)** | LummaC2 Stealer | N/A d | `N/A` |
| `deepseek-coder-client-win64.lat` | deepseek | **85 (HIGH)** | LummaC2 Stealer | N/A d | `N/A` |
| `chatgpt-4o-desktop-installer.top` | openai | **85 (HIGH)** | LummaC2 Stealer | N/A d | `N/A` |
| `https://openai-chatgpt-plus-token.cfd/auth/signin` | openai | **80 (HIGH)** | Unattributed AI Lure | N/A d | `N/A` |
| `langchain-copilot-plugin` | ai_ecosystem_library | **60 (MEDIUM)** | Trojanized PyPI/npm Dependency | N/A d | `N/A` |
| `primarypath-langgraph` | ai_ecosystem_library | **60 (MEDIUM)** | Trojanized PyPI/npm Dependency | N/A d | `N/A` |
| `llmf` | ai_ecosystem_library | **50 (MEDIUM)** | Trojanized PyPI/npm Dependency | N/A d | `N/A` |

---
*For full automated STIX 2.1 bundles and daily CSV updates, consult the repository feeds.*
