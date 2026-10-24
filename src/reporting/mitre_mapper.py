"""
AI Lure Tracker - MITRE ATT&CK Mapping
Maps AI lure campaigns and malicious infrastructure to the MITRE ATT&CK Enterprise Matrix.
"""

from typing import Dict, List, Any
import json

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries distribute malicious links mimicking generative AI portals, ChatGPT plugins, or Claude web apps to deliver payloads or phish credentials."
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Users visiting deceptive AI sites are redirected or prompted to download trojanized setup bundles."
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Victim executes trojanized AI desktop client (e.g. 'chatgpt_v4o_installer.exe', 'claude_desktop.dmg')."
    },
    "T1059.006": {
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "description": "Execution of malicious setup.py or __init__.py code inside typosquatted PyPI packages."
    },
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": "Adversary names files and services after legitimate AI tools (e.g., 'ChatGPT.exe', 'ClaudeHelper.exe', 'OllamaService')."
    },
    "T1555.003": {
        "name": "Credentials from Password Stores: Credentials from Web Browsers",
        "tactic": "Credential Access",
        "description": "Info-stealers (LummaC2, Stealc, Vidar) extract stored passwords, autofill tokens, and master keys from browsers."
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "description": "Adversaries extract active session cookies from Chromium and Firefox profiles to hijack authenticated AI sessions."
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "C2 communication conducted over HTTPS to bulletproof servers or Telegram Bot API channels."
    },
    "T1567.002": {
        "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "description": "Stolen credentials and browser vaults exfiltrated to Discord webhooks, Telegram, or attacker-controlled C2 buckets."
    },
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Adversary registers lookalike domains (e.g. 'chatgpt-pro-ai.top', 'claude-desktop.icu') using high-abuse registrars."
    },
    "T1195.001": {
        "name": "Supply Chain Compromise: Compromise Software Dependencies",
        "tactic": "Initial Access",
        "description": "Publication of lookalike/typosquatted packages on PyPI or npm targeting developers of AI pipelines."
    }
}


class MitreMapper:
    @staticmethod
    def get_technique_details(technique_id: str) -> Dict[str, str]:
        return MITRE_TECHNIQUES.get(technique_id, {
            "name": "Unknown Technique",
            "tactic": "Unknown Tactic",
            "description": "Technique not indexed."
        })

    @staticmethod
    def generate_navigator_layer(techniques: List[str], layer_name: str = "AI Lure Tracker Campaign Layer") -> Dict[str, Any]:
        """
        Generates a MITRE ATT&CK Navigator Layer v4.3 JSON.
        """
        layer_techs = []
        for tech in set(techniques):
            layer_techs.append({
                "techniqueID": tech,
                "score": 100,
                "color": "#e02424",
                "comment": "Observed in active AI lure campaigns",
                "enabled": True
            })

        return {
            "name": layer_name,
            "versions": {
                "attack": "15",
                "navigator": "4.8.1",
                "layer": "4.3"
            },
            "domain": "enterprise-attack",
            "description": "MITRE ATT&CK coverage for AI Lure Tracker campaigns",
            "techniques": layer_techs,
            "gradient": {
                "colors": ["#ff6666", "#e02424"],
                "minValue": 0,
                "maxValue": 100
            }
        }
