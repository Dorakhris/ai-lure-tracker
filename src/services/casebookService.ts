import { InvestigationCase, EnrichedIndicator } from '../types/threat';

const CASEBOOK_STORAGE_KEY = 'AI_LURE_CASEBOOK_V1';

const INITIAL_CASES: InvestigationCase[] = [
  {
    id: 'CASE-2026-001',
    title: 'Coordinated Lookalike AI Packages in PyPI/npm Repositories',
    investigationQuestion: 'Are the primarypath-* and langchain lookalike packages published on PyPI/npm part of an automated dependency confusion campaign?',
    status: 'in_progress',
    priority: 'high',
    createdAt: '2026-10-24T12:00:00.000Z',
    updatedAt: '2026-10-24T12:30:00.000Z',
    leadAnalyst: 'CTI Lead Investigator',
    indicatorIds: [
      '89083119-0ef2-43a1-ac78-f0d8ddf5de55', // langchain-copilot-plugin
      '2c7adad6-ce8d-4192-bb98-8a258b888e9f', // primarypath-langgraph
      '63c1ced5-c02c-4d18-90d4-0b97b3ad2bfe', // primarypath-claude-agent
      '7d19d502-5a47-4537-ab0b-56441cffe94a', // primarypath-openai-agents
    ],
    hypotheses: [
      {
        id: 'hyp-1',
        statement: 'A single threat actor is programmatically publishing packages targeting developer typosquatting.',
        status: 'supported',
        supportingEvidence: 'Shared namespace prefix "primarypath-" across multiple AI targets (Claude, OpenAI, LangGraph) published within identical 3-second time window.',
        alternativeExplanation: 'Benign research scanner or authorized enterprise package namespace reservation.'
      }
    ],
    alternativeExplanations: [
      'Security researchers conducting academic dependency confusion measurements.',
      'Internal enterprise testing of namespace reservations without malicious code execution.'
    ],
    evidenceNotes: [
      {
        id: 'note-1',
        timestamp: '2026-10-24T12:05:00.000Z',
        title: 'Namespace Prefix Overlap Analysis',
        content: 'Package registry feeds show primarypath-claude-agent and primarypath-openai-agents were pushed simultaneously with setup.py stubs.',
        author: 'CTI Lead Investigator',
        tags: ['pypi', 'typosquat', 'evidence']
      }
    ],
    timeline: [
      {
        id: 'time-1',
        timestamp: '2026-10-24T11:48:24.000Z',
        title: 'Initial Package Registration',
        description: 'Primarypath-* packages indexed on PyPI mirrors.',
        indicatorValue: 'primarypath-langgraph'
      },
      {
        id: 'time-2',
        timestamp: '2026-10-24T11:48:27.000Z',
        title: 'LangChain Plugin Alert',
        description: 'ThreatFox and PyPI feeds flagged langchain-copilot-plugin with Levenshtein edit distance 1.',
        indicatorValue: 'langchain-copilot-plugin'
      }
    ],
    findings: [
      'Coordinated publication timing (<5 seconds) strongly indicates scripted automated tooling.',
      'Targeting covers all major frontier AI models (Claude, GPT, LangChain).',
      'Requires package setup.py inspection to identify exfiltration endpoints.'
    ],
    unresolvedQuestions: [
      'What specific callback URLs are embedded in the setup.py execution logic?',
      'Has any developer within the organization accidentally installed these packages?'
    ],
    recommendedActions: [
      'Add primarypath-* and langchain-copilot-* to enterprise artifact repository blocklists (e.g. Artifactory/Nexus).',
      'Scan Git repositories and package-lock files for references to primarypath-* packages.',
      'Report abusive namespace squatting to PyPI and npm security teams for immediate removal.'
    ],
    finalSummary: 'Active dependency confusion investigation targeting AI engineers. Coordinated registration of lookalike libraries masquerading as official agent frameworks.'
  }
];

export function getStoredCases(): InvestigationCase[] {
  try {
    const raw = localStorage.getItem(CASEBOOK_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch (e) {
    console.warn('Failed to load casebook from localStorage:', e);
  }
  return INITIAL_CASES;
}

export function saveCases(cases: InvestigationCase[]) {
  try {
    localStorage.setItem(CASEBOOK_STORAGE_KEY, JSON.stringify(cases));
  } catch (e) {
    console.error('Failed to save cases to localStorage:', e);
  }
}

export function getCaseById(id: string): InvestigationCase | undefined {
  return getStoredCases().find(c => c.id === id);
}

export function updateOrAddCase(caseObj: InvestigationCase): InvestigationCase[] {
  const current = getStoredCases();
  const existingIdx = current.findIndex(c => c.id === caseObj.id);
  let updated: InvestigationCase[];
  
  if (existingIdx >= 0) {
    updated = [...current];
    updated[existingIdx] = { ...caseObj, updatedAt: new Date().toISOString() };
  } else {
    updated = [caseObj, ...current];
  }

  saveCases(updated);
  return updated;
}

export function deleteCase(id: string): InvestigationCase[] {
  const current = getStoredCases();
  const filtered = current.filter(c => c.id !== id);
  saveCases(filtered);
  return filtered;
}

// Markdown Export for Case Dossier
export function exportCaseAsMarkdown(caseObj: InvestigationCase, indicators: EnrichedIndicator[]): string {
  const caseIndicators = indicators.filter(i => caseObj.indicatorIds.includes(i.id));

  return `# 🛡️ CTI Investigation Case Dossier: ${caseObj.title}
**Case ID:** ${caseObj.id} | **Status:** ${caseObj.status.toUpperCase()} | **Priority:** ${caseObj.priority.toUpperCase()}  
**Lead Analyst:** ${caseObj.leadAnalyst}  
**Created:** ${new Date(caseObj.createdAt).toUTCString()} | **Updated:** ${new Date(caseObj.updatedAt).toUTCString()}  

---

## 1. Investigation Question
> ${caseObj.investigationQuestion}

## 2. Executive Summary
${caseObj.finalSummary || 'Investigation ongoing. Telemetry and indicators under active review.'}

## 3. Indicators Under Investigation (${caseIndicators.length})
| Indicator | Type | Brand | Confidence | Attributed Threat | Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
${caseIndicators.map(i => `| \`${i.value}\` | ${i.indicator_type} | ${i.target_brand} | ${i.confidence_score}/100 (${i.confidence_level}) | ${i.associated_malware || 'Unattributed'} | ${i.source} |`).join('\n')}

## 4. Hypotheses & Evidence Analysis
${caseObj.hypotheses.map(h => `
### Hypothesis: ${h.statement}
- **Status:** ${h.status.toUpperCase()}
- **Supporting Evidence:** ${h.supportingEvidence}
- **Alternative Explanation:** ${h.alternativeExplanation || 'None documented'}
`).join('\n')}

## 5. Alternative Explanations Considered
${caseObj.alternativeExplanations.map(a => `- ${a}`).join('\n')}

## 6. Findings
${caseObj.findings.map(f => `- ${f}`).join('\n')}

## 7. Unresolved Questions & Data Gaps
${caseObj.unresolvedQuestions.map(q => `- ${q}`).join('\n')}

## 8. Recommended Actions
${caseObj.recommendedActions.map(r => `1. ${r}`).join('\n')}

## 9. Investigation Timeline
| Timestamp | Event | Observable | Description |
| :--- | :--- | :--- | :--- |
${caseObj.timeline.map(t => `| ${new Date(t.timestamp).toUTCString()} | ${t.title} | \`${t.indicatorValue || 'N/A'}\` | ${t.description} |`).join('\n')}

---
*Report generated by AI Lure Tracker CTI Platform &bull; TLP:CLEAR*
`;
}

// STIX 2.1 Bundle Generation with strict schema compliance
export function exportCaseAsStix21(caseObj: InvestigationCase, indicators: EnrichedIndicator[]) {
  const caseIndicators = indicators.filter(i => caseObj.indicatorIds.includes(i.id));
  const identityId = 'identity--c7650f9a-8b1c-4b68-96f3-a3d1d1f05321';
  const reportId = `report--${caseObj.id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;

  const objectRefs: string[] = [identityId];

  // STIX Objects array
  const objects: any[] = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: caseObj.createdAt,
      modified: caseObj.updatedAt,
      name: 'AI Lure Tracker CTI Investigation Unit',
      description: 'Specialized cyber threat intelligence unit tracking AI brand weaponization.',
      identity_class: 'organization',
    }
  ];

  // Indicator SDOs
  caseIndicators.forEach(ind => {
    const indicatorId = `indicator--${ind.id}`;
    objectRefs.push(indicatorId);

    let pattern = `[domain-name:value = '${ind.value}']`;
    if (ind.indicator_type === 'url') {
      pattern = `[url:value = '${ind.value}']`;
    } else if (ind.indicator_type === 'ip') {
      pattern = `[ipv4-addr:value = '${ind.value}']`;
    } else if (ind.indicator_type?.toString().includes('package')) {
      pattern = `[software:name = '${ind.value}']`;
    }

    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: ind.first_seen,
      modified: ind.last_seen || ind.first_seen,
      name: `AI Lure: ${ind.value}`,
      description: `Targeting ${ind.target_brand}. Type: ${ind.lure_type}. Score: ${ind.confidence_score}.`,
      indicator_types: [ind.lure_type.includes('phish') ? 'malicious-activity' : 'compromised'],
      pattern,
      pattern_type: 'stix',
      valid_from: ind.first_seen,
      confidence: ind.confidence_score,
      labels: ind.tags || ['ai-lure'],
      created_by_ref: identityId,
    });
  });

  // Report SDO (OASIS STIX 2.1 Specification)
  objects.push({
    type: 'report',
    spec_version: '2.1',
    id: reportId,
    created: caseObj.createdAt,
    modified: caseObj.updatedAt,
    name: `Investigation Report: ${caseObj.title}`,
    description: caseObj.finalSummary || caseObj.investigationQuestion,
    published: caseObj.updatedAt,
    report_types: ['threat-report'],
    object_refs: objectRefs,
    labels: ['threat-intelligence', 'ai-lure', caseObj.priority],
    created_by_ref: identityId,
  });

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'b82d9a33-6cf0-43ef-b92c-554d31061f01'}`,
    objects,
  };
}

// Validate STIX 2.1 Bundle against structural requirements
export function validateStix21Bundle(bundle: any): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!bundle || typeof bundle !== 'object') {
    return { isValid: false, errors: ['Bundle is not a valid JSON object.'] };
  }

  if (bundle.type !== 'bundle') {
    errors.push(`Root type must be 'bundle', found '${bundle.type}'.`);
  }

  if (!bundle.id || !bundle.id.startsWith('bundle--')) {
    errors.push(`Bundle id must start with 'bundle--', found '${bundle.id}'.`);
  }

  if (!Array.isArray(bundle.objects)) {
    errors.push('Bundle objects must be an array.');
    return { isValid: false, errors };
  }

  const ids = new Set<string>();
  bundle.objects.forEach((obj: any, idx: number) => {
    if (!obj.id) {
      errors.push(`Object at index ${idx} is missing an 'id'.`);
    } else {
      if (ids.has(obj.id)) {
        errors.push(`Duplicate STIX ID detected: '${obj.id}'.`);
      }
      ids.add(obj.id);
    }

    if (!obj.type) {
      errors.push(`Object at index ${idx} is missing a 'type'.`);
    }

    if (obj.spec_version !== '2.1') {
      errors.push(`Object '${obj.id}' spec_version must be '2.1', found '${obj.spec_version}'.`);
    }

    if (!obj.created) {
      errors.push(`Object '${obj.id}' is missing required 'created' timestamp.`);
    }

    if (!obj.modified) {
      errors.push(`Object '${obj.id}' is missing required 'modified' timestamp.`);
    }

    if (obj.type === 'indicator' && (!obj.pattern || !obj.pattern_type)) {
      errors.push(`Indicator '${obj.id}' is missing required 'pattern' or 'pattern_type'.`);
    }
  });

  return {
    isValid: errors.length === 0,
    errors,
  };
}
