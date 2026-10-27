import { EnrichedIndicator } from '../types/threat';
import { defang } from './defang';

export function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function generateCsvFeed(indicators: EnrichedIndicator[]): string {
  const headers = [
    'id',
    'indicator_defanged',
    'indicator_raw',
    'type',
    'verdict',
    'verdict_rule_matched',
    'target_brand',
    'lure_type',
    'confidence_score',
    'associated_malware',
    'malware_attribution_source',
    'source',
    'source_url',
    'status',
    'first_seen',
    'last_checked',
    'domain_age_days',
    'registrar',
    'asn',
    'asn_org',
    'resolved_ips',
    'has_download',
    'has_login',
    'vt_detections',
    'mitre_techniques',
    'tlp'
  ];

  const rows = indicators.map(i => {
    const fields = [
      i.id,
      `"${defang(i.value)}"`,
      `"${i.value}"`,
      i.indicator_type,
      i.verdict || (i.confidence_score >= 75 ? 'Confirmed Malicious' : 'Suspected'),
      `"${(i.verdict_rule_matched || '').replace(/"/g, '""')}"`,
      i.target_brand,
      i.lure_type,
      i.confidence_score,
      `"${(i.associated_malware || 'Unknown').replace(/"/g, '""')}"`,
      `"${(i.malware_attribution_source || 'Unverified').replace(/"/g, '""')}"`,
      i.source,
      `"${(i.source_url || '').replace(/"/g, '""')}"`,
      i.status || 'Active',
      i.first_seen,
      i.last_checked || i.first_seen,
      i.enrichment?.domain_age_days ?? '',
      i.enrichment?.registrar ? `"${i.enrichment.registrar.replace(/"/g, '""')}"` : '',
      i.enrichment?.asn || '',
      i.enrichment?.asn_org ? `"${i.enrichment.asn_org.replace(/"/g, '""')}"` : '',
      i.enrichment?.resolved_ips?.join(';') || '',
      i.enrichment?.has_download_link ? 'True' : 'False',
      i.enrichment?.has_login_form ? 'True' : 'False',
      i.enrichment?.virustotal_detections ?? 0,
      i.mitre_attack?.join(';') || '',
      i.tlp || 'TLP:CLEAR'
    ];
    return fields.join(',');
  });

  return [headers.join(','), ...rows].join('\n');
}

export function generatePlainBlocklist(
  indicators: EnrichedIndicator[], 
  options: { defanged: boolean; confirmedOnly: boolean }
): string {
  let list = indicators;
  if (options.confirmedOnly) {
    list = list.filter(i => (i.verdict === 'Confirmed Malicious' || i.confidence_score >= 75));
  }

  const lines = [
    `# AI Lure Tracker CTI Blocklist`,
    `# Exported: ${new Date().toISOString()}`,
    `# Filter: ${options.confirmedOnly ? 'Confirmed Malicious Only' : 'All Tracked Indicators'}`,
    `# Format: ${options.defanged ? 'Defanged (safe for ticket/docs)' : 'Raw (for firewall / DNS filter)'}`,
    `# Total count: ${list.length}`,
    `# TLP:CLEAR`,
    ''
  ];

  list.forEach(i => {
    const val = options.defanged ? defang(i.value) : i.value;
    lines.push(val);
  });

  return lines.join('\n');
}

export function generateMispJson(indicators: EnrichedIndicator[]) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const event = {
    Event: {
      id: "ai-lure-" + timestamp,
      info: "AI Lure Tracker - Curated Threat Intelligence Event",
      date: new Date().toISOString().split('T')[0],
      threat_level_id: "2",
      analysis: "2",
      distribution: "3", // All communities
      published: true,
      orgc_id: "AI-LURE-CTI",
      Attribute: indicators.map((ind, idx) => {
        let type = 'domain';
        if (ind.indicator_type === 'url') type = 'url';
        else if (ind.indicator_type === 'ip') type = 'ip-dst';
        else if (ind.indicator_type?.includes('package')) type = 'filename';

        return {
          id: `${timestamp}${idx}`,
          type,
          category: 'Network activity',
          to_ids: ind.verdict === 'Confirmed Malicious' || ind.confidence_score >= 75,
          value: ind.value,
          comment: `Target Brand: ${ind.target_brand} | Verdict: ${ind.verdict || 'Suspected'} | Score: ${ind.confidence_score}`,
          timestamp
        };
      })
    }
  };
  return event;
}

export function generateStixBundle(indicators: EnrichedIndicator[]) {
  const identityId = 'identity--c7650f9a-8b1c-4b68-96f3-a3d1d1f05321';
  const nowIso = new Date().toISOString();
  
  const objects: any[] = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: nowIso,
      modified: nowIso,
      name: 'AI Lure Tracker CTI Initiative',
      description: 'Open Cyber Threat Intelligence initiative monitoring infrastructure weaponizing Generative AI brands.',
      identity_class: 'organization',
      sectors: ['technology', 'cybersecurity'],
      contact_information: 'cti@ai-lure-tracker.org'
    }
  ];

  const malwareMap = new Map<string, string>();
  const malwareNames = ['LummaC2 Stealer', 'Stealc', 'AMOS Stealer', 'Vidar', 'Suspected typosquat or lookalike package'];
  
  malwareNames.forEach((name, idx) => {
    const id = `malware--${idx + 1}0000000-0000-0000-0000-000000000000`;
    malwareMap.set(name, id);
    objects.push({
      type: 'malware',
      spec_version: '2.1',
      id,
      created: nowIso,
      modified: nowIso,
      name,
      is_family: true,
      malware_types: ['infostealer', 'trojan']
    });
  });

  indicators.forEach(ind => {
    let pattern = `[domain-name:value = '${ind.value}']`;
    if (ind.indicator_type === 'url') {
      pattern = `[url:value = '${ind.value}']`;
    } else if (ind.indicator_type === 'ip') {
      pattern = `[ipv4-addr:value = '${ind.value}']`;
    } else if (ind.indicator_type?.toString().includes('package')) {
      pattern = `[software:name = '${ind.value}']`;
    }

    const stixIndicatorId = `indicator--${ind.id}`;
    const validFrom = ind.first_seen ? new Date(ind.first_seen).toISOString() : nowIso;

    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: stixIndicatorId,
      created: validFrom,
      modified: ind.last_seen ? new Date(ind.last_seen).toISOString() : validFrom,
      name: `AI Lure: ${defang(ind.value)}`,
      description: `Malicious infrastructure impersonating ${ind.target_brand}. Verdict: ${ind.verdict || 'Suspected'}. Rule: ${ind.verdict_rule_matched || 'Heuristic'}. Confidence: ${ind.confidence_score}/100.`,
      indicator_types: [ind.lure_type === 'credential_phish' ? 'malicious-activity' : 'compromised'],
      pattern,
      pattern_type: 'stix',
      valid_from: validFrom,
      confidence: ind.confidence_score,
      labels: ind.tags || ['ai-lure'],
      created_by_ref: identityId
    });

    if (ind.associated_malware && malwareMap.has(ind.associated_malware)) {
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: `relationship--rel-${ind.id}`,
        created: validFrom,
        modified: validFrom,
        relationship_type: 'indicates',
        source_ref: stixIndicatorId,
        target_ref: malwareMap.get(ind.associated_malware)
      });
    }
  });

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'b82d9a33-6cf0-43ef-b92c-554d31061f01'}`,
    objects
  };
}
