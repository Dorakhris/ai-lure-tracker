import fs from 'fs';
import path from 'path';

// Load public feed
const publicFeedPath = path.resolve('public/feeds/ai_lures_latest.json');
const rootFeedJsonPath = path.resolve('feeds/ai_lures_latest.json');
const publicCsvPath = path.resolve('public/feeds/ai_lures_latest.csv');
const rootCsvPath = path.resolve('feeds/ai_lures_latest.csv');
const publicStixPath = path.resolve('public/feeds/ai_lures_stix21.json');
const rootStixPath = path.resolve('feeds/ai_lures_stix21.json');

const rawData = JSON.parse(fs.readFileSync(publicFeedPath, 'utf8'));

// CTI Scoring Engine logic in Node
const SHARED_CDN_ASNS = new Set(['AS13335', 'AS16509', 'AS54113', 'AS20940', 'AS15169']);
const SUSPICIOUS_TLDS = new Set(['top', 'icu', 'buzz', 'cfd', 'lat', 'site', 'xyz', 'pro', 'click', 'link', 'download']);

function calculateScore(ind) {
  const val = (ind.value || ind.indicator || '').trim().toLowerCase();
  const source = (ind.source || '').toLowerCase();
  const lureType = (ind.lure_type || '').toLowerCase();
  const malware = (ind.associated_malware || '').toLowerCase();
  const enrichment = ind.enrichment || {};

  // 1. Source Reliability (max 30)
  let src = 5;
  if (source.includes('threatfox')) src = 25;
  else if (source.includes('urlhaus')) src = 25;
  else if (source.includes('openphish')) src = 20;
  else if (source.includes('phishtank')) src = 15;
  else if (source.includes('certstream')) src = 10;
  else if (source.includes('pypi') || source.includes('npm')) src = 15;

  // 2. Evidence Quality (max 35)
  let ev = 0;
  if (enrichment.has_download_link) ev += 30;
  else if (val.includes('.exe') || val.includes('.dmg') || val.includes('.msi') || val.includes('installer')) ev += 20;

  if (enrichment.has_login_form) ev += 20;
  else if (val.includes('login') || val.includes('signin') || val.includes('auth') || val.includes('token')) ev += 12;

  if (enrichment.virustotal_detections >= 3) ev += 25;
  else if (enrichment.virustotal_detections > 0) ev += 10;
  ev = Math.min(ev, 35);

  // 3. Corroboration (max 20)
  let sourceCount = 0;
  if (source.includes('threatfox') || source.includes('urlhaus')) sourceCount++;
  if (source.includes('openphish') || source.includes('phishtank')) sourceCount++;
  if (enrichment.virustotal_detections >= 2) sourceCount++;
  if (enrichment.urlscan_id) sourceCount++;

  let corr = sourceCount >= 2 ? 15 : (sourceCount === 1 ? 5 : 0);

  // 4. Behaviour (max 25)
  let beh = 0;
  const brand = (ind.target_brand || '').toLowerCase();
  if (brand && brand !== 'unknown' && brand !== 'generic_ai') beh += 15;

  const tldMatch = val.match(/\.([a-z0-9-]+)(?:\/|$|\?)/);
  if (tldMatch && SUSPICIOUS_TLDS.has(tldMatch[1])) beh += 10;

  if (malware && !malware.includes('unattributed') && !malware.includes('generic')) beh += 10;
  if (lureType.includes('typosquat') || lureType.includes('lookalike')) beh += 15;
  beh = Math.min(beh, 25);

  // 5. Penalties
  let pen = 0;
  if (enrichment.asn && SHARED_CDN_ASNS.has(enrichment.asn)) pen -= 5;
  if (enrichment.domain_age_days !== null && enrichment.domain_age_days > 730 && !enrichment.has_download_link) pen -= 15;

  // 6. Recency
  let rec = 0;
  if (ind.first_seen) {
    const ageDays = (Date.now() - new Date(ind.first_seen).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays <= 3) rec = 10;
    else if (ageDays <= 14) rec = 5;
    else if (ageDays > 60) rec = -10;
  }

  let total = Math.max(5, Math.min(100, Math.round(src + ev + corr + beh + pen + rec)));
  let level = total >= 75 ? 'high' : (total >= 50 ? 'medium' : 'low');

  return { total, level };
}

// Clean uncorroborated malware labels
const reconciled = rawData.map(item => {
  let updated = { ...item };

  // CertStream observables are staging domain observations, not confirmed malware payloads
  if (updated.source === 'CertStream') {
    if (updated.associated_malware && updated.associated_malware.includes('LummaC2')) {
      updated.associated_malware = 'Unattributed AI Lure (Staging Candidate)';
      updated.lure_type = 'suspicious_registration';
      updated.tags = updated.tags.filter(t => !t.includes('lummac2')).concat('staging-candidate');
    }
  }

  // OpenPhish login form should not be labeled LummaC2 Stealer without binary payload
  if (updated.source === 'OpenPhish' && updated.value.includes('login.php')) {
    if (updated.associated_malware && updated.associated_malware.includes('LummaC2')) {
      updated.associated_malware = 'Unattributed AI Lure (Credential Phishing)';
      updated.lure_type = 'credential_phish';
      updated.tags = updated.tags.filter(t => !t.includes('lummac2')).concat('credential-phish');
    }
  }

  // Compute evidence-based confidence score
  const { total, level } = calculateScore(updated);
  updated.confidence_score = total;
  updated.confidence_level = level;

  return updated;
});

// Write reconciled JSON feeds
fs.writeFileSync(publicFeedPath, JSON.stringify(reconciled, null, 2), 'utf8');
fs.writeFileSync(rootFeedJsonPath, JSON.stringify(reconciled, null, 2), 'utf8');

// Generate CSV
const csvHeaders = [
  'id','indicator','type','target_brand','lure_type','confidence_score','confidence_level',
  'associated_malware','source','first_seen','domain_age_days','registrar','asn','asn_org',
  'resolved_ips','country','has_download','has_login','vt_detections','mitre_techniques','tags','tlp'
];
const csvRows = reconciled.map(i => [
  i.id,
  i.value,
  i.indicator_type,
  i.target_brand,
  i.lure_type,
  i.confidence_score,
  i.confidence_level,
  i.associated_malware || 'Unknown',
  i.source,
  i.first_seen,
  i.enrichment?.domain_age_days ?? '',
  i.enrichment?.registrar ? `"${i.enrichment.registrar.replace(/"/g, '""')}"` : '',
  i.enrichment?.asn || '',
  i.enrichment?.asn_org ? `"${i.enrichment.asn_org.replace(/"/g, '""')}"` : '',
  i.enrichment?.resolved_ips?.join(';') || '',
  i.enrichment?.country || '',
  i.enrichment?.has_download_link ? 'True' : 'False',
  i.enrichment?.has_login_form ? 'True' : 'False',
  i.enrichment?.virustotal_detections ?? 0,
  i.mitre_attack?.join(';') || '',
  i.tags?.join(';') || '',
  i.tlp || 'TLP:CLEAR'
].join(','));
const csvContent = [csvHeaders.join(','), ...csvRows].join('\n');
fs.writeFileSync(publicCsvPath, csvContent, 'utf8');
fs.writeFileSync(rootCsvPath, csvContent, 'utf8');

// Generate STIX 2.1
const identityId = 'identity--c7650f9a-8b1c-4b68-96f3-a3d1d1f05321';
const stixObjects = [
  {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: '2026-10-24T12:00:00.000Z',
    modified: '2026-10-24T12:00:00.000Z',
    name: 'AI Lure Tracker CTI Initiative',
    description: 'Open Cyber Threat Intelligence initiative monitoring infrastructure weaponizing Generative AI brands.',
    identity_class: 'organization',
    sectors: ['technology', 'cybersecurity'],
    contact_information: 'cti@ai-lure-tracker.org'
  }
];

const malwareFamilies = ['LummaC2 Stealer', 'Stealc', 'AMOS Stealer', 'Vidar', 'Trojanized PyPI/npm Dependency'];
const malwareMap = new Map();
malwareFamilies.forEach((name, idx) => {
  const mid = `malware--${idx + 1}0000000-0000-0000-0000-000000000000`;
  malwareMap.set(name, mid);
  stixObjects.push({
    type: 'malware',
    spec_version: '2.1',
    id: mid,
    created: '2026-10-24T12:00:00.000Z',
    modified: '2026-10-24T12:00:00.000Z',
    name,
    is_family: true,
    malware_types: ['infostealer', 'trojan']
  });
});

reconciled.forEach(ind => {
  let pattern = `[domain-name:value = '${ind.value}']`;
  if (ind.indicator_type === 'url') pattern = `[url:value = '${ind.value}']`;
  else if (ind.indicator_type === 'ip') pattern = `[ipv4-addr:value = '${ind.value}']`;
  else if (ind.indicator_type?.includes('package')) pattern = `[software:name = '${ind.value}']`;

  const iid = `indicator--${ind.id}`;
  stixObjects.push({
    type: 'indicator',
    spec_version: '2.1',
    id: iid,
    created: ind.first_seen,
    modified: ind.last_seen || ind.first_seen,
    name: `AI Lure: ${ind.value}`,
    description: `Malicious infrastructure impersonating ${ind.target_brand}. Type: ${ind.lure_type}. Confidence: ${ind.confidence_score}/100.`,
    indicator_types: [ind.lure_type === 'credential_phish' ? 'malicious-activity' : 'compromised'],
    pattern,
    pattern_type: 'stix',
    valid_from: ind.first_seen,
    confidence: ind.confidence_score,
    labels: ind.tags || ['ai-lure'],
    created_by_ref: identityId
  });

  if (ind.associated_malware && malwareMap.has(ind.associated_malware)) {
    stixObjects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--${ind.id}`,
      created: ind.first_seen,
      modified: ind.last_seen || ind.first_seen,
      relationship_type: 'indicates',
      source_ref: iid,
      target_ref: malwareMap.get(ind.associated_malware)
    });
  }
});

const stixBundle = {
  type: 'bundle',
  id: `bundle--${crypto.randomUUID()}`,
  objects: stixObjects
};
fs.writeFileSync(publicStixPath, JSON.stringify(stixBundle, null, 2), 'utf8');
fs.writeFileSync(rootStixPath, JSON.stringify(stixBundle, null, 2), 'utf8');

console.log(`[+] Reconciled ${reconciled.length} indicators across JSON, CSV, and STIX 2.1 feeds.`);
