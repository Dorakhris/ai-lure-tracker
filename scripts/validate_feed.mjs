#!/usr/bin/env node
/**
 * AI Lure Tracker - Automated Threat Intelligence Feed Quality Validator
 * Validates schema conformity, detects duplicates & malformed IOCs, and generates
 * a machine-readable feed_quality_report.json for CI/CD audit trails.
 */

import fs from 'fs';
import path from 'path';

const FEED_PATH = path.resolve('public/feeds/ai_lures_latest.json');
const REPORT_PATH = path.resolve('reports/feed_quality_report.json');

const VALID_INDICATOR_TYPES = new Set([
  'domain', 'url', 'ip', 'package-pypi', 'package-npm', 'hash-md5', 'hash-sha256'
]);

const VALID_SOURCES = new Set([
  'ThreatFox', 'URLhaus', 'OpenPhish', 'PhishTank', 'CertStream', 'PyPI', 'npm', 'Gemini AI Triage', 'Feeds'
]);

function isValidIsoDate(str) {
  if (!str) return false;
  const d = new Date(str);
  return d instanceof Date && !isNaN(d.getTime());
}

function validateIndicatorFormat(value, type) {
  if (!value || typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 2000) return false;

  // Space check (indicators should not contain unescaped whitespace)
  if (/\s/.test(trimmed)) return false;

  if (type === 'domain') {
    // Basic domain validation
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(trimmed);
  } else if (type === 'url') {
    try {
      new URL(trimmed);
      return true;
    } catch {
      return false;
    }
  } else if (type === 'ip') {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed);
  } else if (type === 'package-pypi' || type === 'package-npm') {
    return /^[a-z0-9@/._-]+$/i.test(trimmed);
  }
  return true;
}

export function runFeedValidation(data) {
  const issues = [];
  const seenValues = new Map();
  const seenIds = new Set();

  let malformedCount = 0;
  let duplicateCount = 0;
  let schemaErrorsCount = 0;
  let missingSourceCount = 0;
  let flaggedReviewCount = 0;

  data.forEach((item, index) => {
    const itemErrors = [];

    // 1. Required Fields & Schema
    if (!item.id) itemErrors.push('Missing required field: id');
    if (!item.value && !item.indicator) itemErrors.push('Missing required field: value/indicator');
    if (!item.indicator_type) itemErrors.push('Missing required field: indicator_type');
    if (!item.source) itemErrors.push('Missing required field: source');
    if (typeof item.confidence_score !== 'number') itemErrors.push('Missing or invalid confidence_score (must be number)');
    if (!item.first_seen) itemErrors.push('Missing required field: first_seen');

    if (itemErrors.length > 0) {
      schemaErrorsCount++;
    }

    // 2. ID Uniqueness
    if (item.id) {
      if (seenIds.has(item.id)) {
        duplicateCount++;
        itemErrors.push(`Duplicate ID detected: ${item.id}`);
      }
      seenIds.add(item.id);
    }

    // 3. Indicator Value Uniqueness & Syntax
    const val = (item.value || item.indicator || '').trim().toLowerCase();
    if (val) {
      if (seenValues.has(val)) {
        duplicateCount++;
        itemErrors.push(`Duplicate indicator value: '${val}' (already observed in entry ${seenValues.get(val)})`);
      } else {
        seenValues.set(val, index);
      }

      const isValidFormat = validateIndicatorFormat(val, item.indicator_type);
      if (!isValidFormat) {
        malformedCount++;
        itemErrors.push(`Malformed observable syntax for type '${item.indicator_type}': '${val}'`);
      }
    }

    // 4. Timestamp validity
    if (item.first_seen && !isValidIsoDate(item.first_seen)) {
      itemErrors.push(`Invalid first_seen timestamp: '${item.first_seen}'`);
    }

    // 5. Source verification
    if (!item.source || item.source.trim() === '') {
      missingSourceCount++;
      itemErrors.push('Discovery source is empty or unknown.');
    }

    // 6. Confidence Score Range
    if (typeof item.confidence_score === 'number') {
      if (item.confidence_score < 0 || item.confidence_score > 100) {
        itemErrors.push(`Confidence score out of bounds (0-100): ${item.confidence_score}`);
      }
    }

    // Flag for manual review if item has issues or single uncorroborated high score
    const requiresReview = itemErrors.length > 0 || (item.confidence_score >= 80 && (!item.enrichment?.has_download_link && item.enrichment?.virustotal_detections === 0 && item.source === 'CertStream'));
    if (requiresReview) {
      flaggedReviewCount++;
    }

    if (itemErrors.length > 0) {
      issues.push({
        index,
        id: item.id || `unknown-${index}`,
        value: val,
        errors: itemErrors,
      });
    }
  });

  const total = data.length;
  const passedCount = total - issues.length;
  const qualityScorePct = total > 0 ? Math.round((passedCount / total) * 100) : 100;

  const report = {
    report_version: '1.0.0',
    generated_at: new Date().toISOString(),
    status: issues.length === 0 ? 'PASSED' : 'PASSED_WITH_REVIEW_FLAGS',
    metrics: {
      total_indicators: total,
      valid_indicators: passedCount,
      malformed_indicators: malformedCount,
      duplicate_indicators: duplicateCount,
      schema_errors: schemaErrorsCount,
      missing_sources: missingSourceCount,
      flagged_for_manual_review: flaggedReviewCount,
      quality_score_percentage: qualityScorePct,
    },
    issues,
  };

  return report;
}

// Execute standalone if called directly
if (process.argv[1] && process.argv[1].endsWith('validate_feed.mjs')) {
  try {
    let feedDataRaw;
    if (fs.existsSync(FEED_PATH)) {
      feedDataRaw = fs.readFileSync(FEED_PATH, 'utf-8');
    } else if (fs.existsSync(path.resolve('feeds/ai_lures_latest.json'))) {
      feedDataRaw = fs.readFileSync(path.resolve('feeds/ai_lures_latest.json'), 'utf-8');
    } else {
      console.error('[-] Could not locate ai_lures_latest.json feed file.');
      process.exit(1);
    }

    const data = JSON.parse(feedDataRaw);
    console.log(`[*] Validating ${data.length} CTI threat indicators in feed...`);
    const report = runFeedValidation(data);

    // Ensure reports directory exists
    const repDir = path.dirname(REPORT_PATH);
    if (!fs.existsSync(repDir)) fs.mkdirSync(repDir, { recursive: true });
    fs.writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2), 'utf-8');

    console.log(`[+] Feed Quality Validation Complete! Quality Score: ${report.metrics.quality_score_percentage}%`);
    console.log(`    - Total Indicators: ${report.metrics.total_indicators}`);
    console.log(`    - Valid Indicators: ${report.metrics.valid_indicators}`);
    console.log(`    - Duplicates: ${report.metrics.duplicate_indicators}`);
    console.log(`    - Malformed: ${report.metrics.malformed_indicators}`);
    console.log(`    - Flagged for Review: ${report.metrics.flagged_for_manual_review}`);
    console.log(`[+] Quality report written to: ${REPORT_PATH}`);

    if (report.metrics.malformed_indicators > 0 || report.metrics.schema_errors > 0) {
      console.warn('[!] Feed contains syntax or schema errors requiring review.');
    }
  } catch (err) {
    console.error('[-] Error executing feed validator:', err);
    process.exit(1);
  }
}
