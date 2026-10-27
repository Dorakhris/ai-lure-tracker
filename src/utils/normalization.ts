/**
 * Indicator Normalization & Deduplication Utilities
 */

export function normalizeIndicatorValue(val: string): string {
  if (!val) return '';
  let cleaned = val.trim();

  // Strip leading/trailing quotes or brackets
  cleaned = cleaned.replace(/^["'\[]+|["'\]]+$/g, '');

  try {
    if (cleaned.startsWith('http://') || cleaned.startsWith('https://')) {
      const parsed = new URL(cleaned);
      // Remove common tracking search params
      const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'ref'];
      trackingParams.forEach(p => parsed.searchParams.delete(p));
      
      // Normalize hostname to lowercase
      parsed.hostname = parsed.hostname.toLowerCase();
      
      // Clean trailing slash if root path only
      let cleanUrl = parsed.toString();
      if (cleanUrl.endsWith('/') && parsed.pathname === '/' && !parsed.search && !parsed.hash) {
        cleanUrl = cleanUrl.slice(0, -1);
      }
      return cleanUrl;
    }
  } catch {
    // Not a valid URL, treat as domain, IP, or package
  }

  // If domain or package, lowercase and strip trailing slash
  cleaned = cleaned.toLowerCase().replace(/\/+$/, '');
  return cleaned;
}

export function deduplicateIndicators<T extends { value?: string; indicator?: string; id?: string }>(items: T[]): T[] {
  const seenValues = new Set<string>();
  const seenIds = new Set<string>();
  const results: T[] = [];

  for (const item of items) {
    const rawVal = item.value || item.indicator || '';
    const normalized = normalizeIndicatorValue(rawVal);
    const id = item.id || normalized;

    if (!normalized || seenValues.has(normalized) || seenIds.has(id)) {
      continue;
    }

    seenValues.add(normalized);
    seenIds.add(id);
    results.push({
      ...item,
      value: normalized
    });
  }

  return results;
}
