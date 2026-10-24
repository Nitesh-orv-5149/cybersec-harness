// Explicit severity mapping from each tool's vocabulary to the workbench scale (high | medium | low | info),
// plus 'unknown' when the tool supplied nothing usable. The original label is always kept alongside.
//
// The workbench scale has no "critical" level by design (see findings.ts). A published advisory severity of
// CRITICAL therefore maps to high, and the original "critical" label is stored and shown next to it.
import type { AppSeverity } from '../types.js';

const TABLE: Record<string, AppSeverity> = {
  critical: 'high', high: 'high', moderate: 'medium', medium: 'medium', low: 'low', info: 'info', informational: 'info', none: 'info',
};

/** npm audit: info | low | moderate | high | critical. OSV/GHSA database_specific: LOW | MODERATE | HIGH | CRITICAL. Trivy: UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL. */
export function mapLabel(label: string | null | undefined): AppSeverity {
  if (!label) return 'unknown';
  return TABLE[label.trim().toLowerCase()] ?? 'unknown';
}

/** CVSS v3 qualitative bands: 0.0 none, 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical (-> high). */
export function mapCvssScore(score: number | null | undefined): AppSeverity {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unknown';
  if (score === 0) return 'info';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  return 'high';
}

export const SEVERITY_RANK_EXT: Record<AppSeverity, number> = { high: 3, medium: 2, unknown: 1.5, low: 1, info: 0 };

export function maxSeverity(a: AppSeverity, b: AppSeverity): AppSeverity {
  return SEVERITY_RANK_EXT[a] >= SEVERITY_RANK_EXT[b] ? a : b;
}
