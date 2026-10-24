import type { ExecResult, ToolOutcome } from '../types.js';

export function parseJson(stdout: string): { ok: true; value: unknown } | { ok: false; reason: string } {
  const text = stdout.trim();
  if (!text) return { ok: false, reason: 'the tool produced no JSON output' };
  try { return { ok: true, value: JSON.parse(text) }; }
  catch (e) { return { ok: false, reason: `malformed JSON output (${String((e as Error).message).slice(0, 120)})` }; }
}

/** Process-level failures shared by every adapter. Returns null when the output should be inspected. */
export function genericFailure(exec: ExecResult): ToolOutcome | null {
  if (exec.spawnError) return { status: 'failed', reason: `could not start the tool: ${exec.spawnError}`, notes: [] };
  if (exec.cancelled) return { status: 'failed', reason: 'cancelled', notes: [] };
  if (exec.timedOut) return { status: 'failed', reason: `timed out after ${Math.round(exec.durationMs / 1000)}s; partial output discarded`, notes: [] };
  if (exec.stdoutTruncated) return { status: 'failed', reason: `output exceeded the configured limit (${exec.stdoutBytes} bytes kept); report discarded rather than parsed partially`, notes: [] };
  return null;
}

export function normaliseGhsa(id: string | null | undefined): string | null {
  if (!id || !/^GHSA-/i.test(id)) return null;
  return `GHSA${id.slice(4).toLowerCase()}`;
}

/** Normalise an advisory identifier for alias matching (GHSA ids are case-insensitive, CVE ids upper-case). */
export function idKey(id: string): string {
  if (/^GHSA-/i.test(id)) return normaliseGhsa(id)!;
  if (/^CVE-/i.test(id)) return id.toUpperCase();
  return id;
}
