// Nuclei adapter: readiness of the locally installed executable and template directory, the exact argument list,
// and interpretation of its JSONL output and log lines. Flags were checked against the official documentation and
// the nuclei source (cmd/nuclei/main.go, v3); readiness also checks every flag against the installed binary's own
// `-h` output, so an older or different build is reported as not usable instead of failing mid-scan.
//
// Facts this relies on (nuclei v3 source):
//  - `-version` logs "Nuclei Engine Version: vX.Y.Z" and `-tv` logs "Public nuclei-templates version: vN (dir)",
//    both through the logger on stderr.
//  - `-duc` disables the version check AND the automatic template install/update (both are guarded by
//    CanCheckForUpdates()). DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true is set as a second guard.
//  - With `-jsonl`, each result is one JSON object per line on stdout (output.ResultEvent); logs go to stderr.
import fs from 'node:fs';
import path from 'node:path';
import type { AppSeverity, Exec, ExecResult, Which } from '../types.js';
import { sha256 } from '../../util.js';
import { redactCurl, redactExtracted, redactHttpDump, redactUrl, truncate } from './redact.js';
import { inScope, normalizeEndpoint, type AuthorizedTarget } from './target.js';
import { DENY_TAGS } from './templates.js';
import type { ProjectConfig } from '../../config.js';

export type NucleiConfig = ProjectConfig['security']['nuclei'];

export const NUCLEI_ENV = { DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD: 'true' };

/** Every flag the workbench passes. Each must appear in the installed binary's `-h` output. */
export const REQUIRED_FLAGS = ['u', 't', 'jsonl', 'nc', 'duc', 'ni', 'rl', 'c', 'bs', 'timeout', 'retries', 'mhe', 'dr', 'fhr', 'mr', 'etags'];
/** Used when available; their absence is reported but does not block a scan. pd/cup are the cloud-upload switches,
 *  forced off on the command line so a user config.yaml cannot enable uploading results. elog writes one JSON line
 *  per failed request (template file + request URL), which keeps those checks out of the incremental cache. */
export const OPTIONAL_FLAGS = ['ot', 'rsr', 'pd', 'cup', 'l', 'stats', 'sj', 'si', 'elog'];

export type ScanProfile = 'quick' | 'standard' | 'full';
/** Template folders per profile (relative to the nuclei-templates directory). Everything is still vetted per template. */
export const PROFILE_TEMPLATES: Record<ScanProfile, string[]> = {
  quick: ['http/misconfiguration', 'http/exposures/configs', 'http/technologies'],
  standard: ['http/misconfiguration', 'http/exposures', 'http/technologies', 'http/exposed-panels', 'http/vulnerabilities', 'http/cves'],
  full: ['http'],
};
const PROFILE_TIMEOUT: Record<ScanProfile, number> = { quick: 10 * 60_000, standard: 30 * 60_000, full: 60 * 60_000 };

/** Settings actually used for one scan: profile templates, and rate/timeout defaults that depend on the target. */
export interface EffectiveSettings { profile: ScanProfile | 'custom'; templates: string[]; rateLimit: number; timeoutMs: number }
export function effectiveSettings(cfg: NucleiConfig, loopback: boolean, profile?: ScanProfile): EffectiveSettings {
  const p = profile ?? cfg.profile;
  return {
    profile: cfg.templates ? 'custom' : p,
    templates: cfg.templates ?? PROFILE_TEMPLATES[p],
    rateLimit: cfg.rateLimit ?? (loopback ? 50 : 10),
    timeoutMs: cfg.timeoutMs ?? PROFILE_TIMEOUT[p],
  };
}

export const SETUP_INSTRUCTIONS = [
  'Install nuclei yourself (the workbench never installs it): see https://docs.projectdiscovery.io/opensource/nuclei/install — e.g. `brew install nuclei` on macOS, `pacman -S nuclei` on Arch, or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`.',
  'If it is not on PATH, set security.nuclei.binary in workbench.config.json to the absolute path of the executable.',
  'Download templates yourself, outside the workbench: run `nuclei -ut` once (or clone https://github.com/projectdiscovery/nuclei-templates). Scans never download or update templates.',
  'If the templates live somewhere nuclei does not report, set security.nuclei.templatesDir to that directory.',
];

export interface NucleiReadiness {
  state: 'ready' | 'not_installed' | 'not_functional' | 'disabled';
  binary: string | null;
  version: string | null;
  reason: string | null;
  missingOptionalFlags: string[];
  templates: {
    state: 'ready' | 'missing' | 'empty' | 'unknown';
    dir: string | null;
    source: 'config' | 'nuclei' | null;
    version: string | null;
    reason: string | null;
  };
  checkedAt: string;
}

export function parseEngineVersion(text: string): string | null {
  return text.match(/Engine Version:\s*v?(\d+\.\d+\.\d+[\w.-]*)/i)?.[1] ?? text.match(/^v?(\d+\.\d+\.\d+)\s*$/m)?.[1] ?? null;
}

export function parseTemplatesVersion(text: string): { version: string | null; dir: string | null } {
  const m = text.match(/nuclei-templates version:\s*(\S*)\s*\(([^)]*)\)/i);
  return { version: m?.[1] ? m[1].replace(/^v/, '') || null : null, dir: m?.[2]?.trim() || null };
}

export function flagsInHelp(help: string, flags: string[]): string[] {
  return flags.filter((f) => !new RegExp(`(^|[\\s,])-${f.replace(/[-]/g, '\\-')}(?=[\\s,])`, 'm').test(help));
}

const out = (r: ExecResult) => `${r.stdout}\n${r.stderrTail}`;

export async function checkNuclei(cfg: NucleiConfig, exec: Exec, which: Which, cwd: string): Promise<NucleiReadiness> {
  const checkedAt = new Date().toISOString();
  const noTemplates = { state: 'unknown' as const, dir: null, source: null, version: null, reason: 'nuclei is not usable' };
  const base = { binary: null, version: null, missingOptionalFlags: [], templates: noTemplates, checkedAt };
  if (!cfg.enabled) return { ...base, state: 'disabled', reason: 'security.nuclei.enabled is false' };
  const binary = which('nuclei', cfg.binary);
  if (!binary) return { ...base, state: 'not_installed', reason: cfg.binary ? `configured path ${cfg.binary} is not an executable file` : "'nuclei' was not found on PATH" };
  const run = (args: string[]) => exec(binary, args, { cwd, timeoutMs: 30_000, maxOutputBytes: 1024 * 1024, extraEnv: NUCLEI_ENV, stderrTailBytes: 200_000 });
  const v = await run(['-version', '-duc', '-nc']);
  const version = v.spawnError ? null : parseEngineVersion(out(v));
  if (!version) {
    return { ...base, binary, state: 'not_functional', reason: v.spawnError ?? (v.timedOut ? 'version check timed out' : `could not read a version from \`nuclei -version\` (exit ${v.exitCode})`) };
  }
  const h = await run(['-h']);
  const missing = flagsInHelp(out(h), REQUIRED_FLAGS);
  if (missing.length) {
    return { ...base, binary, version, state: 'not_functional', reason: `the installed nuclei ${version} does not list these required flags in -h: ${missing.map((f) => `-${f}`).join(', ')}` };
  }
  const missingOptional = flagsInHelp(out(h), OPTIONAL_FLAGS);
  const tv = await run(['-tv', '-duc', '-nc']);
  const reported = parseTemplatesVersion(out(tv));
  const dir = cfg.templatesDir ?? reported.dir;
  const source = cfg.templatesDir ? 'config' as const : reported.dir ? 'nuclei' as const : null;
  let templates: NucleiReadiness['templates'];
  if (!dir) templates = { state: 'missing', dir: null, source: null, version: null, reason: 'no template directory configured and nuclei did not report one' };
  else if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) templates = { state: 'missing', dir, source, version: null, reason: `template directory ${dir} does not exist` };
  else if (!hasYaml(dir)) templates = { state: 'empty', dir, source, version: null, reason: `template directory ${dir} contains no templates` };
  else templates = { state: 'ready', dir, source, version: cfg.templatesDir && path.resolve(cfg.templatesDir) !== path.resolve(reported.dir ?? '') ? readTemplatesVersionFile(dir) : (reported.version ?? readTemplatesVersionFile(dir)), reason: null };
  return { binary, version, state: 'ready', reason: null, missingOptionalFlags: missingOptional, templates, checkedAt };
}

function hasYaml(dir: string, depth = 0): boolean {
  if (depth > 4) return false;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue;
    if (e.isFile() && /\.ya?ml$/i.test(e.name)) return true;
    if (e.isDirectory() && hasYaml(path.join(dir, e.name), depth + 1)) return true;
  }
  return false;
}

/** nuclei-templates checkouts carry a version marker in some layouts; read it when present. */
function readTemplatesVersionFile(dir: string): string | null {
  for (const f of ['.version', 'VERSION']) {
    try { const t = fs.readFileSync(path.join(dir, f), 'utf8').trim(); if (/^v?\d/.test(t)) return t.replace(/^v/, ''); } catch { /* none */ }
  }
  return null;
}

/** `listFile`: a file with one target URL per line (the root plus app routes); otherwise only target.url is scanned. */
export function buildArgs(target: AuthorizedTarget, stagedDir: string, cfg: NucleiConfig, missingOptional: string[] = [], eff?: Pick<EffectiveSettings, 'rateLimit'>, listFile?: string, errorLog?: string): string[] {
  const useList = !!listFile && !missingOptional.includes('l');
  const args = [
    ...(useList ? ['-l', listFile!] : ['-u', target.url]),
    '-t', stagedDir,
    '-jsonl', '-nc', '-duc',
    '-ni',                                   // no interactsh / out-of-band templates
    '-rl', String(eff?.rateLimit ?? cfg.rateLimit ?? (target.loopback ? 50 : 10)),
    '-c', String(cfg.concurrency),
    '-bs', '1',
    '-timeout', String(cfg.requestTimeoutSec),
    '-retries', String(cfg.retries),
    '-mhe', String(cfg.maxHostErrors),
    '-etags', [...new Set([...DENY_TAGS, ...cfg.excludeTags])].join(','),   // defence in depth; templates are vetted before staging
  ];
  if (cfg.redirects === 'none') args.push('-dr');
  else args.push('-fhr', '-mr', '3');
  if (!missingOptional.includes('ot')) args.push('-ot');
  if (!missingOptional.includes('rsr')) args.push('-rsr', String(cfg.maxResponseBytes));
  if (!missingOptional.includes('pd')) args.push('-pd=false');
  if (!missingOptional.includes('cup')) args.push('-cup=false');
  // live progress: one JSON statistics line per second on stderr
  if (!['stats', 'sj', 'si'].some((f) => missingOptional.includes(f))) args.push('-stats', '-sj', '-si', '1');
  if (errorLog && !missingOptional.includes('elog')) args.push('-elog', errorLog);
  return args;
}

/** One failed request from the `-elog` file: which template file sent which request URL. */
export interface RequestError { template: string; url: string; error: string }

/** Parse the `-elog` JSONL (nuclei v3: {"template": <path>, "input": <request URL>, "error": ..., "kind": ...}). */
export function parseErrorLog(text: string): RequestError[] {
  const out: RequestError[] = [];
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l) continue;
    try {
      const e = JSON.parse(l) as Record<string, unknown>;
      if (typeof e.template === 'string' && typeof e.input === 'string') out.push({ template: e.template, url: e.input, error: String(e.error ?? e.kind ?? '').slice(0, 300) });
    } catch { /* a torn last line when nuclei was stopped */ }
  }
  return out;
}

// ---------------------------------------------------------------- output

const SEVERITY: Record<string, AppSeverity> = { critical: 'high', high: 'high', medium: 'medium', low: 'low', info: 'info', unknown: 'unknown' };
export function mapNucleiSeverity(s: unknown): AppSeverity {
  return typeof s === 'string' ? SEVERITY[s.trim().toLowerCase()] ?? 'unknown' : 'unknown';
}

export interface WebObservation {
  fingerprint: string;
  templateId: string;
  templatePath: string | null;
  name: string | null;
  description: string | null;
  severity: AppSeverity;
  originalSeverity: string | null;
  tags: string[];
  references: string[];
  classification: { cve: string[]; cwe: string[]; cvssScore: number | null; cvssMetrics: string | null };
  type: string | null;
  host: string | null;
  port: string | null;
  scheme: string | null;
  url: string | null;
  /** the scan input (target URL path) that produced the result; absence is only judged for inputs that were scanned again */
  input: string;
  matchedAt: string;
  endpoint: string;
  method: string | null;
  matcherName: string | null;
  extractorName: string | null;
  extractedResults: string[];
  request: string | null;
  response: string | null;
  evidenceTruncated: boolean;
  curlCommand: string | null;
  ip: string | null;
  timestamp: string | null;
  occurrences: number;
}

export interface ParsedOutput {
  observations: WebObservation[];
  lines: number;
  malformed: number;
  outOfScope: { templateId: string; matchedAt: string }[];
  toolErrors: string[];
  truncatedFindings: boolean;
}

const MAX_EVIDENCE = 8 * 1024;
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === 'string' && v ? v.split(',').map((s) => s.trim()).filter(Boolean) : []);
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);

export function fingerprintOf(templateId: string, matcher: string | null, extractor: string | null, method: string | null, endpoint: string) {
  return sha256([templateId, matcher ?? '', extractor ?? '', method ?? '', endpoint].join('\u0000')).slice(0, 24);
}

/** Parse nuclei JSONL. Malformed lines are counted (never silently dropped); results outside the target origin are not findings. */
export function parseNucleiJsonl(stdout: string, target: AuthorizedTarget, maxFindings = 5000): ParsedOutput {
  const byFp = new Map<string, WebObservation>();
  let lines = 0;
  let malformed = 0;
  const outOfScope: ParsedOutput['outOfScope'] = [];
  const toolErrors: string[] = [];
  let truncatedFindings = false;
  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    lines++;
    let e: Record<string, unknown>;
    try { e = JSON.parse(line); } catch { malformed++; continue; }
    if (!e || typeof e !== 'object' || Array.isArray(e)) { malformed++; continue; }
    const templateId = str(e['template-id']);
    if (str(e.error) && !str(e['matched-at'])) { toolErrors.push(`${templateId ?? '?'}: ${redactUrl(String(e.error)).slice(0, 300)}`); continue; }
    const matchedRaw = str(e['matched-at']) ?? str(e.url) ?? str(e.host);
    if (!templateId || !matchedRaw) { malformed++; continue; }
    if (e['matcher-status'] === false) continue; // only present with -ms; a failed match is not a finding
    if (!inScope(matchedRaw, target)) { outOfScope.push({ templateId, matchedAt: redactUrl(matchedRaw) }); continue; }
    const info = (e.info && typeof e.info === 'object' ? e.info : {}) as Record<string, unknown>;
    const cls = (info.classification && typeof info.classification === 'object' ? info.classification : {}) as Record<string, unknown>;
    const reqRaw = str(e.request);
    const method = reqRaw?.match(/^([A-Z]+)\s+\S+\s+HTTP\//)?.[1] ?? null;
    const endpoint = normalizeEndpoint(matchedRaw);
    const matcherName = str(e['matcher-name']);
    const extractorName = str(e['extractor-name']);
    const fp = fingerprintOf(templateId, matcherName, extractorName, method, endpoint);
    const prev = byFp.get(fp);
    if (prev) { prev.occurrences++; continue; }
    if (byFp.size >= maxFindings) { truncatedFindings = true; continue; }
    const tags = arr(info.tags).map((t) => t.toLowerCase());
    const req = reqRaw ? truncate(redactHttpDump(reqRaw), MAX_EVIDENCE) : null;
    const resRaw = str(e.response);
    const res = resRaw ? truncate(redactHttpDump(resRaw), MAX_EVIDENCE) : null;
    const cvss = Number(cls['cvss-score']);
    byFp.set(fp, {
      fingerprint: fp, templateId, templatePath: str(e['template-path']) ?? str(e.template), name: str(info.name), description: str(info.description)?.trim() ?? null,
      severity: mapNucleiSeverity(info.severity), originalSeverity: str(info.severity), tags,
      references: arr(info.reference).filter((r) => /^https?:\/\//i.test(r)).slice(0, 20),
      classification: { cve: arr(cls['cve-id']), cwe: arr(cls['cwe-id']), cvssScore: Number.isFinite(cvss) && cls['cvss-score'] !== undefined ? cvss : null, cvssMetrics: str(cls['cvss-metrics']) },
      type: str(e.type), host: str(e.host) ? redactUrl(String(e.host)) : null, port: str(e.port), scheme: str(e.scheme), url: str(e.url) ? redactUrl(String(e.url)) : null,
      input: str(e.url) && /^https?:\/\//i.test(String(e.url)) ? normalizeEndpoint(String(e.url)).split('?')[0]! : '/',
      matchedAt: redactUrl(matchedRaw), endpoint, method, matcherName, extractorName,
      extractedResults: redactExtracted(arr(e['extracted-results']).slice(0, 50).map((x) => x.slice(0, 500)), `${templateId} ${tags.join(' ')} ${extractorName ?? ''}`),
      request: req?.text ?? null, response: res?.text ?? null, evidenceTruncated: !!(req?.truncated || res?.truncated),
      curlCommand: str(e['curl-command']) ? truncate(redactCurl(String(e['curl-command'])), 4096).text : null,
      ip: str(e.ip), timestamp: str(e.timestamp), occurrences: 1,
    });
  }
  return { observations: [...byFp.values()], lines, malformed, outOfScope, toolErrors, truncatedFindings };
}

/** The target's host:port as nuclei writes it in skip lines (explicit port, IPv6 without brackets). */
export function targetHostPort(target: AuthorizedTarget): string {
  const u = new URL(target.origin);
  return `${target.host}:${u.port || (u.protocol === 'https:' ? '443' : '80')}`;
}

export interface ScanStats { requests: number; total: number; percent: number; matched: number; errors: number; rps: number; duration: string; hosts: number; templates: number }
export interface StderrFacts {
  templatesLoaded: number | null; targetsLoaded: number | null; templatesVersion: string | null; stats: ScanStats | null;
  hostSkipped: boolean;
  /** host:port values nuclei gave up on ("Skipped <host:port> from target list"); '?' when a skip line names none.
   *  Some templates probe other ports of the target host, so a skip is not necessarily the target itself. */
  skippedHosts: string[];
  fatal: string | null; errors: string[]; warnings: string[];
}

/** One `-stats -sj` line (all values are strings in nuclei's output). */
export function parseStatsLine(line: string): ScanStats | null {
  if (!line.startsWith('{') || !line.includes('"percent"')) return null;
  try {
    const o = JSON.parse(line) as Record<string, string>;
    const n = (k: string) => (Number.isFinite(Number(o[k])) ? Number(o[k]) : 0);
    return { requests: n('requests'), total: n('total'), percent: Math.min(100, n('percent')), matched: n('matched'), errors: n('errors'), rps: n('rps'), duration: String(o.duration ?? ''), hosts: n('hosts'), templates: n('templates') };
  } catch { return null; }
}

/** Read nuclei's log lines (stderr). They decide whether a scan with zero results actually covered the target. */
export function readStderr(text: string): StderrFacts {
  const lines = text.split('\n').map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').trim()).filter(Boolean);
  let templatesLoaded: number | null = null;
  let targetsLoaded: number | null = null;
  let templatesVersion: string | null = null;
  let stats: ScanStats | null = null;
  let hostSkipped = false;
  const skippedHosts = new Set<string>();
  let fatal: string | null = null;
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const l of lines) {
    const st = parseStatsLine(l);
    if (st) { stats = st; continue; }
    const t = l.match(/Templates loaded for (?:current )?scan:\s*(\d+)/i);
    if (t) templatesLoaded = Number(t[1]);
    const tg = l.match(/Targets loaded for (?:current )?scan:\s*(\d+)/i);
    if (tg) targetsLoaded = Number(tg[1]);
    const tv = l.match(/nuclei-templates version:\s*v?(\d[\w.-]*)/i);
    if (tv) templatesVersion = tv[1]!;
    if (/unresponsive|Skipped .* from target list/i.test(l)) {
      hostSkipped = true;
      skippedHosts.add(l.match(/Skipped\s+(\S+?)\s+from target list/i)?.[1]?.replace(/^\[|\](?=:)/g, '').toLowerCase() ?? '?');
    }
    if (/^\[FTL\]|Could not run nuclei|no templates (were )?(provided|found|loaded)|no valid templates/i.test(l)) fatal ??= l.slice(0, 400);
    // -duc also stops nuclei from fetching its .nuclei-ignore file; the resulting [ERR] line is expected and harmless.
    else if (/^\[ERR\]/.test(l) && !/nuclei-ignore/i.test(l)) errors.push(l.slice(0, 400));
    else if (/^\[ERR\]/.test(l)) warnings.push(l.slice(0, 400));
    else if (/^\[WRN\]/.test(l)) warnings.push(l.slice(0, 400));
  }
  return { templatesLoaded, targetsLoaded, templatesVersion, stats, hostSkipped, skippedHosts: [...skippedHosts], fatal, errors: errors.slice(-20), warnings: warnings.slice(-20) };
}
