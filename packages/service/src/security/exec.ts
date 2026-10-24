// Safe subprocess execution for scanners: argument arrays (no shell), a minimal environment, a hard
// timeout that kills the whole process group, bounded stdout/stderr, and cancellation.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { OutputBuffer, redact } from '../util.js';
import type { Exec, ExecResult, Which } from './types.js';

const ENV_KEYS = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ', 'USER', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME'];
// Network/registry configuration the tools need to honour the user's own proxy and registry settings.
const ENV_PATTERNS = [/^npm_config_/i, /^https?_proxy$/i, /^no_proxy$/i, /^SSL_CERT_(FILE|DIR)$/, /^NODE_EXTRA_CA_CERTS$/, /^TRIVY_/, /^OSV_/];

export function scannerEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (ENV_KEYS.includes(k) || ENV_PATTERNS.some((re) => re.test(k))) env[k] = v;
  }
  return { ...env, NO_COLOR: '1', CI: '1' };
}

export const which: Which = (name, explicit) => {
  const isExec = (p: string) => { try { fs.accessSync(p, fs.constants.X_OK); return fs.statSync(p).isFile(); } catch { return false; } };
  if (explicit) return path.isAbsolute(explicit) && isExec(explicit) ? explicit : null;
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, name);
    if (isExec(p)) return p;
  }
  return null;
};

export const execTool: Exec = (binary, args, opts) => new Promise<ExecResult>((resolve) => {
  const started = Date.now();
  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;
  let timedOut = false;
  let cancelled = false;
  const stderr = new OutputBuffer(8 * 1024);
  let child;
  try {
    child = spawn(binary, args, { cwd: opts.cwd, env: scannerEnv(), detached: true, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
  } catch (e) {
    resolve({ exitCode: null, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: String((e as Error).message ?? e), durationMs: 0 });
    return;
  }
  const kill = () => {
    if (child.pid === undefined || child.exitCode !== null) return;
    try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ }
    setTimeout(() => { try { process.kill(-child.pid!, 'SIGKILL'); } catch { /* gone */ } }, 2000).unref();
  };
  const timer = setTimeout(() => { timedOut = true; kill(); }, opts.timeoutMs);
  const onAbort = () => { cancelled = true; kill(); };
  opts.signal?.addEventListener('abort', onAbort, { once: true });
  let spawnError: string | null = null;
  let settled = false;
  const finish = (code: number | null, sig: string | null) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    opts.signal?.removeEventListener('abort', onAbort);
    resolve({
      exitCode: code, signal: sig, stdout: Buffer.concat(chunks).toString('utf8'), stdoutBytes: bytes, stdoutTruncated: truncated,
      stderrTail: redact(stderr.toString()).slice(-4000), timedOut, cancelled, spawnError, durationMs: Date.now() - started,
    });
  };
  child.on('error', (e) => { spawnError = e.message; setTimeout(() => finish(null, null), 50); });
  child.stdout!.on('data', (d: Buffer) => {
    if (truncated) return;
    if (bytes + d.length > opts.maxOutputBytes) { truncated = true; kill(); return; }
    chunks.push(d);
    bytes += d.length;
  });
  child.stderr!.on('data', (d: Buffer) => stderr.push(d.toString('utf8')));
  child.on('close', (code, sig) => finish(code, sig));
});
