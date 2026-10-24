// Build/start an application copy with explicit, approved commands. Every process we start runs in
// its own process group so we can stop exactly what we created (and nothing else).
import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import { OutputBuffer, sleep } from './util.js';
import type { ProjectConfig } from './config.js';

const ENV_ALLOWLIST = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ', 'NODE_OPTIONS', 'NVM_DIR', 'SHELL', 'USER'];

export class StepError extends Error {
  constructor(public readonly step: 'build' | 'start' | 'health', message: string, public readonly output: string) { super(message); }
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.unref();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      s.close(() => (typeof addr === 'object' && addr ? resolve(addr.port) : reject(new Error('no port'))));
    });
  });
}

function baseEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const k of ENV_ALLOWLIST) if (process.env[k] !== undefined) env[k] = process.env[k];
  return { ...env, ...extra, CI: '1', BROWSER: 'none' };
}

function killGroup(child: ChildProcess) {
  if (child.pid === undefined || child.exitCode !== null) return;
  try { process.kill(-child.pid, 'SIGTERM'); } catch { /* already gone */ }
  setTimeout(() => { try { process.kill(-child.pid!, 'SIGKILL'); } catch { /* gone */ } }, 3000).unref();
}

function runCommand(cmd: string, cwd: string, env: NodeJS.ProcessEnv, timeoutMs: number, out: OutputBuffer, signal?: AbortSignal): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('sh', ['-c', cmd], { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { out.push(`\n[timed out after ${timeoutMs}ms]\n`); killGroup(child); }, timeoutMs);
    const onAbort = () => { out.push('\n[cancelled]\n'); killGroup(child); };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout!.on('data', (d) => out.push(String(d)));
    child.stderr!.on('data', (d) => out.push(String(d)));
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('exit', (code, sig) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolve(code ?? (sig ? 128 : 1));
    });
  });
}

export interface RunningApp {
  url: string;
  port: number;
  log: () => string;
  stop: () => Promise<void>;
}

export async function buildAndStart(
  workDir: string,
  run: NonNullable<ProjectConfig['run']>,
  onPhase: (phase: 'building' | 'starting' | 'ready') => void,
  signal?: AbortSignal,
): Promise<RunningApp> {
  const out = new OutputBuffer(64 * 1024);
  const port = await freePort();
  const env = baseEnv({ ...run.env, [run.portEnv]: String(port) });

  if (run.build) {
    onPhase('building');
    out.push(`$ ${run.build}\n`);
    const code = await runCommand(run.build, workDir, env, run.buildTimeoutMs, out, signal);
    if (signal?.aborted) throw new StepError('build', 'cancelled', out.toString());
    if (code !== 0) throw new StepError('build', `build command exited with code ${code}`, out.toString());
  }

  onPhase('starting');
  out.push(`$ ${run.start}\n`);
  const child = spawn('sh', ['-c', run.start], { cwd: workDir, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout!.on('data', (d) => out.push(String(d)));
  child.stderr!.on('data', (d) => out.push(String(d)));
  let exited: number | null = null;
  child.on('exit', (code) => { exited = code ?? 1; });
  const stop = async () => {
    killGroup(child);
    for (let i = 0; i < 30 && child.exitCode === null && child.signalCode === null; i++) await sleep(100);
  };
  signal?.addEventListener('abort', () => void stop(), { once: true });

  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + run.startTimeoutMs;
  let lastErr = '';
  while (Date.now() < deadline) {
    if (signal?.aborted) { await stop(); throw new StepError('start', 'cancelled', out.toString()); }
    if (exited !== null) throw new StepError('start', `start command exited early with code ${exited}`, out.toString());
    try {
      const res = await fetch(url + run.healthPath, { signal: AbortSignal.timeout(2000) });
      if (res.status < 500) { onPhase('ready'); return { url, port, log: () => out.toString(), stop }; }
      lastErr = `health check returned ${res.status}`;
    } catch (e) {
      lastErr = String((e as Error).message ?? e);
    }
    await sleep(250);
  }
  await stop();
  throw new StepError('health', `application not ready within ${run.startTimeoutMs}ms (${lastErr})`, out.toString());
}
