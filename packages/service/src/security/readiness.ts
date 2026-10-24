// Generic readiness probe for a locally installed scanner: find the executable (explicit path or PATH),
// run its version command, and report exactly why it is not usable. Never installs anything.
import fs from 'node:fs';
import path from 'node:path';
import type { AnyToolId, Exec, Readiness, Which } from './types.js';

/**
 * spawn() reports ENOENT both for a missing file and for a script whose interpreter (the #! line) is missing.
 * The second case is common with pipx/virtualenv installs after Homebrew upgrades or removes the Python they
 * were built on. Say which one it is.
 */
export function explainSpawnError(binary: string, err: string, tool: string, envPath = process.env.PATH ?? ''): string {
  if (!/ENOENT/.test(err)) return err;
  if (!fs.existsSync(binary)) return `${binary} does not exist (${err})`;
  let first = '';
  try {
    const fd = fs.openSync(binary, 'r');
    const buf = Buffer.alloc(512);
    const n = fs.readSync(fd, buf, 0, 512, 0);
    fs.closeSync(fd);
    first = buf.subarray(0, n).toString('utf8').split('\n')[0]!;
  } catch { return err; }
  if (!first.startsWith('#!')) return err;
  const parts = first.slice(2).trim().split(/\s+/);
  let interp = parts[0]!;
  if (path.basename(interp) === 'env' && parts[1]) {
    const name = parts[1];
    const found = envPath.split(path.delimiter).some((d) => d && fs.existsSync(path.join(d, name)));
    if (found) return err;
    interp = `${name} (looked up on PATH by ${parts[0]})`;
  } else if (fs.existsSync(interp)) return err;
  const resolved = (() => { try { return fs.realpathSync(binary); } catch { return binary; } })();
  const hint = /pipx/.test(resolved) || /pipx/.test(first) ? `pipx reinstall ${tool}` : `reinstall ${tool}`;
  return `${binary} cannot start: its interpreter ${interp} (from the script's #! line) does not exist, so the install is broken (usually a virtualenv whose Python was upgraded or removed). Fix: ${hint}`;
}

export async function probeBinary(opts: {
  tool: AnyToolId; names: string[]; explicit?: string; versionArgs: string[]; parseVersion: (s: string) => string | null;
  exec: Exec; which: Which; cwd: string; timeoutMs?: number;
}): Promise<Readiness> {
  const base = { tool: opts.tool, version: null, binary: null, checkedAt: new Date().toISOString() };
  let binary: string | null = null;
  for (const n of opts.explicit ? [opts.explicit] : opts.names) { binary = opts.which(n, opts.explicit); if (binary) break; }
  if (!binary) {
    return { ...base, state: 'not_installed', reason: opts.explicit ? `configured path ${opts.explicit} is not an executable file` : `none of ${opts.names.map((n) => `'${n}'`).join(', ')} found on PATH` };
  }
  const r = await opts.exec(binary, opts.versionArgs, { cwd: opts.cwd, timeoutMs: opts.timeoutMs ?? 30_000, maxOutputBytes: 64 * 1024 });
  const version = r.exitCode === 0 ? opts.parseVersion(r.stdout) : null;
  if (r.spawnError || r.timedOut || r.exitCode !== 0 || !version) {
    const why = (r.spawnError ? explainSpawnError(binary, r.spawnError, opts.tool) : null) ?? (r.timedOut ? 'version check timed out' : r.exitCode !== 0 ? `version check exited with ${r.exitCode}` : 'unrecognised version output');
    return { ...base, binary, state: 'not_functional', reason: why };
  }
  return { ...base, binary, version, state: 'ready', reason: null };
}
