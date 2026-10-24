// Generic readiness probe for a locally installed scanner: find the executable (explicit path or PATH),
// run its version command, and report exactly why it is not usable. Never installs anything.
import type { AnyToolId, Exec, Readiness, Which } from './types.js';

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
    const why = r.spawnError ?? (r.timedOut ? 'version check timed out' : r.exitCode !== 0 ? `version check exited with ${r.exitCode}` : 'unrecognised version output');
    return { ...base, binary, state: 'not_functional', reason: why };
  }
  return { ...base, binary, version, state: 'ready', reason: null };
}
