import { redact } from './util.js';

type Level = 'debug' | 'info' | 'warn' | 'error';
const order: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const min = order[(process.env.WORKBENCH_LOG_LEVEL as Level) || 'info'] ?? 20;

function emit(level: Level, msg: string, extra?: unknown) {
  if (order[level] < min) return;
  const line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${redact(msg)}`;
  const tail = extra === undefined ? '' : ` ${redact(typeof extra === 'string' ? extra : JSON.stringify(extra))}`;
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + tail + '\n');
}

export const log = {
  debug: (m: string, x?: unknown) => emit('debug', m, x),
  info: (m: string, x?: unknown) => emit('info', m, x),
  warn: (m: string, x?: unknown) => emit('warn', m, x),
  error: (m: string, x?: unknown) => emit('error', m, x),
};
