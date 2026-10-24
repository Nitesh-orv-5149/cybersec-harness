#!/usr/bin/env node
// Entry point: start the local analysis service, optionally registering a project to monitor.
//   workbench --project ./sample-app [--port 4317] [--no-monitor] [--mongo mongodb://127.0.0.1:27017]
import { parseArgs } from 'node:util';
import { serviceConfig } from './config.js';
import { Service } from './server.js';
import { log } from './log.js';

const { values } = parseArgs({
  options: {
    project: { type: 'string', multiple: true },
    port: { type: 'string' },
    mongo: { type: 'string' },
    db: { type: 'string' },
    'no-monitor': { type: 'boolean', default: false },
  },
});

const cfg = serviceConfig({
  ...(values.port ? { port: Number(values.port) } : {}),
  ...(values.mongo ? { mongoUri: values.mongo } : {}),
  ...(values.db ? { mongoDb: values.db } : {}),
});

const service = new Service(cfg);
let stopping = false;
async function shutdown(sig: string) {
  if (stopping) return;
  stopping = true;
  log.info(`received ${sig}, shutting down`);
  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();
  await service.stop().catch((e) => log.error(String(e)));
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

await service.start();
if (!service.store.available) log.warn('MongoDB is not reachable; graph analysis still runs, history and verification are disabled until it is. Set WORKBENCH_MONGO_URI or --mongo.');
for (const p of values.project ?? []) {
  try {
    const s = await service.addProject(p, !values['no-monitor']);
    log.info(`project ${s.name} (${s.id}) ready: http://${cfg.host}:${cfg.port}/?project=${s.id}`);
  } catch (e) {
    log.error(`could not open project ${p}: ${(e as Error).message}`);
  }
}
