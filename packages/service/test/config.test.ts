// workbench.config.json loading: a broken browser scenario must not silently reset the run commands and
// security settings to defaults; other errors still reject the file with a readable message.
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadProjectConfig } from '../src/config.js';

const withConfig = (cfg: unknown) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-cfg-'));
  fs.writeFileSync(path.join(dir, 'workbench.config.json'), typeof cfg === 'string' ? cfg : JSON.stringify(cfg));
  return loadProjectConfig(dir);
};

describe('loadProjectConfig', () => {
  it('skips only the scenario with an unsupported step and keeps run + security settings', () => {
    const l = withConfig({
      run: { start: 'npm start', healthPath: '/rest/admin/application-version' },
      security: { api: { allowActiveTesting: true } },
      browser: { scenarios: [
        { id: 'home', name: 'Home', path: '/', steps: [{ expectVisible: 'body' }] },
        { id: 'login', name: 'Login', path: '/#/login', steps: [{ fill: { selector: '#email', value: 'a' } }, { click: '#loginButton' }, { waitFor: '.x' }, { wait: 1000 }] },
      ] },
    });
    expect(l.error).toBeUndefined();
    expect(l.source).toBe('file');
    expect(l.config.run?.start).toBe('npm start');
    expect(l.runHash).toMatch(/^[0-9a-f]{16}$/);
    expect(l.config.security.api.allowActiveTesting).toBe(true);
    expect(l.config.browser.scenarios.map((s) => s.id)).toEqual(['home']);
    expect(l.warnings).toHaveLength(1);
    expect(l.warnings![0]).toContain('"login" was skipped');
    expect(l.warnings![0]).toContain('browser.scenarios[1].steps[3]: {"wait":1000} is not a supported step');
    expect(l.warnings![0]).toContain('"waitFor"');
  });

  it('still rejects errors outside scenarios, naming the field', () => {
    const l = withConfig({ run: { start: 'npm start' }, security: { api: { methods: ['GET', 'TRACE'] } } });
    expect(l.source).toBe('default');
    expect(l.error).toMatch(/security\.api\.methods\[1\]/);
    expect(withConfig('{ nope').error).toMatch(/not valid JSON/);
  });

  it('a valid file has no warnings', () => {
    const l = withConfig({ run: { start: 'node server.js' } });
    expect(l.error).toBeUndefined();
    expect(l.warnings).toBeUndefined();
  });
});
