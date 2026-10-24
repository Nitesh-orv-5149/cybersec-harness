// Real browser execution with Playwright. Every result here comes from an actual page load.
import fs from 'node:fs';
import path from 'node:path';
import { chromium, type Browser, type Page } from 'playwright';
import type { ProjectConfig, Scenario, ScenarioStep } from './config.js';
import { redact } from './util.js';

export interface AssertionResult { step: string; ok: boolean; message: string }

export interface ScenarioResult {
  scenarioId: string;
  scenarioName: string;
  viewport: string;
  status: 'passed' | 'failed' | 'error';
  assertions: AssertionResult[];
  consoleErrors: string[];
  failedRequests: { url: string; status: number | null; error?: string }[];
  apiRequests: { method: string; path: string; status: number | null }[];
  scriptsLoaded: string[];
  screenshot: string | null;
  durationMs: number;
  error?: string;
}

const STEP_TIMEOUT = 5000;
const FREEZE_CSS = '*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important;scroll-behavior:auto!important}';

export async function launchBrowser(): Promise<Browser> {
  return chromium.launch({ headless: true });
}

export function browserAvailable(): { ok: boolean; reason?: string } {
  try {
    const exe = chromium.executablePath();
    return fs.existsSync(exe) ? { ok: true } : { ok: false, reason: `Chromium not installed at ${exe}. Run: npx playwright install chromium` };
  } catch (e) {
    return { ok: false, reason: String(e) };
  }
}

function describe(step: ScenarioStep): string {
  const [k, v] = Object.entries(step)[0];
  return `${k} ${typeof v === 'string' ? v : JSON.stringify(v)}`;
}

async function runStep(page: Page, step: ScenarioStep, baseUrl: string, statuses: Map<string, number>): Promise<AssertionResult> {
  const label = describe(step);
  try {
    if ('click' in step) { await page.locator(step.click).first().click({ timeout: STEP_TIMEOUT }); return { step: label, ok: true, message: 'clicked' }; }
    if ('fill' in step) { await page.locator(step.fill.selector).first().fill(step.fill.value, { timeout: STEP_TIMEOUT }); return { step: label, ok: true, message: 'filled' }; }
    if ('press' in step) { await page.locator(step.press.selector).first().press(step.press.key, { timeout: STEP_TIMEOUT }); return { step: label, ok: true, message: 'pressed' }; }
    if ('waitFor' in step) { await page.locator(step.waitFor).first().waitFor({ state: 'attached', timeout: STEP_TIMEOUT }); return { step: label, ok: true, message: 'present' }; }
    if ('goto' in step) { await page.goto(new URL(step.goto, baseUrl).toString(), { waitUntil: 'networkidle', timeout: 15000 }); return { step: label, ok: true, message: 'navigated' }; }
    if ('expectVisible' in step) {
      const loc = page.locator(step.expectVisible).first();
      try { await loc.waitFor({ state: 'visible', timeout: STEP_TIMEOUT }); return { step: label, ok: true, message: 'visible' }; }
      catch { return { step: label, ok: false, message: (await loc.count()) ? 'element exists but is not visible' : 'element not found' }; }
    }
    if ('expectHidden' in step) {
      const visible = await page.locator(step.expectHidden).first().isVisible();
      return { step: label, ok: !visible, message: visible ? 'element is visible' : 'hidden' };
    }
    if ('expectText' in step) {
      const loc = page.locator(step.expectText.selector).first();
      const deadline = Date.now() + STEP_TIMEOUT;
      let text = '';
      while (Date.now() < deadline) {
        text = (await loc.textContent({ timeout: STEP_TIMEOUT }).catch(() => '')) ?? '';
        if (text.includes(step.expectText.contains)) return { step: label, ok: true, message: 'text found' };
        await page.waitForTimeout(150);
      }
      return { step: label, ok: false, message: `expected to contain "${step.expectText.contains}", got "${text.trim().slice(0, 140)}"` };
    }
    if ('expectNoHorizontalOverflow' in step) {
      const { sw, cw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
      return { step: label, ok: sw <= cw + 1, message: sw <= cw + 1 ? 'no horizontal overflow' : `page is ${sw}px wide in a ${cw}px viewport` };
    }
    if ('expectStatus' in step) {
      const hit = [...statuses.entries()].find(([u]) => u.includes(step.expectStatus.urlContains));
      return { step: label, ok: !!hit && hit[1] === step.expectStatus.status, message: hit ? `status ${hit[1]}` : 'no matching request observed' };
    }
    return { step: label, ok: false, message: 'unknown step' };
  } catch (e) {
    return { step: label, ok: false, message: `action failed: ${String((e as Error).message ?? e).split('\n')[0]}` };
  }
}

export async function runScenario(
  browser: Browser, baseUrl: string, scenario: Scenario, viewport: { name: string; width: number; height: number },
  cfg: ProjectConfig, outDir: string,
): Promise<ScenarioResult> {
  const started = Date.now();
  const res: ScenarioResult = {
    scenarioId: scenario.id, scenarioName: scenario.name, viewport: viewport.name, status: 'passed',
    assertions: [], consoleErrors: [], failedRequests: [], apiRequests: [], scriptsLoaded: [], screenshot: null, durationMs: 0,
  };
  const origin = new URL(baseUrl).origin;
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height }, deviceScaleFactor: 1,
    locale: 'en-US', timezoneId: 'UTC', reducedMotion: 'reduce', colorScheme: 'light',
  });
  const page = await context.newPage();
  const statuses = new Map<string, number>();
  page.on('console', (m) => { if (m.type() === 'error') res.consoleErrors.push(redact(m.text()).slice(0, 300)); });
  page.on('pageerror', (e) => res.consoleErrors.push(redact(`uncaught: ${e.message}`).slice(0, 300)));
  page.on('requestfailed', (r) => res.failedRequests.push({ url: redact(r.url().replace(origin, '')), status: null, error: r.failure()?.errorText }));
  page.on('response', (r) => {
    const u = r.url();
    if (!u.startsWith(origin)) return;
    const p = u.slice(origin.length);
    statuses.set(p, r.status());
    if (r.status() >= 400) res.failedRequests.push({ url: redact(p), status: r.status() });
    const type = r.request().resourceType();
    if (type === 'script' || type === 'stylesheet' || type === 'document') res.scriptsLoaded.push(p.split('?')[0]);
    if (type === 'fetch' || type === 'xhr') res.apiRequests.push({ method: r.request().method(), path: redact(p.split('?')[0]), status: r.status() });
  });
  try {
    const nav = await page.goto(new URL(scenario.path, baseUrl).toString(), { waitUntil: 'networkidle', timeout: 15000 });
    await page.addStyleTag({ content: FREEZE_CSS }).catch(() => {});
    if (!nav || nav.status() >= 400) {
      res.assertions.push({ step: `load ${scenario.path}`, ok: false, message: `navigation returned ${nav?.status() ?? 'no response'}` });
    } else {
      await page.evaluate(() => document.fonts.ready).catch(() => {});
      for (const step of scenario.steps) res.assertions.push(await runStep(page, step, baseUrl, statuses));
    }
    await page.waitForLoadState('networkidle', { timeout: 3000 }).catch(() => {});
    const file = path.join(outDir, `${scenario.id}--${viewport.name}.png`);
    fs.mkdirSync(outDir, { recursive: true });
    await page.screenshot({
      path: file, fullPage: true, animations: 'disabled', caret: 'hide',
      mask: cfg.browser.mask.map((s) => page.locator(s)),
    });
    res.screenshot = file;
    res.status = res.assertions.every((a) => a.ok) ? 'passed' : 'failed';
  } catch (e) {
    res.status = 'error';
    res.error = String((e as Error).message ?? e).split('\n')[0];
  } finally {
    await context.close().catch(() => {});
  }
  res.durationMs = Date.now() - started;
  return res;
}
