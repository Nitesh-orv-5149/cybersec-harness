// Thin IDE client: forwards workspace activity to the local analysis service and shows its state.
// All analysis, persistence and browser work happens in the service; nothing here edits user files.
import * as vscode from 'vscode';
import * as path from 'node:path';
import WebSocket from 'ws';

let projectId: string | null = null;
let projectRoot: string | null = null;
let status: vscode.StatusBarItem;
let ws: WebSocket | null = null;
let poll: NodeJS.Timeout | null = null;
const bufferTimers = new Map<string, NodeJS.Timeout>();

const cfg = () => vscode.workspace.getConfiguration('workbench');
const base = () => String(cfg().get('serviceUrl')).replace(/\/$/, '');

async function call<T>(method: 'GET' | 'POST', route: string, body?: unknown): Promise<T> {
  const res = await fetch(base() + route, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const data = (await res.json().catch(() => null)) as any;
  if (!res.ok) {
    const reasons = data?.reasons ? ` (${data.reasons.join('; ')})` : '';
    throw new Error(`${data?.error ?? `HTTP ${res.status}`}${reasons}`);
  }
  return data as T;
}

function rel(doc: vscode.TextDocument): string | null {
  if (!projectRoot || doc.uri.scheme !== 'file') return null;
  const r = path.relative(projectRoot, doc.uri.fsPath);
  return r.startsWith('..') || path.isAbsolute(r) ? null : r.split(path.sep).join('/');
}

function render(s: any | null, err?: string) {
  if (err) { status.text = '$(warning) Workbench offline'; status.tooltip = `${err}\nStart the service: npm start -- --project <folder>`; return; }
  if (!s) { status.text = '$(circle-slash) Workbench'; status.tooltip = 'Not monitoring. Run "Workbench: Start monitoring".'; return; }
  const job = s.browser?.job;
  const analysis = s.analysis.status === 'idle' ? '$(eye)' : s.analysis.status === 'failed' ? '$(error)' : '$(sync~spin)';
  status.text = `${analysis} Workbench${job ? ` · site ${job.status.replace('_', ' ')}` : ''}${s.store.available ? '' : ' · no DB'}`;
  status.tooltip = [
    `Monitoring: ${s.monitoring ? 'on' : 'off'}`,
    `Analysis: ${s.analysis.status}${s.analysis.error ? ` (${s.analysis.error})` : ''}`,
    s.live ? `Graph v${s.live.graphVersion}: ${s.live.nodeCount} nodes, source ${s.live.sourceHash.slice(0, 8)}` : '',
    `Baseline: ${s.baseline ? s.baseline.snapshotId : 'not set'}`,
    s.unsavedBuffers.length ? `Unsaved buffers in graph: ${s.unsavedBuffers.join(', ')}` : '',
    s.lastBrowserRun ? `Last website run: ${s.lastBrowserRun.status}` : '',
    s.verification.ok ? '' : `Verification unavailable: ${s.verification.reasons.join('; ')}`,
    'Click to open the dashboard',
  ].filter(Boolean).join('\n');
}

async function refreshStatus() {
  if (!projectId) return render(null);
  try { render(await call('GET', `/api/projects/${projectId}/status`)); } catch (e) { render(null, String((e as Error).message)); }
}

function connectSocket() {
  ws?.close();
  const url = base().replace(/^http/, 'ws') + '/ws';
  ws = new WebSocket(url);
  ws.on('message', (raw) => {
    const m = JSON.parse(String(raw));
    if (m.projectId !== projectId) return;
    if (m.kind === 'open-in-editor' && m.root === projectRoot) {
      const uri = vscode.Uri.file(path.join(m.root, m.file));
      void vscode.window.showTextDocument(uri, { selection: new vscode.Range(m.line - 1, 0, m.line - 1, 0), preview: false });
      return;
    }
    if (m.kind === 'browser' && (m.payload?.status === 'failed' || m.payload?.status === 'inconclusive')) {
      void vscode.window.showWarningMessage(`Website comparison ${m.payload.status}: ${m.payload.error ?? 'see dashboard'}`, 'Open dashboard').then((a) => a && openDashboard('compare'));
    }
    void refreshStatus();
  });
  ws.on('close', () => { if (projectId) setTimeout(connectSocket, 3000); });
  ws.on('error', () => { /* close handler reconnects */ });
}

async function startMonitoring() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) return void vscode.window.showErrorMessage('Open a folder first.');
  try {
    const s = await call<any>('POST', '/api/projects', { root: folder.uri.fsPath, monitor: true });
    projectId = s.id;
    projectRoot = s.root;
    connectSocket();
    if (poll) clearInterval(poll);
    poll = setInterval(refreshStatus, 10_000);
    render(s);
    if (s.config.error) void vscode.window.showWarningMessage(s.config.error);
    else if (s.config.source === 'default') void vscode.window.showInformationMessage('Monitoring with default settings. Add workbench.config.json to enable website verification.');
  } catch (e) {
    render(null, String((e as Error).message));
    void vscode.window.showErrorMessage(`Could not reach the analysis service at ${base()}: ${(e as Error).message}`);
  }
}

async function stopMonitoring() {
  if (!projectId) return;
  await call('POST', `/api/projects/${projectId}/monitoring`, { enabled: false }).catch(() => {});
  ws?.close();
  ws = null;
  projectId = null;
  render(null);
}

function openDashboard(tab = 'graph') {
  const q = projectId ? `?project=${projectId}&tab=${tab}` : '';
  void vscode.env.openExternal(vscode.Uri.parse(`${base()}/${q}`));
}

function sendBuffer(doc: vscode.TextDocument, content: string | null) {
  const r = rel(doc);
  if (!r || !projectId || !cfg().get('sendUnsavedBuffers')) return;
  void call('POST', `/api/projects/${projectId}/buffer`, { path: r, content }).catch(() => {});
}

async function withProject(fn: (id: string) => Promise<unknown>, done?: string) {
  if (!projectId) await startMonitoring();
  if (!projectId) return;
  try { await fn(projectId); if (done) void vscode.window.showInformationMessage(done); await refreshStatus(); }
  catch (e) { void vscode.window.showErrorMessage((e as Error).message); }
}

export function activate(context: vscode.ExtensionContext) {
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'workbench.openDashboard';
  render(null);
  status.show();

  context.subscriptions.push(
    status,
    vscode.commands.registerCommand('workbench.startMonitoring', startMonitoring),
    vscode.commands.registerCommand('workbench.stopMonitoring', stopMonitoring),
    vscode.commands.registerCommand('workbench.openDashboard', () => openDashboard()),
    vscode.commands.registerCommand('workbench.refresh', () => withProject((id) => call('POST', `/api/projects/${id}/refresh`, { full: false }))),
    vscode.commands.registerCommand('workbench.fullRescan', () => withProject((id) => call('POST', `/api/projects/${id}/refresh`, { full: true }), 'Full rescan complete')),
    vscode.commands.registerCommand('workbench.markBaseline', () => withProject(async (id) => {
      const dirty = vscode.workspace.textDocuments.filter((d) => d.isDirty && rel(d));
      if (dirty.length) {
        const ok = await vscode.window.showWarningMessage(`${dirty.length} file(s) have unsaved changes. The baseline uses files on disk only.`, { modal: true }, 'Mark baseline anyway');
        if (!ok) return;
      }
      const r = await call<any>('POST', `/api/projects/${id}/baseline`);
      void vscode.window.showInformationMessage(`Baseline set: ${r.snapshotId} (${r.fileCount} files)`);
    })),
    vscode.commands.registerCommand('workbench.verify', () => withProject(async (id) => {
      const r = await call<any>('POST', `/api/projects/${id}/verify`);
      void vscode.window.showInformationMessage(r.queued ? 'A run is in progress; one more run is queued.' : 'Website comparison started.', 'Open dashboard').then((a) => a && openDashboard('compare'));
    })),

    // Unsaved buffers: debounced, analysis-only. Saves clear the overlay; the file watcher picks up the disk change.
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (!e.document.isDirty || !rel(e.document)) return;
      const key = e.document.uri.toString();
      clearTimeout(bufferTimers.get(key));
      bufferTimers.set(key, setTimeout(() => sendBuffer(e.document, e.document.getText()), Number(cfg().get('bufferDebounceMs'))));
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => { clearTimeout(bufferTimers.get(doc.uri.toString())); sendBuffer(doc, null); }),
    vscode.workspace.onDidCloseTextDocument((doc) => { clearTimeout(bufferTimers.get(doc.uri.toString())); if (doc.isDirty) sendBuffer(doc, null); }),
  );

  // Reconnect automatically if this folder is already being monitored by the service.
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (folder) {
    call<any[]>('GET', '/api/projects').then((ps) => {
      const p = ps.find((x) => path.resolve(x.root) === path.resolve(folder.uri.fsPath));
      if (p) { projectId = p.id; projectRoot = p.root; connectSocket(); render(p); poll = setInterval(refreshStatus, 10_000); }
    }).catch((e) => render(null, String(e.message)));
  }
}

export function deactivate() {
  ws?.close();
  if (poll) clearInterval(poll);
  for (const t of bufferTimers.values()) clearTimeout(t);
}
