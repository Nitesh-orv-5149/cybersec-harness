// JavaScript / TypeScript adapter built on the TypeScript compiler API (AST, not regex).
// Supported framework path: Express-style routers (app/router.get|post|... and app.use(prefix, router)).
import ts from 'typescript';
import type {
  CallFact, CalleeRef, DeclFact, FileFacts, ImportBinding, LanguageAdapter, ParseOptions,
  RenderFact, RequestFact, RouteFact, SinkFact, SinkKind,
} from './types.js';
import { shortHash } from '../util.js';

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'head', 'options']);
const CHILD_PROCESS_FNS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']);
const FS_PATH_FNS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream',
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'appendFile', 'appendFileSync', 'readdir', 'readdirSync', 'open', 'openSync',
]);
const SQL_FNS = new Set(['query', 'execute', 'raw', 'exec', '$queryRawUnsafe', '$executeRawUnsafe']);
const HTTP_CLIENT_OBJECTS = new Set(['axios', 'http', 'https', 'got', 'superagent', 'request']);
const AUTH_HINT = /auth|login|session|jwt|token|permission|role|guard|protect|verify/i;
const SANITIZE_HINT = /sanitiz|escape|validat|\.replace\(\s*\/|parseInt\(|Number\(|encodeURI/i;

function kindFor(file: string): ts.ScriptKind {
  if (file.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (file.endsWith('.ts') || file.endsWith('.mts') || file.endsWith('.cts')) return ts.ScriptKind.TS;
  if (file.endsWith('.jsx')) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function isTestFile(file: string): boolean {
  return /(^|\/)(tests?|__tests__)\//.test(file) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(file);
}

function stringValue(n: ts.Node | undefined): string | null {
  if (!n) return null;
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  return null;
}

function isLiteralish(n: ts.Expression): boolean {
  return ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isNumericLiteral(n);
}

function isFunctionLike(n: ts.Node | undefined): n is ts.ArrowFunction | ts.FunctionExpression {
  return !!n && (ts.isArrowFunction(n) || ts.isFunctionExpression(n));
}

function paramNames(fn: ts.SignatureDeclarationBase): string[] {
  const out: string[] = [];
  for (const p of fn.parameters) if (ts.isIdentifier(p.name)) out.push(p.name.text);
  return out;
}

export const jsAdapter: LanguageAdapter = {
  id: 'typescript-compiler-api',
  extensions: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx'],

  parse(file: string, text: string, opts: ParseOptions): FileFacts {
    const facts: FileFacts = {
      file,
      hash: shortHash(text),
      language: kindFor(file) === ts.ScriptKind.TS || kindFor(file) === ts.ScriptKind.TSX ? 'typescript' : 'javascript',
      isTest: isTestFile(file),
      isClient: opts.isClient,
      imports: [], exports: {}, decls: [], objectVars: [], routerVars: {},
      calls: [], routes: [], mounts: [], sinks: [], requests: [], renders: [],
    };

    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kindFor(file));
    const diags = (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics;
    if (diags && diags.length) {
      facts.parseError = ts.flattenDiagnosticMessageText(diags[0].messageText, '\n');
    }

    const line = (n: ts.Node) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
    const endLine = (n: ts.Node) => sf.getLineAndCharacterOfPosition(n.getEnd()).line + 1;
    const nodeHash = (n: ts.Node) => shortHash(n.getText(sf).replace(/\s+/g, ' '));
    const declNames = new Set<string>();
    let sinkOrdinal = 0;

    // ---- pass 1: imports / requires / exports (module-level only) ----
    const addImport = (b: ImportBinding) => facts.imports.push(b);
    for (const st of sf.statements) {
      if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
        const spec = st.moduleSpecifier.text;
        const ic = st.importClause;
        if (ic?.name) addImport({ local: ic.name.text, spec, imported: 'default', line: line(st) });
        const nb = ic?.namedBindings;
        if (nb && ts.isNamespaceImport(nb)) addImport({ local: nb.name.text, spec, imported: '*', line: line(st) });
        if (nb && ts.isNamedImports(nb)) {
          for (const el of nb.elements) {
            addImport({ local: el.name.text, spec, imported: (el.propertyName ?? el.name).text, line: line(st) });
          }
        }
      }
      if (ts.isVariableStatement(st)) {
        for (const d of st.declarationList.declarations) {
          const init = d.initializer;
          if (init && ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === 'require') {
            const spec = stringValue(init.arguments[0]);
            if (!spec) continue;
            if (ts.isIdentifier(d.name)) addImport({ local: d.name.text, spec, imported: '*', line: line(st) });
            if (ts.isObjectBindingPattern(d.name)) {
              for (const el of d.name.elements) {
                if (ts.isIdentifier(el.name)) {
                  const imported = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
                  addImport({ local: el.name.text, spec, imported, line: line(st) });
                }
              }
            }
          }
        }
      }
      const exported = ts.canHaveModifiers(st) && ts.getModifiers(st)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
      const isDefault = ts.canHaveModifiers(st) && ts.getModifiers(st)?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
      if (exported) {
        if ((ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) && st.name) {
          facts.exports[isDefault ? 'default' : st.name.text] = st.name.text;
        } else if (ts.isVariableStatement(st)) {
          for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) facts.exports[d.name.text] = d.name.text;
        }
      }
      if (ts.isExportAssignment(st) && ts.isIdentifier(st.expression)) facts.exports.default = st.expression.text;
      if (ts.isExportDeclaration(st) && st.exportClause && ts.isNamedExports(st.exportClause) && !st.moduleSpecifier) {
        for (const el of st.exportClause.elements) facts.exports[el.name.text] = (el.propertyName ?? el.name).text;
      }
      // module.exports = { a, b } / module.exports.x = fn
      if (ts.isExpressionStatement(st) && ts.isBinaryExpression(st.expression) && st.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = st.expression.left.getText(sf);
        const right = st.expression.right;
        if (left === 'module.exports' && ts.isObjectLiteralExpression(right)) {
          for (const p of right.properties) {
            if (ts.isShorthandPropertyAssignment(p)) facts.exports[p.name.text] = p.name.text;
            if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && ts.isIdentifier(p.initializer)) facts.exports[p.name.text] = p.initializer.text;
          }
        } else if (left === 'module.exports' && ts.isIdentifier(right)) {
          facts.exports.default = right.text;
        }
      }
    }

    const importOf = (local: string) => facts.imports.find((i) => i.local === local);
    const moduleOf = (local: string): string | null => {
      const imp = importOf(local);
      return imp ? imp.spec.replace(/^node:/, '') : null;
    };

    // ---- helpers for pass 2 ----
    const declStack: { qname: string; params: string[] }[] = [];
    const current = () => (declStack.length ? declStack[declStack.length - 1] : null);

    const addDecl = (qname: string, kind: DeclFact['kind'], node: ts.Node, fn?: ts.SignatureDeclarationBase): string => {
      let q = qname;
      let i = 2;
      while (declNames.has(q)) q = `${qname}#${i++}`;
      declNames.add(q);
      const textBody = node.getText(sf);
      facts.decls.push({
        qname: q, kind, line: line(node), endLine: endLine(node), hash: nodeHash(node),
        params: fn ? paramNames(fn) : [],
        sanitizationHint: SANITIZE_HINT.exec(textBody)?.[0],
      });
      return q;
    };

    const withDecl = (qname: string, params: string[], body: ts.Node | undefined) => {
      if (!body) return;
      declStack.push({ qname, params });
      visit(body);
      declStack.pop();
    };

    const calleeRef = (expr: ts.Expression): CalleeRef => {
      if (ts.isIdentifier(expr)) return { kind: 'ident', name: expr.text };
      if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) {
        return { kind: 'member', object: expr.expression.text, prop: expr.name.text };
      }
      return { kind: 'other', text: expr.getText(sf).slice(0, 80) };
    };

    const recordSink = (sinkKind: SinkKind, callee: string, node: ts.Node, arg: ts.Expression | undefined) => {
      const argText = arg ? arg.getText(sf).slice(0, 160) : '';
      const cur = current();
      const ids = new Set<string>();
      if (arg) {
        const collect = (n: ts.Node) => { if (ts.isIdentifier(n)) ids.add(n.text); ts.forEachChild(n, collect); };
        collect(arg);
      }
      facts.sinks.push({
        from: cur?.qname ?? null,
        sinkKind, callee, line: line(node), ordinal: sinkOrdinal++, argText,
        directRequestInput: /\breq(uest)?\.(query|params|body|headers|cookies)\b/.test(argText),
        paramsUsed: cur ? cur.params.filter((p) => ids.has(p)) : [],
      });
    };

    // Local variables whose value is built from a template literal or string concatenation
    // (const sql = `... ${id}`; db.query(sql)). Keyed by enclosing declaration.
    const builtStrings = new Map<string, ts.Expression>();
    const isStringBuild = (e: ts.Expression) =>
      ts.isTemplateExpression(e) || (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken);
    const resolveBuilt = (e: ts.Expression | undefined): ts.Expression | undefined => {
      if (e && ts.isIdentifier(e)) return builtStrings.get(`${current()?.qname ?? ''}|${e.text}`);
      return undefined;
    };

    const isDynamic = (arg: ts.Expression | undefined): boolean => {
      if (!arg) return false;
      if (isLiteralish(arg)) return false;
      if (ts.isTemplateExpression(arg)) return true;
      return true;
    };

    const checkSinkCall = (call: ts.CallExpression) => {
      const expr = call.expression;
      const arg0 = call.arguments[0];
      // eval(x)
      if (ts.isIdentifier(expr) && expr.text === 'eval' && isDynamic(arg0)) return recordSink('code_exec', 'eval', call, arg0);
      // exec(...) imported from child_process
      if (ts.isIdentifier(expr) && CHILD_PROCESS_FNS.has(expr.text)) {
        const imp = importOf(expr.text);
        if (imp && imp.spec.replace(/^node:/, '') === 'child_process' && isDynamic(arg0)) return recordSink('command_exec', expr.text, call, arg0);
      }
      if (ts.isPropertyAccessExpression(expr)) {
        const prop = expr.name.text;
        const obj = ts.isIdentifier(expr.expression) ? expr.expression.text : null;
        const mod = obj ? moduleOf(obj) : null;
        if (mod === 'child_process' && CHILD_PROCESS_FNS.has(prop) && isDynamic(arg0)) return recordSink('command_exec', `${obj}.${prop}`, call, arg0);
        if ((mod === 'fs' || mod === 'fs/promises' || expr.expression.getText(sf).endsWith('fs.promises')) && FS_PATH_FNS.has(prop) && isDynamic(arg0)) {
          return recordSink('path_access', `${expr.expression.getText(sf)}.${prop}`, call, arg0);
        }
        if (SQL_FNS.has(prop) && arg0 && isStringBuild(arg0)) {
          return recordSink('sql_dynamic', `${expr.expression.getText(sf)}.${prop}`, call, arg0);
        }
        const built = SQL_FNS.has(prop) ? resolveBuilt(arg0) : undefined;
        if (built) return recordSink('sql_dynamic', `${expr.expression.getText(sf)}.${prop}`, call, built);
        if (opts.isClient && prop === 'write' && expr.expression.getText(sf) === 'document' && isDynamic(arg0)) return recordSink('dom_xss', 'document.write', call, arg0);
        if (opts.isClient && prop === 'insertAdjacentHTML' && isDynamic(call.arguments[1])) return recordSink('dom_xss', 'insertAdjacentHTML', call, call.arguments[1]);
        if (!opts.isClient && obj && HTTP_CLIENT_OBJECTS.has(obj) && ['get', 'post', 'put', 'delete', 'request'].includes(prop) && isDynamic(arg0)) {
          return recordSink('ssrf', `${obj}.${prop}`, call, arg0);
        }
      }
      if (!opts.isClient && ts.isIdentifier(expr) && expr.text === 'fetch' && isDynamic(arg0)) return recordSink('ssrf', 'fetch', call, arg0);
    };

    const checkRequest = (call: ts.CallExpression) => {
      const url = stringValue(call.arguments[0]) ?? (call.arguments[0] && ts.isTemplateExpression(call.arguments[0]) ? call.arguments[0].head.text + ':param' : null);
      if (!url || !(url.startsWith('/') || /^https?:\/\//.test(url))) return;
      let method = 'GET';
      const expr = call.expression;
      if (ts.isPropertyAccessExpression(expr) && HTTP_METHODS.has(expr.name.text)) method = expr.name.text.toUpperCase();
      const opt = call.arguments[1];
      if (opt && ts.isObjectLiteralExpression(opt)) {
        for (const p of opt.properties) {
          if (ts.isPropertyAssignment(p) && p.name.getText(sf) === 'method') {
            const v = stringValue(p.initializer);
            if (v) method = v.toUpperCase();
          }
        }
      }
      facts.requests.push({ from: current()?.qname ?? null, url, method, line: line(call) } satisfies RequestFact);
    };

    const handleRouteCall = (call: ts.CallExpression): boolean => {
      const expr = call.expression;
      if (!ts.isPropertyAccessExpression(expr) || !ts.isIdentifier(expr.expression)) return false;
      const receiver = expr.expression.text;
      const method = expr.name.text;
      const known = receiver in facts.routerVars || /^(app|router|api|server)$/i.test(receiver);
      if (!known) return false;
      const path = stringValue(call.arguments[0]);
      if (method === 'use' && path && call.arguments[1] && ts.isIdentifier(call.arguments[call.arguments.length - 1])) {
        const target = (call.arguments[call.arguments.length - 1] as ts.Identifier).text;
        facts.mounts.push({ receiver, prefix: path, target, line: line(call) });
        return true;
      }
      if (!HTTP_METHODS.has(method) || path === null) return false;
      const args = call.arguments.slice(1);
      const middleware: string[] = [];
      let handler: RouteFact['handler'] = null;
      args.forEach((a, idx) => {
        const last = idx === args.length - 1;
        if (last) {
          if (ts.isIdentifier(a)) handler = { kind: 'ident', name: a.text };
          else if (ts.isPropertyAccessExpression(a) && ts.isIdentifier(a.expression)) handler = { kind: 'member', object: a.expression.text, prop: a.name.text };
          else if (isFunctionLike(a)) {
            const q = addDecl(`route ${method.toUpperCase()} ${path}`, 'handler', a, a);
            handler = { kind: 'inline', qname: q };
            withDecl(q, paramNames(a), a.body);
          }
        } else {
          middleware.push(a.getText(sf).slice(0, 60));
          if (!ts.isIdentifier(a)) visit(a);
        }
      });
      facts.routes.push({ receiver, method: method.toUpperCase(), path, handler, middleware, line: line(call), hash: nodeHash(call) });
      return true;
    };

    const handleTestCall = (call: ts.CallExpression): boolean => {
      if (!facts.isTest || !ts.isIdentifier(call.expression) || !['test', 'it'].includes(call.expression.text)) return false;
      const title = stringValue(call.arguments[0]);
      const fn = call.arguments.find(isFunctionLike);
      if (!title || !fn) return false;
      const q = addDecl(`test: ${title}`, 'test', call, fn);
      withDecl(q, [], fn.body);
      return true;
    };

    const visit = (n: ts.Node): void => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && isStringBuild(n.initializer)) {
        builtStrings.set(`${current()?.qname ?? ''}|${n.name.text}`, n.initializer);
      }
      if (ts.isCallExpression(n)) {
        if (handleRouteCall(n)) return;
        if (handleTestCall(n)) return;
        const callee = calleeRef(n.expression);
        facts.calls.push({ from: current()?.qname ?? null, callee, line: line(n) } satisfies CallFact);
        checkSinkCall(n);
        checkRequest(n);
        // identifiers passed as callbacks: addEventListener('submit', submitOrder)
        for (const a of n.arguments) {
          if (ts.isIdentifier(a)) facts.calls.push({ from: current()?.qname ?? null, callee: { kind: 'ident', name: a.text }, line: line(a), asReference: true });
        }
      }
      if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'Function') {
        recordSink('code_exec', 'new Function', n, n.arguments?.[n.arguments.length - 1]);
      }
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && opts.isClient
        && ts.isPropertyAccessExpression(n.left) && ['innerHTML', 'outerHTML'].includes(n.left.name.text) && isDynamic(n.right)) {
        recordSink('dom_xss', n.left.name.text, n, n.right);
      }
      if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && ts.isIdentifier(n.tagName) && /^[A-Z]/.test(n.tagName.text)) {
        facts.renders.push({ from: current()?.qname ?? null, tag: n.tagName.text, line: line(n) } satisfies RenderFact);
      }
      ts.forEachChild(n, visit);
    };

    // ---- pass 2: declarations and bodies ----
    for (const st of sf.statements) {
      if (ts.isImportDeclaration(st)) continue;
      if (ts.isFunctionDeclaration(st) && st.name) {
        const q = addDecl(st.name.text, 'function', st, st);
        withDecl(q, paramNames(st), st.body);
        continue;
      }
      if (ts.isClassDeclaration(st) && st.name) {
        for (const m of st.members) {
          if ((ts.isMethodDeclaration(m) || ts.isConstructorDeclaration(m)) && m.body) {
            const mname = ts.isConstructorDeclaration(m) ? 'constructor' : m.name.getText(sf);
            const q = addDecl(`${st.name.text}.${mname}`, 'function', m, m);
            withDecl(q, paramNames(m), m.body);
          }
        }
        continue;
      }
      if (ts.isVariableStatement(st)) {
        for (const d of st.declarationList.declarations) {
          const init = d.initializer;
          if (!init || !ts.isIdentifier(d.name)) { if (init) visit(init); continue; }
          const name = d.name.text;
          if (isFunctionLike(init)) {
            const q = addDecl(name, 'function', d, init);
            withDecl(q, paramNames(init), init.body);
          } else if (ts.isObjectLiteralExpression(init)) {
            facts.objectVars.push(name);
            for (const p of init.properties) {
              if (ts.isMethodDeclaration(p) && p.body) {
                const q = addDecl(`${name}.${p.name.getText(sf)}`, 'function', p, p);
                withDecl(q, paramNames(p), p.body);
              } else if (ts.isPropertyAssignment(p) && isFunctionLike(p.initializer)) {
                const q = addDecl(`${name}.${p.name.getText(sf)}`, 'function', p, p.initializer);
                withDecl(q, paramNames(p.initializer), p.initializer.body);
              } else {
                visit(p);
              }
            }
          } else {
            const t = init.getText(sf);
            if (/^(express\.)?Router\(\s*\)$/.test(t)) facts.routerVars[name] = 'router';
            else if (/^express\(\s*\)$/.test(t) || /^(fastify|Fastify)\(/.test(t)) facts.routerVars[name] = 'app';
            if (!(ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === 'require')) visit(init);
          }
        }
        continue;
      }
      if (ts.isExportAssignment(st)) {
        if (isFunctionLike(st.expression)) {
          const q = addDecl('default', 'function', st, st.expression);
          facts.exports.default = q;
          withDecl(q, paramNames(st.expression), st.expression.body);
        } else visit(st.expression);
        continue;
      }
      visit(st);
    }

    return facts;
  },
};

export { AUTH_HINT };
