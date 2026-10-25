// Evidence redaction for web-scan results. Request/response dumps, curl commands and extracted values can carry
// cookies, tokens and credentials (of the scanned app, or found by an exposure template). They are redacted before
// anything is persisted, logged or shown. Redaction keeps the structure (header names, parameter names, lengths)
// so the evidence stays useful.
import { redact } from '../../util.js';

const SENSITIVE_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-amz-security-token|x-access-token)$|token|secret|session|passw|api[-_]?key|auth/i;
const SENSITIVE_PARAM = /^(token|access_token|refresh_token|id_token|secret|client_secret|password|passwd|pwd|pass|api[_-]?key|apikey|key|auth|session|sessionid|sid|jwt|signature|sig|code)$/i;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const AWS_KEY = /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g;

export const MASK = '***';

/** Mask a value but keep a little shape: first 3 characters and the length. */
export function maskValue(v: string): string {
  if (v.length <= 4) return MASK;
  return `${v.slice(0, 3)}${MASK}(${v.length} chars)`;
}

function redactQuery(url: string): string {
  return url.replace(/([?&])([^=&#\s'"]+)=([^&#\s'"]*)/g, (m, sep: string, k: string, v: string) => (SENSITIVE_PARAM.test(decodeSafe(k)) && v ? `${sep}${k}=${MASK}` : m));
}

function decodeSafe(s: string) { try { return decodeURIComponent(s); } catch { return s; } }

function redactCommon(s: string): string {
  return redact(s).replace(JWT, `${MASK}jwt`).replace(PRIVATE_KEY, `${MASK}private-key`).replace(AWS_KEY, `${MASK}aws-key`);
}

/** An HTTP request or response dump: headers by name, then query strings and body-level patterns. */
export function redactHttpDump(dump: string): string {
  const lines = dump.split(/\r?\n/);
  let inHeaders = true;
  const out = lines.map((line, i) => {
    if (i === 0) return redactQuery(line);
    if (inHeaders) {
      if (line === '') { inHeaders = false; return line; }
      const m = line.match(/^([A-Za-z0-9-]+):\s?(.*)$/);
      if (m && SENSITIVE_HEADER.test(m[1]!)) return `${m[1]}: ${MASK}`;
      return line;
    }
    // Body: form-encoded and JSON credentials.
    return line
      .replace(/("(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_?key|apikey|client_secret|session(?:id)?|jwt|authorization)"\s*:\s*)"[^"]*"/gi, `$1"${MASK}"`)
      .replace(/(^|&)((?:password|passwd|pwd|secret|token|api_?key|session(?:id)?)=)[^&\s]*/gi, `$1$2${MASK}`);
  });
  return redactCommon(out.join('\n'));
}

/** curl reproduction commands: -H 'Name: value', -b/--cookie, -u/--user and the URL. */
export function redactCurl(cmd: string): string {
  return redactCommon(redactQuery(cmd)
    .replace(/(-H\s+)(['"])([A-Za-z0-9-]+):\s?([^'"]*)\2/g, (m, flag: string, q: string, name: string) => (SENSITIVE_HEADER.test(name) ? `${flag}${q}${name}: ${MASK}${q}` : m))
    .replace(/(\s(?:-b|--cookie|-u|--user)\s+)(['"]?)[^'"\s]+\2/g, `$1$2${MASK}$2`));
}

export function redactUrl(u: string): string {
  return redactCommon(redactQuery(u));
}

/** Values extracted by a template. Anything that looks like a credential, or comes from a template about secrets, is masked. */
export function redactExtracted(values: string[], templateHints: string): string[] {
  const secretTemplate = /token|secret|key|password|passwd|credential|session|cookie|jwt|bearer|private|auth/i.test(templateHints);
  return values.map((v) => {
    const r = redactCommon(v);
    if (r !== v) return r;
    const looksLikeCredential = v.length >= 16 && /^[A-Za-z0-9+/=_\-.]+$/.test(v) && /[A-Za-z]/.test(v) && /\d/.test(v);
    return secretTemplate || looksLikeCredential ? maskValue(v) : v;
  });
}

export function truncate(s: string, max: number): { text: string; truncated: boolean } {
  return s.length > max ? { text: `${s.slice(0, max)}\n[…truncated ${s.length - max} characters…]`, truncated: true } : { text: s, truncated: false };
}
