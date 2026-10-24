import crypto from 'node:crypto';

export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function shortHash(data: string | Buffer, len = 12): string {
  return sha256(data).slice(0, len);
}

export function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}${crypto.randomBytes(4).toString('hex')}`;
}

export function now(): Date {
  return new Date();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Keep the tail of a stream of text bounded. */
export class OutputBuffer {
  private chunks: string[] = [];
  private size = 0;
  truncated = false;
  constructor(private readonly limit = 64 * 1024) {}
  push(s: string) {
    this.chunks.push(s);
    this.size += s.length;
    while (this.size > this.limit && this.chunks.length > 1) {
      this.size -= this.chunks.shift()!.length;
      this.truncated = true;
    }
  }
  toString() {
    return (this.truncated ? '[…output truncated…]\n' : '') + this.chunks.join('');
  }
}

/** Strip obvious credentials from strings before logging or persisting them. */
export function redact(s: string): string {
  return s
    .replace(/(https?:\/\/)([^:@/\s]+):([^@/\s]+)@/g, '$1$2:***@')
    .replace(/\b(token|secret|password|passwd|api[_-]?key|authorization)=([^&\s]+)/gi, '$1=***')
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/-]+=*/g, '$1 ***');
}
