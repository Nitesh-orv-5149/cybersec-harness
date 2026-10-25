import { useState } from 'react';
import { Icon } from './icons';

/** A copyable shell command, styled like a terminal prompt. */
export function TerminalLine({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard?.writeText(cmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1400); }).catch(() => {});
  return (
    <div className="term">
      <span className="term-prompt">$</span>
      <code className="term-cmd">{cmd}</code>
      <button className="term-copy" onClick={copy} aria-label={copied ? 'Copied' : 'Copy command'}>{copied ? <Icon.check /> : <Icon.copy />}</button>
    </div>
  );
}
