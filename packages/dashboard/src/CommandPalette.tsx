import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './icons';

export interface Command { id: string; label: string; group: string; icon?: ReactNode; hint?: string; run: () => void }

/** ⌘K palette: type to filter, ↑/↓ to move, Enter to run, Esc to close. */
export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  useEffect(() => { if (open) { setQ(''); setActive(0); requestAnimationFrame(() => inputRef.current?.focus()); } }, [open]);

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return commands;
    // Rank: prefix > word-start > substring > subsequence ("dep sc" still finds "Dependency scan").
    const score = (label: string) => {
      const hay = label.toLowerCase();
      if (hay.startsWith(needle)) return 0;
      if (hay.split(/\s+/).some((w) => w.startsWith(needle))) return 1;
      if (hay.includes(needle)) return 2;
      let i = 0;
      for (const ch of needle.replace(/\s+/g, '')) { i = hay.indexOf(ch, i); if (i < 0) return -1; i++; }
      return 3;
    };
    return commands.map((c) => ({ c, s: score(c.label) })).filter((r) => r.s >= 0)
      .sort((a, b) => a.s - b.s).map((r) => r.c);
  }, [q, commands]);

  useEffect(() => { setActive(0); }, [q]);
  useEffect(() => { listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' }); }, [active]);

  if (!open) return null;

  const run = (c?: Command) => { if (!c) return; onClose(); c.run(); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(results.length - 1, a + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); run(results[active]); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };

  let lastGroup = '';
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <div className="palette-input">
          <Icon.search />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to a view or run a command…"
            role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={results[active] ? `cmd-${results[active].id}` : undefined} />
          <kbd>esc</kbd>
        </div>
        <ul className="palette-list" id="palette-list" role="listbox" ref={listRef}>
          {results.length === 0 && <li className="palette-empty">No matching commands</li>}
          {results.map((c, i) => {
            // group headings only for the unfiltered list; a ranked list would repeat them
            const head = !q.trim() && c.group !== lastGroup ? (lastGroup = c.group) : null;
            return (
              <li key={c.id} role="presentation">
                {head && <div className="palette-group">{head}</div>}
                <div id={`cmd-${c.id}`} role="option" aria-selected={i === active} className="palette-item"
                  onMouseMove={() => setActive(i)} onClick={() => run(c)}>
                  <span className="palette-icon">{c.icon}</span>
                  <span className="palette-label">{c.label}</span>
                  {c.hint && <kbd>{c.hint}</kbd>}
                  {i === active && <span className="palette-enter"><Icon.enter /></span>}
                </div>
              </li>
            );
          })}
        </ul>
        <div className="palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div>
      </div>
    </div>
  );
}
