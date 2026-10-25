// Inline SVG icons (Lucide geometry, 24px grid, stroke = currentColor). Decorative: aria-hidden.
import type { ReactNode } from 'react';

const Svg = ({ children, size = 16 }: { children: ReactNode; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>
);

export const Icon = {
  overview: () => <Svg><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></Svg>,
  graph: () => <Svg><circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" /><path d="m8.59 13.51 6.83 3.98M15.41 6.51l-6.82 3.98" /></Svg>,
  findings: () => <Svg><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" /><path d="M12 9v4M12 17h.01" /></Svg>,
  reach: () => <Svg><circle cx="6" cy="19" r="3" /><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15" /><circle cx="18" cy="5" r="3" /></Svg>,
  compare: () => <Svg><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M12 3v18" /></Svg>,
  security: () => <Svg><path d="M16.5 9.4 7.55 4.24" /><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><path d="M3.27 6.96 12 12.01l8.73-5.05M12 22.08V12" /></Svg>,
  scans: () => <Svg><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></Svg>,
  agent: () => <Svg><rect x="3" y="11" width="18" height="10" rx="2" /><circle cx="12" cy="5" r="2" /><path d="M12 7v4M8 16h.01M16 16h.01" /></Svg>,
  history: () => <Svg><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" /><path d="M3 3v5h5M12 7v5l4 2" /></Svg>,
  search: () => <Svg><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></Svg>,
  folder: () => <Svg><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" /></Svg>,
  git: () => <Svg><circle cx="12" cy="12" r="3" /><path d="M3 12h6M15 12h6" /></Svg>,
  copy: () => <Svg size={14}><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></Svg>,
  check: () => <Svg size={14}><path d="M20 6 9 17l-5-5" /></Svg>,
  enter: () => <Svg size={13}><path d="M9 10 4 15l5 5" /><path d="M20 4v7a4 4 0 0 1-4 4H4" /></Svg>,
};

/** Brand mark: a shield whose inner node-graph hints at "code impact". */
export const Logo = ({ size = 26 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
    <defs>
      <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#0a84ff" /><stop offset="1" stopColor="#bf5af2" /></linearGradient>
    </defs>
    <path d="M16 2.5 4.5 6.8v8.4c0 7.2 5 12 11.5 14.3 6.5-2.3 11.5-7.1 11.5-14.3V6.8z" fill="url(#lg)" opacity="0.14" stroke="url(#lg)" strokeWidth="1.6" />
    <circle cx="11.5" cy="12" r="2" fill="#64d2ff" /><circle cx="20.5" cy="12" r="2" fill="#da8fff" /><circle cx="16" cy="20" r="2.2" fill="#f5f5f7" />
    <path d="M11.5 12 16 20l4.5-8" fill="none" stroke="#f5f5f7" strokeOpacity="0.55" strokeWidth="1.3" />
  </svg>
);
