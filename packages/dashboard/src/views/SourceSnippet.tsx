import { useEffect, useState } from 'react';
import { api } from '../api';

export function SourceSnippet({ projectId, file, line, tick }: { projectId: string; file: string; line: number; tick: number }) {
  const [data, setData] = useState<{ from: number; lines: string[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.get<{ from: number; lines: string[] }>(`/api/projects/${projectId}/source?file=${encodeURIComponent(file)}&line=${line}`)
      .then((d) => { setData(d); setErr(null); }).catch((e) => setErr(e.message));
  }, [projectId, file, line, tick]);
  if (err) return <p className="small faint">Source unavailable: {err}</p>;
  if (!data) return null;
  return (
    <div className="code" style={{ marginTop: 10 }} aria-label={`${file} around line ${line}`}>
      {data.lines.map((t, i) => (
        <div key={i} className={data.from + i === line ? 'hit' : ''}><span className="ln">{data.from + i}</span>{t}</div>
      ))}
    </div>
  );
}
