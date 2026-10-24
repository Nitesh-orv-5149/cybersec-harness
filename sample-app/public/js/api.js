export async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status}`), { body });
  return body;
}
