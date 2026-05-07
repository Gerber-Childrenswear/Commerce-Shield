import React, { useEffect, useState } from 'react';

const CACHE_KEY_DISCOUNT = 'cs_discount_config_cache';

function readCache<T>(key: string): { data: T; savedAt: string } | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function writeCache<T>(key: string, data: T) {
  try { localStorage.setItem(key, JSON.stringify({ data, savedAt: new Date().toISOString() })); } catch {}
}

interface DiscountConfig {
  percent: number;
  active: boolean;
  notes: string;
}

const DISCOUNT_DEFAULTS: DiscountConfig = { percent: 10, active: true, notes: '' };

export const DiscountManager: React.FC = () => {
  const [config, setConfig] = useState<DiscountConfig>(DISCOUNT_DEFAULTS);
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [staleAt, setStaleAt] = useState<string>('');

  useEffect(() => {
    fetch('/api/config')
      .then(res => {
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        return res.json();
      })
      .then(body => {
        const fresh = body.config || DISCOUNT_DEFAULTS;
        setConfig(fresh);
        writeCache(CACHE_KEY_DISCOUNT, fresh);
      })
      .catch(() => {
        const cached = readCache<DiscountConfig>(CACHE_KEY_DISCOUNT);
        if (cached) {
          setConfig(cached.data);
          setStaleAt(cached.savedAt);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { id, value } = e.target;
    setConfig(cfg => ({
      ...cfg,
      [id]: id === 'percent' ? Number(value) : id === 'active' ? value === 'true' : value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('');
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (res.ok) setStatus('Saved.');
    else setStatus('Error: ' + (await res.text()));
  };

  if (loading) return <div style={{ color: 'var(--gcw-subtext)', textAlign: 'center', marginTop: 48 }}>Loading...</div>;

  return (
    <div className="section card stack" style={{ maxWidth: 480, margin: '0 auto' }}>
      {staleAt && <div style={{ fontSize: 13, color: 'var(--gcw-subtext)', background: 'var(--gcw-bg-secondary)', padding: '6px 10px', borderRadius: 4, marginBottom: 12 }}>Backend unavailable — showing data from {new Date(staleAt).toLocaleString()}. Changes cannot be saved right now.</div>}
      <form id="configForm" onSubmit={handleSubmit} className="stack" style={{ gap: 0 }}>
        <label htmlFor="percent">Discount Percent (0-100)</label>
        <input id="percent" type="number" min="0" max="100" value={config.percent} onChange={handleChange} style={{ width: '100%' }} />

        <label htmlFor="active">Active</label>
        <select id="active" value={String(config.active)} onChange={handleChange} style={{ width: '100%' }}>
          <option value="true">true</option>
          <option value="false">false</option>
        </select>

        <label htmlFor="notes">Notes (optional)</label>
        <textarea id="notes" rows={4} value={config.notes} onChange={handleChange} style={{ width: '100%' }} />

        <button type="submit" style={{ marginTop: 16 }} disabled={!!staleAt}>Save</button>
      </form>
      <div className="status" style={{ color: status.startsWith('Error') ? 'var(--gcw-sale)' : 'var(--gcw-btn)', marginTop: 8 }}>{status}</div>
    </div>
  );
};
