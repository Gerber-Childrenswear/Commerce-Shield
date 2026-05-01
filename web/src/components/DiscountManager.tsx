import React, { useEffect, useState } from 'react';

interface DiscountConfig {
  percent: number;
  active: boolean;
  notes: string;
}

export const DiscountManager: React.FC = () => {
  const [config, setConfig] = useState<DiscountConfig>({ percent: 10, active: true, notes: '' });
  const [status, setStatus] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetch('/api/config')
      .then(res => res.json())
      .then(body => setConfig(body.config || { percent: 10, active: true, notes: '' }))
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

        <button type="submit" style={{ marginTop: 16 }}>Save</button>
      </form>
      <div className="status" style={{ color: status.startsWith('Error') ? 'var(--gcw-sale)' : 'var(--gcw-btn)', marginTop: 8 }}>{status}</div>
    </div>
  );
};
