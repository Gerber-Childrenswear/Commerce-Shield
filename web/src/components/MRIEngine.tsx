import React, { useEffect, useState } from 'react';

const CACHE_KEY_METRICS = 'cs_mri_metrics_cache';
const CACHE_KEY_MRI_CONFIG = 'cs_mri_config_cache';

function readCache<T>(key: string): { data: T; savedAt: string } | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function writeCache<T>(key: string, data: T) {
  try { localStorage.setItem(key, JSON.stringify({ data, savedAt: new Date().toISOString() })); } catch {}
}

interface MRIMetrics {
  revenue_saved: number;
  conversion_lift: number;
  coupon_abuse_prevented: number;
  bot_traffic_blocked: number;
  channel_breakdown: Array<{ channel: string; discounts_given: number; no_discount: number }>;
}

interface MRIConfig {
  enabled: boolean;
  ui_mode: string;
  discount_optimization: boolean;
  coupon_abuse_prevention: boolean;
  bot_protection: boolean;
  profit_maximization: boolean;
}

const MRI_DEFAULTS: MRIConfig = {
  enabled: false,
  ui_mode: 'bloomreach',
  discount_optimization: false,
  coupon_abuse_prevention: false,
  bot_protection: false,
  profit_maximization: false,
};

const METRICS_DEFAULTS: MRIMetrics = {
  revenue_saved: 0,
  conversion_lift: 0,
  coupon_abuse_prevented: 0,
  bot_traffic_blocked: 0,
  channel_breakdown: [],
};

export const MRIEngine: React.FC = () => {
  const [metrics, setMetrics] = useState<MRIMetrics | null>(null);
  const [config, setConfig] = useState<MRIConfig | null>(null);
  const [status, setStatus] = useState('');
  const [staleAt, setStaleAt] = useState('');
  const [aiOverview, setAIOverview] = useState<string[]>([]);
  const [aiLoading, setAILoading] = useState(false);

  useEffect(() => {
    fetchMetrics();
    fetchConfig();
    fetchAIOverview();
  }, []);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
        writeCache(CACHE_KEY_METRICS, data);
      } else throw new Error(`${res.status}`);
    } catch {
      const cached = readCache<MRIMetrics>(CACHE_KEY_METRICS);
      setMetrics(cached ? cached.data : METRICS_DEFAULTS);
      if (cached && !staleAt) setStaleAt(cached.savedAt);
    }
  };
  const fetchConfig = async () => {
    try {
      const res = await fetch('/api/mri-config');
      if (res.ok) {
        const data = await res.json();
        setConfig(data);
        writeCache(CACHE_KEY_MRI_CONFIG, data);
      } else throw new Error(`${res.status}`);
    } catch {
      const cached = readCache<MRIConfig>(CACHE_KEY_MRI_CONFIG);
      setConfig(cached ? cached.data : MRI_DEFAULTS);
      if (cached && !staleAt) setStaleAt(cached.savedAt);
    }
  };
  const fetchAIOverview = async () => {
    setAILoading(true);
    try {
      const res = await fetch('/api/mri-overview');
      if (res.ok) {
        const data = await res.json();
        setAIOverview(data.issues || []);
      }
    } catch {
      // non-critical — leave aiOverview empty
    } finally {
      setAILoading(false);
    }
  };
  const handleConfigChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { id, value, type } = e.target;
    let newValue: string | boolean = value;
    if (type === 'checkbox') {
      newValue = (e.target as HTMLInputElement).checked;
    }
    setConfig(cfg => cfg ? { ...cfg, [id]: newValue } : null);
  };
  const handleSave = async () => {
    if (!config) return;
    setStatus('');
    const res = await fetch('/api/mri-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (res.ok) setStatus('Settings saved.');
    else setStatus('Error saving settings.');
  };
  if (!metrics || !config) return <div style={{ color: 'var(--gcw-subtext)', textAlign: 'center', marginTop: 48 }}>Loading...</div>;
  return (
    <div className="section card stack" style={{ maxWidth: 800, margin: '0 auto' }}>
      <h2 style={{ color: 'var(--gcw-text)' }}>Conversion MRI Engine</h2>
      {staleAt && <div style={{ fontSize: 13, color: 'var(--gcw-subtext)', background: 'var(--gcw-bg-secondary)', padding: '6px 10px', borderRadius: 4, marginBottom: 12 }}>Backend unavailable — showing data from {new Date(staleAt).toLocaleString()}.</div>}
      <div style={{ background: 'var(--gcw-bg-secondary)', padding: 16, borderRadius: 8, marginBottom: 24 }}>
        <h3 style={{ color: 'var(--gcw-text)' }}>AI Overview</h3>
        {aiLoading ? <div style={{ color: 'var(--gcw-subtext)' }}>Loading AI insights...</div> : aiOverview.length > 0 ? (
          <ul>{aiOverview.map((issue, i) => <li key={i}>{issue}</li>)}</ul>
        ) : <div style={{ color: 'var(--gcw-subtext)' }}>No issues detected. All systems healthy.</div>}
      </div>
      <div>
        <h3 style={{ color: 'var(--gcw-text)' }}>Key Metrics</h3>
        <ul style={{ fontSize: 16, color: 'var(--gcw-text)' }}>
          <li><b>Revenue Saved:</b> ${metrics.revenue_saved?.toFixed(2) ?? '0.00'}</li>
          <li><b>Conversion Lift:</b> {(metrics.conversion_lift * 100).toFixed(2)}%</li>
          <li><b>Coupon Abuse Prevented:</b> {metrics.coupon_abuse_prevented ?? '0'}</li>
          <li><b>Bot Traffic Blocked:</b> {metrics.bot_traffic_blocked ?? '0'}</li>
          <li><b>Channel Breakdown:</b> {Array.isArray(metrics.channel_breakdown) ? metrics.channel_breakdown.map(c => `${c.channel}: ${c.discounts_given} discounts, ${c.no_discount} no discount`).join('; ') : 'N/A'}</li>
        </ul>
      </div>
      <div>
        <h3 style={{ color: 'var(--gcw-text)' }}>Engine Controls</h3>
        <form id="mri-config-form" onSubmit={e => e.preventDefault()} className="stack" style={{ gap: 0 }}>
          <label htmlFor="enabled" style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" id="enabled" checked={config.enabled} onChange={handleConfigChange} />
            <b>Enable Conversion MRI Engine</b>
          </label>
          <label htmlFor="ui_mode" style={{ marginTop: 12 }}>
            <b>UI Mode:</b>
            <select id="ui_mode" value={config.ui_mode} onChange={handleConfigChange} style={{ width: 220, marginLeft: 8 }}>
              <option value="bloomreach">Bloomreach Weblayers</option>
              <option value="custom">Custom UI</option>
              <option value="both">Both</option>
            </select>
          </label>
          <fieldset style={{ marginTop: 12, border: '1px solid var(--gcw-border)', padding: 12 }}>
            <legend style={{ fontWeight: 600, color: 'var(--gcw-text)' }}>Features</legend>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, cursor: 'pointer' }}><input type="checkbox" id="discount_optimization" checked={config.discount_optimization} onChange={handleConfigChange} /> Discount Optimization</label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, cursor: 'pointer' }}><input type="checkbox" id="coupon_abuse_prevention" checked={config.coupon_abuse_prevention} onChange={handleConfigChange} /> Coupon Abuse Prevention</label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, cursor: 'pointer' }}><input type="checkbox" id="bot_protection" checked={config.bot_protection} onChange={handleConfigChange} /> Bot Protection</label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 0, cursor: 'pointer' }}><input type="checkbox" id="profit_maximization" checked={config.profit_maximization} onChange={handleConfigChange} /> Profit Maximization</label>
          </fieldset>
          <div className="inline" style={{ marginTop: 16 }}>
            <button type="button" onClick={handleSave} disabled={!!staleAt}>Save Settings</button>
            <button type="button" onClick={fetchMetrics} className="secondary">Refresh Metrics</button>
          </div>
        </form>
      </div>
      <div style={{ marginTop: 12, color: status.startsWith('Error') ? 'var(--gcw-sale)' : 'var(--gcw-btn)' }}>{status}</div>
    </div>
  );
};
