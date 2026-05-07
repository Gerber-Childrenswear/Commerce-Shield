import React, { useEffect, useState } from 'react';

const CACHE_KEY_APP_HEALTH = 'cs_app_health_cache';

function readCache<T>(key: string): { data: T; savedAt: string } | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function writeCache<T>(key: string, data: T) {
  try { localStorage.setItem(key, JSON.stringify({ data, savedAt: new Date().toISOString() })); } catch {}
}

interface AppHealth {
  name: string;
  code_injected: boolean;
  code_summary?: string;
  needs_update: boolean;
  usage?: string;
  errors?: string;
  theme_conflicts?: string;
  performance_impact?: string;
  api_rate_limit?: string;
  uninstalled_residue?: string;
  webhook_failures?: string;
  usage_trend?: string;
  security_vulns?: string;
  script_errors?: string;
}

export const AppHealthCheck: React.FC = () => {
  const [apps, setApps] = useState<AppHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [staleAt, setStaleAt] = useState('');

  useEffect(() => {
    fetch('/api/app-health')
      .then(res => {
        if (!res.ok) throw new Error(`${res.status}`);
        return res.json();
      })
      .then(data => {
        const fresh = data.apps || [];
        setApps(fresh);
        writeCache(CACHE_KEY_APP_HEALTH, fresh);
      })
      .catch(() => {
        const cached = readCache<AppHealth[]>(CACHE_KEY_APP_HEALTH);
        if (cached) {
          setApps(cached.data);
          setStaleAt(cached.savedAt);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ color: 'var(--gcw-subtext)', textAlign: 'center', marginTop: 48 }}>Loading app health data...</div>;

  return (
    <div className="section card stack" style={{ maxWidth: 1200, margin: '0 auto' }}>
      <h2 style={{ color: 'var(--gcw-text)' }}>Shopify App Health-Check</h2>
      {staleAt && <div style={{ fontSize: 13, color: 'var(--gcw-subtext)', background: 'var(--gcw-bg-secondary)', padding: '6px 10px', borderRadius: 4, marginBottom: 12 }}>Backend unavailable — showing data from {new Date(staleAt).toLocaleString()}.</div>}
      {apps.length === 0 ? (
        <div style={{ color: 'var(--gcw-subtext)' }}>No apps found.</div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table border={1} cellPadding={6} style={{ borderCollapse: 'collapse', width: '100%', marginTop: 16, background: 'var(--gcw-bg)' }}>
            <thead style={{ background: 'var(--gcw-bg-secondary)' }}>
              <tr>
                <th>App Name</th>
                <th>Code Injected</th>
                <th>Needs Update</th>
                <th>Usage</th>
                <th>Errors/Misconfig</th>
                <th>Theme File Conflicts</th>
                <th>Performance Impact</th>
                <th>API Rate Limit</th>
                <th>Uninstalled App Residue</th>
                <th>Webhook Failures</th>
                <th>Usage Trend</th>
                <th>Security Vulnerabilities</th>
                <th>Script Errors</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app, i) => (
                <tr key={i} style={{ color: 'var(--gcw-text)' }}>
                  <td>{app.name}</td>
                  <td>{app.code_injected ? <span title={app.code_summary}>Yes</span> : 'No'}</td>
                  <td>{app.needs_update ? 'Yes' : 'No'}</td>
                  <td>{app.usage || 'Unused'}</td>
                  <td>{app.errors ? <span style={{ color: 'var(--gcw-sale)' }}>{app.errors}</span> : ''}</td>
                  <td>{app.theme_conflicts || ''}</td>
                  <td>{app.performance_impact || ''}</td>
                  <td>{app.api_rate_limit || ''}</td>
                  <td>{app.uninstalled_residue || ''}</td>
                  <td>{app.webhook_failures || ''}</td>
                  <td>{app.usage_trend || ''}</td>
                  <td>{app.security_vulns || ''}</td>
                  <td>{app.script_errors || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
