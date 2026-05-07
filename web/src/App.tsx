
import { useState } from 'react';
import './App.css';
import { BotBlocker } from './components/BotBlocker';
import { DiscountManager } from './components/DiscountManager';
import { MRIEngine } from './components/MRIEngine';
import { AppHealthCheck } from './components/AppHealthCheck';

const TABS = [
  { id: 'discount', label: 'Discount Manager' },
  { id: 'mri', label: 'Conversion MRI Engine' },
  { id: 'health', label: 'App Health-Check' },
  { id: 'bot', label: 'Bot Protection' },
];

function App() {
  const [tab, setTab] = useState('discount');

  return (
    <div style={{ minHeight: '100vh', background: 'var(--gcw-bg)' }}>
      <header style={{ padding: 24, borderBottom: '1px solid var(--gcw-border)', background: 'var(--gcw-bg-secondary)' }}>
        <h1 style={{ fontSize: 32, margin: 0, color: 'var(--gcw-text)' }}>Commerce Shield</h1>
        <nav style={{ marginTop: 16 }}>
          {TABS.map(t => (
            <button
              key={t.id}
              className="tab-btn"
              style={{
                marginRight: 8,
                background: tab === t.id ? 'var(--gcw-btn)' : 'var(--gcw-bg)',
                color: tab === t.id ? 'var(--gcw-btn-label)' : 'var(--gcw-btn)',
                border: '1px solid var(--gcw-btn)',
                fontWeight: 600,
                padding: '12px 24px',
                cursor: 'pointer',
                borderRadius: 0,
                outline: tab === t.id ? '2px solid var(--gcw-focus)' : 'none',
              }}
              onClick={() => setTab(t.id)}
              disabled={tab === t.id}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <main style={{ padding: 32 }}>
        {tab === 'discount' && <DiscountManager />}
        {tab === 'mri' && <MRIEngine />}
        {tab === 'health' && <AppHealthCheck />}
        {tab === 'bot' && <BotBlocker />}
      </main>
    </div>
  );
}

export default App;
