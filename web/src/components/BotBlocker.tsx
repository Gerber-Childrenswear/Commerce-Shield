import React from 'react';

export const BotBlocker: React.FC = () => {
  return (
    <div className="section card" style={{ maxWidth: 480, margin: '80px auto', textAlign: 'center' }}>
      <h1 style={{ fontSize: 32, marginBottom: 24 }}>Bot Protection</h1>
      <p style={{ color: 'var(--gcw-subtext)', fontSize: 18, marginBottom: 32 }}>
        This page is protected by advanced bot detection.<br />
        If you are a legitimate customer and see this message in error, please contact support.
      </p>
      <div style={{ margin: '32px 0 0 0', color: '#bf360c', fontWeight: 600, fontSize: 16 }}>
        <span role="img" aria-label="warning" style={{ fontSize: 32, verticalAlign: 'middle', marginRight: 8 }}>⚠️</span>
        Access Denied: Suspicious Activity Detected
      </div>
      <div style={{ marginTop: 32, color: 'var(--gcw-subtext)', fontSize: 14 }}>
        If you believe this is a mistake, please email <a href="mailto:support@gerberchildrenswear.com" style={{ color: 'var(--gcw-accent)', textDecoration: 'underline' }}>support@gerberchildrenswear.com</a> with your IP address and a brief description.<br />
        Thank you for helping us keep our site secure.
      </div>
    </div>
  );
};
