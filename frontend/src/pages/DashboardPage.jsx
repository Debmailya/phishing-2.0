import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, BarChart, Bar, CartesianGrid } from 'recharts';

const trendData = [
  { day: 'Mon', risk: 42 },
  { day: 'Tue', risk: 48 },
  { day: 'Wed', risk: 55 },
  { day: 'Thu', risk: 50 },
  { day: 'Fri', risk: 60 },
];

const brandData = [
  { brand: 'PayPal', attacks: 35 },
  { brand: 'Chase', attacks: 21 },
  { brand: 'Stripe', attacks: 14 },
];

export default function DashboardPage() {
  return (
    <main style={{ fontFamily: 'Inter, sans-serif', padding: 24, background: '#0b1020', color: '#e7ebff', minHeight: '100vh' }}>
      <h1>PhishGuard AI Enterprise Command Center</h1>
      <p>Real-time anti-phishing defense for digital banking and e-commerce security operations.</p>
      <section style={{ display: 'flex', gap: 16 }}>
        <article style={{ background: '#121b37', padding: 16, borderRadius: 12 }}>
          <h3>Risk Score Trend</h3>
          <LineChart width={420} height={220} data={trendData}>
            <XAxis dataKey="day" stroke="#b5c2ff" />
            <YAxis stroke="#b5c2ff" />
            <Tooltip />
            <Line type="monotone" dataKey="risk" stroke="#4fd1c5" strokeWidth={2} />
          </LineChart>
        </article>
        <article style={{ background: '#121b37', padding: 16, borderRadius: 12 }}>
          <h3>Top Attacked Brands</h3>
          <BarChart width={420} height={220} data={brandData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="brand" stroke="#b5c2ff" />
            <YAxis stroke="#b5c2ff" />
            <Tooltip />
            <Bar dataKey="attacks" fill="#f6ad55" />
          </BarChart>
        </article>
      </section>
    </main>
  );
}
