import React, { useEffect, useState } from 'react';
import axios from 'axios';

const providers = [
  { id: 'irancell', label: 'ایرانسل' },
  { id: 'hamrahaval', label: 'مخابرات' },
  { id: 'mci', label: 'همراه‌اول' },
  { id: 'asiatech', label: 'آسیاتک' },
];

function App() {
  const [selected, setSelected] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    // دریافت route پیشفرض از backend
    axios.get('/api/default-route')
      .then(res => setSelected(res.data.route))
      .catch(() => setSelected('irancell'));
  }, []);

  const changeRoute = () => {
    setMessage('در حال ارسال درخواست...');
    axios.post('/api/change-route', { route: selected }, {
      auth: {
        username: 'admin',
        password: 'pass123'
      }
    })
      .then(res => setMessage(res.data.status))
      .catch(err => setMessage('خطا: ' + err.response?.data?.error || err.message));
  };

  return (
    <div style={{ maxWidth: 400, margin: 'auto', padding: 20, fontFamily: 'Tahoma' }}>
      <h2>انتخاب اینترنت پیشفرض</h2>
      <select value={selected} onChange={e => setSelected(e.target.value)} style={{ width: '100%', padding: 8 }}>
        {providers.map(p => (
          <option key={p.id} value={p.id}>{p.label}</option>
        ))}
      </select>
      <button onClick={changeRoute} style={{ marginTop: 10, padding: 10, width: '100%' }}>
        تغییر مسیر
      </button>
      <p>{message}</p>
    </div>
  );
}

export default App;
