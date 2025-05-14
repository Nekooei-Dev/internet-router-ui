function selectRoute(internet) {
  fetch('/api/route', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ internet })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById('msg').innerText = 'با موفقیت تنظیم شد';
  })
  .catch(err => {
    document.getElementById('msg').innerText = 'خطا در ارسال';
  });
}
