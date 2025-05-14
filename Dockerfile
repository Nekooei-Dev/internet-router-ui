# تصویر پایه
FROM python:3.9-slim

# تنظیم مسیر کاری داخل کانتینر
WORKDIR /app

# کپی کردن فایل‌های پروژه به کانتینر
COPY . .

# نصب پکیج‌ها
RUN pip install --no-cache-dir -r requirements.txt

# پورت پیش‌فرض برای اجرا
EXPOSE 80

# اجرای برنامه
CMD ["python", "app.py"]
