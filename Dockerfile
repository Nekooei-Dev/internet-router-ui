# استفاده از ایمیج رسمی پایتون
FROM python:3.11-slim

# تنظیم دایرکتوری کاری داخل کانتینر
WORKDIR /app

# کپی فایل‌های مورد نیاز
COPY requirements.txt .
COPY . .

# نصب پکیج‌ها
RUN pip install --no-cache-dir -r requirements.txt

# اطمینان از فعال بودن پورت Flask
EXPOSE 5000

# اجرای برنامه
CMD ["python", "app.py"]
