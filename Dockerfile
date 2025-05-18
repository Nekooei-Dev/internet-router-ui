# استفاده از ایمیج سبک پایتون
FROM python:3.9.17-slim

# تنظیم دایرکتوری کاری
WORKDIR /app

# کپی کردن تمام فایل‌ها به کانتینر
COPY . .

# نصب وابستگی‌ها
RUN pip install --no-cache-dir -r requirements.txt

# باز کردن پورت وب‌اپلیکیشن Flask
EXPOSE 5000

# اجرای برنامه
CMD ["python", "app.py"]
