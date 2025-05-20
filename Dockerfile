# استفاده از پایتون آلپاین کم‌حجم و سبک
FROM python:3.12-alpine

# نصب وابستگی‌ها
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

# محل پروژه
WORKDIR /app

# کپی فایل‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کردن فایل‌های برنامه
COPY . /app

# پورت مورد استفاده
EXPOSE 5000

# اجرای اپ
CMD ["python", "app.py"]
