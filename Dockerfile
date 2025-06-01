# استفاده از پایتون آلپاین کم‌حجم و سبک
FROM python:3.12-alpine

# Set environment variables for Alpine to use UTF-8 and avoid pycache
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8
    
# نصب وابستگی‌ها
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev \
    && apk add --no-cache libffi openssl

# محل پروژه
WORKDIR /app

# کپی فایل‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Remove build dependencies to reduce image size
RUN apk del .build-deps

# کپی کردن فایل‌های برنامه
COPY . .

# پورت مورد استفاده
EXPOSE 5000

# اجرای اپ
CMD ["python", "app.py"]
