FROM python:3.11-slim

# تنظیمات محیط و کاربری
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ساخت دایرکتوری کاری
WORKDIR /app

# نصب پیش‌نیازها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی پروژه
COPY . .

# اجرای برنامه
CMD ["python", "app.py"]
