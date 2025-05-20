# پایه سبک
FROM python:3.13-alpine

# تنظیمات پایه‌ای
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# نصب وابستگی‌ها
RUN apk update && apk add --no-cache build-base gcc musl-dev libffi-dev openssl-dev

# محل پروژه
WORKDIR /app

# کپی فایل‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کل پروژه
COPY . .

# پورت مورد استفاده
EXPOSE 5000

# اجرای اپ
CMD ["python", "app.py"]
