# پایه سبک
FROM python:3.13-alpine

# نصب وابستگی‌ها
RUN apk add --no-cache build-base libffi-dev

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
