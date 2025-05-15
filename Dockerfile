# پایه Python 3.11
FROM python:3.11-slim

# تنظیم دایرکتوری کاری
WORKDIR /app

# کپی کردن فایل requirements
COPY requirements.txt .

# نصب وابستگی‌ها
RUN pip install --no-cache-dir -r requirements.txt

# کپی کردن کل برنامه
COPY . .

# پورت پیش‌فرض از ENV گرفته می‌شود (5000)
ENV FLASK_APP=app.py

# اجرای برنامه
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
