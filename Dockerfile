# مرحله 1: انتخاب تصویر پایه Python
FROM python:3.9-slim

# مرحله 2: تنظیم دایرکتوری کاری
WORKDIR /app

# مرحله 3: کپی کردن فایل‌های نیازمند به داخل کانتینر
COPY requirements.txt requirements.txt

# مرحله 4: نصب وابستگی‌ها
RUN pip install --no-cache-dir -r requirements.txt

# مرحله 5: کپی کردن تمام فایل‌ها به دایرکتوری کاری
COPY . .

# مرحله 6: تنظیم متغیر محیطی
ENV ADMIN_USER=${ADMIN_USER}
ENV ADMIN_PASS=${ADMIN_PASS}
ENV SECRET_KEY=${SECRET_KEY}
ENV APP_PORT=${APP_PORT}
ENV DEFAULT_ROUTE=${DEFAULT_ROUTE}

# مرحله 7: expose پورت 80 (یا پورتی که انتخاب کردی)
EXPOSE 80

# مرحله 8: اجرای برنامه
CMD ["python", "app.py"]
