# مرحله بیلد برای نصب وابستگی‌ها
FROM --platform=$BUILDPLATFORM python:3.11-slim as builder

WORKDIR /app

COPY app.py /app/
COPY templates/ /app/templates/

# نصب کتابخانه‌ها در یک پوشه جدا
RUN pip install --upgrade pip && \
    pip install --prefix=/install flask routeros_api

# مرحله دوم - ایمیج نهایی کوچک
FROM python:3.11-slim

WORKDIR /app

# کپی فایل‌های برنامه
COPY app.py /app/
COPY templates/ /app/templates/

# کپی پکیج‌های نصب‌شده از مرحله بیلد
COPY --from=builder /install /usr/local

EXPOSE 5000

CMD ["python", "app.py"]
