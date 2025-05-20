# مرحله 1: ساخت ایمیج در محیط کامل
FROM python:3.9.17-alpine AS builder

WORKDIR /app

# نصب ابزارهای موردنیاز برای ساخت پکیج‌ها (در مرحله ساخت)
RUN apk add --no-cache build-base

COPY requirements.txt .

# نصب پکیج‌ها با حذف کش
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# مرحله 2: اجرای نهایی فقط با پایتون و پکیج‌های نصب‌شده
FROM python:3.9.17-alpine

WORKDIR /app

# فقط پوشه نصب‌شده رو از مرحله قبل کپی می‌کنیم
COPY --from=builder /install /usr/local
COPY . .

# باز کردن پورت
EXPOSE 5000

# اجرای اپ
CMD ["python", "app.py"]
