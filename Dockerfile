FROM python:3.9.17-slim

WORKDIR /app
COPY . .

# نصب وابستگی‌ها
RUN pip install --no-cache-dir -r requirements.txt

# مشخص کردن پورت
EXPOSE 5000

# اجرای اپ
CMD ["python", "app.py"]
