FROM python:3.11

WORKDIR /app

# نصب پیش‌نیازهای ساخت برای PyNaCl و سایر پکیج‌ها
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# فعال‌سازی wheel برای جلوگیری از build طولانی
RUN pip install --upgrade pip wheel setuptools \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]
