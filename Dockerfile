FROM python:3.11-slim

WORKDIR /app

# نصب ابزارهای مورد نیاز برای build پکیج‌های C
RUN apt-get update && \
    apt-get install -y gcc libffi-dev libssl-dev build-essential && \
    apt-get clean

# ارتقاء pip (اختیاری ولی توصیه‌شده)
RUN pip install --upgrade pip

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
