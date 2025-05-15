# syntax=docker/dockerfile:experimental
FROM python:3.11-slim

WORKDIR /app

# نصب dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کردن همه فایل‌ها (شامل app.py، templates، .env و ... )
COPY . .

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["flask", "run"]
