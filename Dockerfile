FROM python:3.11-alpine

WORKDIR /app

# نصب pip فقط برای Pure Python بسته‌ها (هیچ کتابخانه native نصب نمی‌کنیم)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
