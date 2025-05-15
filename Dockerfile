# ===== Stage 1: Build Frontend on amd64 =====
FROM --platform=linux/amd64 node:18-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# ===== Stage 2: Backend + Serve frontend on ARMv7 =====
FROM python:3.11-slim as backend
WORKDIR /app

# نصب وابستگی‌های بک‌اند
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کد backend
COPY backend/ .

# کپی خروجی frontend به دایرکتوری static
COPY --from=frontend-builder /app/dist ./static

# بارگزاری ENV در صورت نیاز
ENV PYTHONUNBUFFERED=1

EXPOSE 80
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
