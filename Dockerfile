# ===== Stage 1: Build Frontend on amd64 =====
FROM node:18-alpine as frontend_builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# ===== Stage 2: Backend + Serve frontend =====
FROM python:3.11-slim as backend
WORKDIR /app

# نصب وابستگی‌های backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کد backend
COPY backend/ .

# کپی خروجی frontend
COPY --from=frontend_builder /app/dist ./static

# بارگزاری ENV در صورت نیاز
ENV PYTHONUNBUFFERED=1

EXPOSE 80
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
