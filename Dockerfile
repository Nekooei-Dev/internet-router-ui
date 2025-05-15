# Use official Python base image for ARMv7 (alpine for سبک بودن)
FROM python:3.11-alpine

# نصب BusyBox برای سرو فایل استاتیک frontend
RUN apk add --no-cache busybox

# Set working directory
WORKDIR /app

# Copy backend files
COPY backend/ ./backend/

# Copy frontend dist
COPY frontend/dist/ ./frontend/

# نصب dependencies Python
RUN pip install --no-cache-dir -r backend/requirements.txt

# expose port (مطابق env یا default)
EXPOSE 80

# Run backend و سرو فایل استاتیک با busybox httpd
CMD sh -c "httpd -f -p 80 -h /app/frontend & python3 /app/backend/app.py"
