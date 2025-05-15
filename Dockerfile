# پایه Python آرم (alpine برای حجم کم)
FROM python:3.11-alpine

# نصب busybox برای سرو فایل استاتیک frontend
RUN apk add --no-cache busybox

WORKDIR /app

# کپی بک‌اند و فایل requirements
COPY backend/ ./backend/
COPY backend/requirements.txt ./backend/requirements.txt

# نصب پایتون دپندنسی‌ها
RUN pip install --no-cache-dir -r backend/requirements.txt

# کپی فرانت‌اند بیلد شده
COPY frontend/dist/ ./frontend/

# expose پورت اپلیکیشن
EXPOSE 80

# اجرای همزمان سرو فایل‌های استاتیک فرانت‌اند و سرور Python
CMD sh -c "httpd -f -p 80 -h /app/frontend & python3 /app/backend/app.py"
