# Internet Router UI

یک رابط کاربری وب برای مدیریت اتصال کاربران به اینترنت از طریق MikroTik با استفاده از رول‌های Mangle و Routing.

## ویژگی‌ها

- ورود کاربر و مدیر با رمز عبور
- بررسی اتصال به API MikroTik
- مشاهده وضعیت اینترنت کاربر
- تغییر اینترنت پیش‌فرض برای کاربران
- مدیریت کاربران و اینترنت‌ها توسط مدیر

## نصب و اجرا

### پیش‌نیازها

- Python 3.11

### اجرای محلی

1. مخزن را کلون کنید:
git clone https://github.com/Nekooei-Dev/internet-router-ui.git
cd internet-router-ui


2. فایل `.env` را با مقادیر مناسب تنظیم کنید.

3. نصب وابستگی‌ها:

pip install -r requirements.txt


4. اجرای برنامه:

python app.py




### اجرای با Docker

1. ساخت تصویر Docker:
docker build -t internet-router-ui

2. اجرای کانتینر:

docker run -d -p 5000:5000 --env-file .env internet-router-ui




## تنظیمات MikroTik

1. ایجاد کاربر API:


/user add name=API password=API group=full

