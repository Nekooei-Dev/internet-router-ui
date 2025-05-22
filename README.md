# 🌐 Internet Router UI (MikroTik Web Panel)

پنل تحت وب برای مدیریت مسیر اینترنت کاربران در روتر MikroTik، با قابلیت انتخاب اینترنت پیش‌فرض، تخصیص مسیر اینترنت به کاربران، و رابط گرافیکی فارسی.

---

## 📦 ساختار پروژه

internet-router-ui/
├── backend/
│ ├── static/
│ │ ├── css/
│ │ ├── js/
│ │ └── image/
│ ├── templates/
│ │ ├── navbar.html
│ │ ├── footer.html
│ │ ├── index.html
│ │ ├── login.html
│ │ ├── admin.html
│ │ ├── user.html
│ │ ├── settings.html
│ │ ├── error.html
│ │ └── about.html
│ └── routes/
│ ├── auth.py
│ ├── user.py
│ ├── admin.py
│ └── common.py
├── settings.json
├── .env.example
├── app.py
├── requirements.txt
└── README.md


---

## ⚙️ پیش‌نیازها

- Python 3.8+
- MikroTik RouterOS با فعال بودن API (port: 8728)

---

## 🚀 شروع سریع

```bash
# 1. کلون کردن پروژه
git clone https://github.com/yourname/internet-router-ui.git
cd internet-router-ui

# 2. نصب وابستگی‌ها
pip install -r requirements.txt

# 3. تنظیم محیط
cp .env.example .env  # و مقداردهی به مقادیر واقعی

# 4. اجرای برنامه
python app.py



🔐 نقش‌ها

    admin: دسترسی کامل به کاربران، تنظیمات، جدول‌ها و اینترنت پیش‌فرض

    user: تنها انتخاب مسیر اینترنت خودش

💡 قابلیت‌ها

    انتخاب اینترنت پیش‌فرض برای جدول main

    تعریف اینترنت خاص برای IP هر کاربر

    حذف یا تغییر مسیر کاربران

    ثبت خودکار منگل و روت بر اساس تنظیمات

    پنل تنظیمات اینترفیس و جدول‌ها با نام‌گذاری دلخواه

    داشبورد ورود با تشخیص نوع کاربر

🧪 متغیرهای محیطی .env
کلید	توضیح
API_HOST	IP میکروتیک
API_PORT	پورت API
API_USER / API_PASS	اطلاعات ورود API
WEB_ADMIN_PASSWORD / WEB_USER_PASSWORD	رمز ورود وب
ALLOWED_NETWORKS	شبکه‌های مجاز برای دسترسی به پنل
SECRET_KEY	کلید رمزنگاری کوکی‌ها

📸 تصویر نمایی

در حال حاضر نمای HTML با استفاده از Bootstrap 5.3 و FontAwesome آماده‌سازی شده است.
🤝 همکاری

در صورت تمایل به بهبود پروژه، درخواست Pull Request دهید یا در Issues مشارکت داشته باشید.
🧑‍💻 توسعه‌دهنده

    نکوئی – اینستاگرام
