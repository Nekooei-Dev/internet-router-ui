# 🧠 Internet Manager for MikroTik
**پنل مدیریت اینترنت برای MikroTik با Flask**

## 📌 درباره پروژه

این پروژه یک پنل مدیریتی تحت وب است که به مدیر شبکه اجازه می‌دهد تا اینترنت کاربران را به صورت پویا مدیریت کند. کاربران می‌توانند بین اینترنت‌های مختلف (مانند ADSL، ایرانسل، همراه اول و...) سوییچ کنند. همچنین، سطح دسترسی‌ها شامل کاربر عادی، مدیر و سوپر ادمین برای تنظیمات پیشرفته وجود دارد.

---

## ⚙️ امکانات اصلی

### 🎛️ بخش‌های مختلف سیستم:

- **پنل کاربر:**  
  کاربران می‌توانند اینترنت مورد نظر خود را از بین گزینه‌های فعال انتخاب کنند.

  ![user](https://github.com/user-attachments/assets/2a8afdf5-301a-4dc9-a99e-638e0cadc66c)


- **پنل مدیر (Admin):**  
  - تغییر اینترنت کاربران بر اساس IP  
  - غیرفعال‌سازی یا فعال‌سازی دسترسی کاربران  
  - ثبت توضیح برای هر دستگاه  
  - انتخاب جدول پیش‌فرض روت  
  - اتصال جدول‌های روت به اینترفیس‌های شبکه
 

![admin](https://github.com/user-attachments/assets/3fad517e-748b-414a-9e49-b69788759bbf)


- **پنل سوپر ادمین (SuperAdmin):**  
  - نام‌گذاری اختصاصی برای اینترفیس‌ها و جدول‌های روت  
  - دسترسی به تنظیمات پایه سیستم
 
  - 

### 🔁 تغییر مسیر اینترنت:

- بر اساس جدول‌های روت MikroTik (Routing Tables)  
- مدیریت از طریق قوانین `mangle`  
- تشخیص خودکار گیت‌وی برای هر اینترفیس  
- پشتیبانی از DHCP و رنج‌های ثابت IP  

---

## 🗂 ساختار فایل‌ها

```
.
├── app.py                  # هسته اصلی برنامه Flask
├── settings.json           # تنظیمات اینترفیس و تیبل‌ها
├── requirements.txt        # کتابخانه‌های پایتون مورد نیاز
├── templates/              # قالب‌های HTML
│   ├── static/             # استایل‌ها و JS اختصاصی
│   ├── login.html          # ورود کاربران
│   ├── user.html           # پنل کاربر
│   ├── admin.html          # پنل مدیر
│   ├── settings.html       # تنظیمات سوپر ادمین
│   └── ...
```

---

## 🔐 دسترسی‌ها و نقش‌ها

| نقش        | دسترسی‌ها                                                                 |
|------------|----------------------------------------------------------------------------|
| **کاربر**      | تغییر اینترنت شخصی خودش                                                  |
| **مدیر**       | مشاهده و کنترل تمام کاربران، تغییر مسیر اینترنت آنها، بلاک‌کردن کاربران  |
| **سوپرادمین**  | تنظیم نام‌ها برای اینترفیس‌ها و تیبل‌ها، کنترل ساختار پایه سیستم        |

---

## 📦 نصب و راه‌اندازی

1. نصب کتابخانه‌ها:

```bash
pip install -r requirements.txt
```

2. تنظیم متغیرهای محیطی:

```bash
export API_HOST=192.168.1.1
export API_USER=admin
export API_PASS=yourpass
export WEB_PORT=5000
export WEB_ADMIN_PASSWORD=123456
export WEB_SUPERADMIN_PASSWORD=123456789
```

3. اجرای برنامه:

```bash
python app.py
```

---

## 🧪 پیش‌نیازها

- MikroTik Router با API فعال  
- Python 3.7+  
- دسترسی SSH یا API به روتر  

---

## 🔐 نکات امنیتی

- استفاده از HTTPS در محیط واقعی  
- ذخیره پسوردها در `.env` و استفاده از ابزارهایی مثل `python-dotenv`  
- فایروال برای محدودسازی دسترسی به پورت Flask و MikroTik  

---

## 🙌 مشارکت

اگر مایل به توسعه یا بهبود این پروژه هستید، Pull Request شما خوش‌آمد است. همچنین می‌توانید Issues باز کنید تا مشکلات بررسی شوند.

---

## 👤 سازنده

> طراحی و پیاده‌سازی توسط مصطفی نکویی  
> 📧 nekooei.developer@gmail.com  
