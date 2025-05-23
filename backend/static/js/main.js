// File: backend/static/js/main.js

document.addEventListener("DOMContentLoaded", function () {
  // نمونه‌ای از اعلان موفقیت پس از فلش
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.classList.add("fade");
      alert.classList.remove("show");
    }, 4000);
  });

  // اضافه‌کردن حالت فعال به آیتم‌های نوار ناوبری
  const navLinks = document.querySelectorAll(".nav-link");
  const currentPath = window.location.pathname;
  navLinks.forEach((link) => {
    if (link.getAttribute("href") === currentPath) {
      link.classList.add("active");
    }
  });
});
