document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('mangleForm');
    if (!form) return;  // فقط اگر صفحه فرم موجود بود ادامه بده

    const loadingSpinner = document.getElementById('loadingSpinner');
    const alertBox = document.getElementById('alertBox');

    function validateIP(ip) {
        const ipPattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
        return ipPattern.test(ip);
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const user_ip = form.user_ip.value.trim();
        if (!validateIP(user_ip)) {
            showAlert('آدرس IP وارد شده نامعتبر است.', 'danger');
            return;
        }

        loadingSpinner.style.display = 'block';
        alertBox.innerHTML = '';

        const formData = new FormData(form);

        try {
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData,
            });
            const data = await response.json();
            loadingSpinner.style.display = 'none';

            if (data.error) {
                showAlert(data.error, 'danger');
            } else if (data.success) {
                showAlert(data.success, 'success');
                form.reset();
            }
        } catch (error) {
            loadingSpinner.style.display = 'none';
            showAlert('خطا در ارتباط با سرور.', 'danger');
        }
    });

    function showAlert(message, type) {
        alertBox.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show alert-custom" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="بستن"></button>
        </div>`;
    }
});
