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
    const toastContainer = document.getElementById('toastContainer');
    const toastId = `toast-${Date.now()}`;
    const toastElement = document.createElement('div');
    toastElement.className = `toast align-items-center text-bg-${type} border-0`;
    toastElement.id = toastId;
    toastElement.setAttribute('role', 'alert');
    toastElement.setAttribute('aria-live', 'assertive');
    toastElement.setAttribute('aria-atomic', 'true');

    toastElement.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;

    toastContainer.appendChild(toastElement);
    const toast = new bootstrap.Toast(toastElement);
    toast.show();

    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

});
