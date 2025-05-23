document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');
    if (!form) return;

    form.addEventListener('submit', (e) => {
        const ipInput = form.ip.value.trim();
        const usernameInput = form.username.value.trim();
        const passwordInput = form.password.value.trim();
        const interfaceInput = form.interface.value.trim();

        const ipPattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

        let errorMessages = [];

        if (!ipPattern.test(ipInput)) {
            errorMessages.push("آدرس IP معتبر نیست.");
        }
        if (!usernameInput) {
            errorMessages.push("نام کاربری نمی‌تواند خالی باشد.");
        }
        if (!passwordInput) {
            errorMessages.push("کلمه عبور نمی‌تواند خالی باشد.");
        }
        if (!interfaceInput) {
            errorMessages.push("اینترفیس نمی‌تواند خالی باشد.");
        }

        if (errorMessages.length > 0) {
            e.preventDefault();
            alert(errorMessages.join("\n"));
        }
    });
});
