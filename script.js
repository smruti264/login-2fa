// Client-side validation for login/register forms
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form[action="/login"]');
    const registerForm = document.querySelector('form[action="/register"]');
    const verify2FAForm = document.querySelector('form[action="/verify_2fa"]');

    // Password strength indicator (for register page)
    if (registerForm) {
        const passwordInput = registerForm.querySelector('input[type="password"]');
        const passwordStrength = document.createElement('div');
        passwordStrength.className = 'password-strength';
        passwordStrength.style.marginTop = '5px';
        passwordStrength.style.fontSize = '0.8rem';
        passwordInput.insertAdjacentElement('afterend', passwordStrength);

        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;

            if (password.length >= 8) strength++;
            if (password.match(/[A-Z]/)) strength++;
            if (password.match(/[0-9]/)) strength++;
            if (password.match(/[^A-Za-z0-9]/)) strength++;

            let strengthText = '';
            let color = 'red';

            switch (strength) {
                case 0:
                case 1:
                    strengthText = 'Weak';
                    color = 'red';
                    break;
                case 2:
                    strengthText = 'Medium';
                    color = 'orange';
                    break;
                case 3:
                    strengthText = 'Strong';
                    color = 'green';
                    break;
                case 4:
                    strengthText = 'Very Strong';
                    color = 'darkgreen';
                    break;
            }

            passwordStrength.textContent = `Strength: ${strengthText}`;
            passwordStrength.style.color = color;
        });
    }

    // Auto-submit OTP after 6 digits (for 2FA verification)
    if (verify2FAForm) {
        const otpInput = verify2FAForm.querySelector('input[name="otp"]');
        otpInput.addEventListener('input', function() {
            if (this.value.length === 6) {
                verify2FAForm.submit();
            }
        });
    }

    // Prevent form submission if fields are invalid
    if (loginForm || registerForm || verify2FAForm) {
        const form = loginForm || registerForm || verify2FAForm;
        form.addEventListener('submit', function(e) {
            const inputs = this.querySelectorAll('input[required]');
            let isValid = true;

            inputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.style.borderColor = 'red';
                } else {
                    input.style.borderColor = '#ddd';
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required fields!');
            }
        });
    }
});

// Logout after inactivity (optional)
let inactivityTime = function() {
    let time;
    window.onload = resetTimer;
    document.onmousemove = resetTimer;
    document.onkeypress = resetTimer;

    function logout() {
        window.location.href = '/logout';
    }

    function resetTimer() {
        clearTimeout(time);
        time = setTimeout(logout, 15 * 60 * 1000); // 15 minutes
    }
};

if (window.location.pathname === '/dashboard') {
    inactivityTime();
}