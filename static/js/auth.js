/**
 * AI Shield Authentication System - Unified Client-Side JS
 * Handled Features: Theme Toggles, Live Validations, Password Strength meters, 6-digit 2FA OTP Code bindings.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Add page enter animation class
    const mainContainer = document.querySelector('.auth-split-container');
    if (mainContainer) {
        mainContainer.classList.add('auth-page-enter');
    }

    // Initialize core components
    initThemeToggle();
    initPasswordToggles();
    initLoginForm();
    initRegisterForm();
    initForgotPasswordForm();
    initResetPasswordForm();
    init2faForm();
    initAlertDismissal();
});

/**
 * Global CSRF & Loading Helpers
 */
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

function showLoading(form) {
    const overlay = form.querySelector('.loading-overlay') || form.closest('.auth-glass-card')?.querySelector('.loading-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
        overlay.setAttribute('aria-hidden', 'false');
    }
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        if (!submitBtn.dataset.originalHtml) {
            submitBtn.dataset.originalHtml = submitBtn.innerHTML;
        }
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...';
    }
}

function hideLoading(form) {
    const overlay = form.querySelector('.loading-overlay') || form.closest('.auth-glass-card')?.querySelector('.loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
        overlay.setAttribute('aria-hidden', 'true');
    }
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn && submitBtn.dataset.originalHtml) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = submitBtn.dataset.originalHtml;
    }
}

function initAlertDismissal() {
    document.querySelectorAll('.alert-custom-close').forEach(button => {
        button.addEventListener('click', () => {
            const alert = button.closest('.alert-custom');
            if (alert) {
                alert.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'scale(0.95)';
                setTimeout(() => alert.remove(), 200);
            }
        });
    });
}

/**
 * Theme Toggle Handler
 */
function initThemeToggle() {
    const themeBtn = document.getElementById('themeToggleBtn') || document.querySelector('.btn-theme-toggle');
    if (!themeBtn) return;

    const icon = themeBtn.querySelector('i');
    const savedTheme = localStorage.getItem('theme') || 'dark';

    // Apply stored theme
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        if (icon) icon.className = 'fas fa-moon';
    } else {
        document.body.classList.remove('light-theme');
        if (icon) icon.className = 'fas fa-sun';
    }

    themeBtn.addEventListener('click', () => {
        if (document.body.classList.contains('light-theme')) {
            document.body.classList.remove('light-theme');
            localStorage.setItem('theme', 'dark');
            if (icon) icon.className = 'fas fa-sun';
        } else {
            document.body.classList.add('light-theme');
            localStorage.setItem('theme', 'light');
            if (icon) icon.className = 'fas fa-moon';
        }
    });
}

/**
 * Handle password show/hide eye buttons
 */
function initPasswordToggles() {
    const toggles = document.querySelectorAll('.password-toggle-btn');
    toggles.forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = toggle.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            const icon = toggle.querySelector('i');

            if (passwordInput && icon) {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                    toggle.setAttribute('aria-label', 'Hide password');
                } else {
                    passwordInput.type = 'password';
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                    toggle.setAttribute('aria-label', 'Show password');
                }
            }
        });
    });
}

/**
 * Login Form Validation and SSO Binding
 */
function initLoginForm() {
    const form = document.getElementById('login-form');
    if (!form) return;

    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');

    form.addEventListener('submit', (e) => {
        let valid = true;

        if (!emailInput.value.trim()) {
            showInputFeedback(emailInput, false, 'Username or Email is required');
            valid = false;
        } else {
            clearInputFeedback(emailInput);
        }

        if (!passwordInput.value) {
            showInputFeedback(passwordInput, false, 'Password is required');
            valid = false;
        } else {
            clearInputFeedback(passwordInput);
        }

        if (!valid) {
            e.preventDefault();
        } else {
            showLoading(form);
        }
    });

    [emailInput, passwordInput].forEach(input => {
        input.addEventListener('input', () => {
            if (input.classList.contains('is-invalid-input')) {
                clearInputFeedback(input);
            }
        });
    });
}

/**
 * Register Form Live validation, password check, and async checks
 */
function initRegisterForm() {
    const form = document.getElementById('register-form');
    if (!form) return;

    const fullNameInput = document.getElementById('full_name');
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const termsInput = document.getElementById('terms');

    let isUsernameAvailable = false;
    let isEmailAvailable = false;
    let usernameCheckTimeout = null;
    let emailCheckTimeout = null;

    // Legal Compliance & Modals State Tracking
    let termsViewed = false;
    let privacyViewed = false;

    if (termsInput) {
        termsInput.disabled = true;
    }

    const label = document.querySelector('.checkbox-custom-label');
    let disabledTip = document.getElementById('checkboxDisabledTip');
    if (!disabledTip && label) {
        disabledTip = document.createElement('div');
        disabledTip.id = 'checkboxDisabledTip';
        disabledTip.className = 'checkbox-disabled-tip';
        disabledTip.innerHTML = '<i class="fas fa-circle-exclamation"></i> <span>Please read the Terms &amp; Conditions and Privacy Policy first.</span>';
        label.parentNode.appendChild(disabledTip);
        disabledTip.style.display = 'flex';
    }

    function updateCheckboxState() {
        if (termsViewed && privacyViewed) {
            termsInput.disabled = false;
            if (disabledTip) disabledTip.style.display = 'none';
        } else {
            termsInput.disabled = true;
            if (disabledTip) {
                let txt = "Please read the Terms & Conditions and Privacy Policy first.";
                if (!termsViewed && privacyViewed) txt = "Please read the Terms & Conditions first.";
                if (termsViewed && !privacyViewed) txt = "Please read the Privacy Policy first.";
                disabledTip.querySelector('span').textContent = txt;
                disabledTip.style.display = 'flex';
            }
        }
    }

    // Modal Scroll Listeners
    const termsBody = document.querySelector('#termsModal .modal-body-scrollable');
    const privacyBody = document.querySelector('#privacyModal .modal-body-scrollable');
    
    if (termsBody) {
        termsBody.addEventListener('scroll', () => {
            if (termsBody.scrollHeight - termsBody.scrollTop <= termsBody.clientHeight + 25) {
                termsViewed = true;
                updateCheckboxState();
            }
        });
    }

    if (privacyBody) {
        privacyBody.addEventListener('scroll', () => {
            if (privacyBody.scrollHeight - privacyBody.scrollTop <= privacyBody.clientHeight + 25) {
                privacyViewed = true;
                updateCheckboxState();
            }
        });
    }

    // Modal Accept Buttons
    const acceptTermsBtn = document.getElementById('acceptTermsBtn');
    const acceptPrivacyBtn = document.getElementById('acceptPrivacyBtn');

    if (acceptTermsBtn) {
        acceptTermsBtn.addEventListener('click', () => {
            termsViewed = true;
            updateCheckboxState();
            termsInput.checked = true;
            clearInputFeedback(termsInput);
            const modalEl = document.getElementById('termsModal');
            const inst = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
            if (inst) inst.hide();
        });
    }

    if (acceptPrivacyBtn) {
        acceptPrivacyBtn.addEventListener('click', () => {
            privacyViewed = true;
            updateCheckboxState();
            termsInput.checked = true;
            clearInputFeedback(termsInput);
            const modalEl = document.getElementById('privacyModal');
            const inst = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
            if (inst) inst.hide();
        });
    }

    // Modal Focus & Accessibility Triggers
    const termsModal = document.getElementById('termsModal');
    const privacyModal = document.getElementById('privacyModal');
    const termsLink = document.getElementById('viewTermsLink');
    const privacyLink = document.getElementById('viewPrivacyLink');

    if (termsModal) {
        termsModal.addEventListener('shown.bs.modal', () => {
            const firstButton = termsModal.querySelector('.btn-close-custom') || termsModal.querySelector('.modal-title');
            if (firstButton) firstButton.focus();
        });
        termsModal.addEventListener('hidden.bs.modal', () => {
            if (termsLink) termsLink.focus();
        });
    }

    if (privacyModal) {
        privacyModal.addEventListener('shown.bs.modal', () => {
            const firstButton = privacyModal.querySelector('.btn-close-custom') || privacyModal.querySelector('.modal-title');
            if (firstButton) firstButton.focus();
        });
        privacyModal.addEventListener('hidden.bs.modal', () => {
            if (privacyLink) privacyLink.focus();
        });
    }

    fullNameInput.addEventListener('input', () => {
        const val = fullNameInput.value.trim();
        if (val.length < 2) {
            showInputFeedback(fullNameInput, false, 'Full name must be at least 2 characters');
        } else {
            showInputFeedback(fullNameInput, true, 'Name is valid');
        }
    });

    usernameInput.addEventListener('input', () => {
        clearTimeout(usernameCheckTimeout);
        const username = usernameInput.value.trim();

        if (username.length < 3) {
            showInputFeedback(usernameInput, false, 'Username must be at least 3 characters');
            isUsernameAvailable = false;
            return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            showInputFeedback(usernameInput, false, 'Alphanumeric and underscores only');
            isUsernameAvailable = false;
            return;
        }

        usernameCheckTimeout = setTimeout(async () => {
            try {
                const response = await fetch('/api/check-username', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify({ username })
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data.available) {
                        showInputFeedback(usernameInput, true, 'Username is available');
                        isUsernameAvailable = true;
                    } else {
                        showInputFeedback(usernameInput, false, 'Username is already taken');
                        isUsernameAvailable = false;
                    }
                } else {
                    showInputFeedback(usernameInput, true, 'Username format valid');
                    isUsernameAvailable = true;
                }
            } catch (err) {
                showInputFeedback(usernameInput, true, 'Username format valid');
                isUsernameAvailable = true;
            }
        }, 400);
    });

    emailInput.addEventListener('input', () => {
        clearTimeout(emailCheckTimeout);
        const email = emailInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            showInputFeedback(emailInput, false, 'Please enter a valid email address');
            isEmailAvailable = false;
            return;
        }

        emailCheckTimeout = setTimeout(async () => {
            try {
                const response = await fetch('/api/check-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify({ email })
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data.available) {
                        showInputFeedback(emailInput, true, 'Email address is available');
                        isEmailAvailable = true;
                    } else {
                        showInputFeedback(emailInput, false, 'Email is already registered');
                        isEmailAvailable = false;
                    }
                } else {
                    showInputFeedback(emailInput, true, 'Email format valid');
                    isEmailAvailable = true;
                }
            } catch (err) {
                showInputFeedback(emailInput, true, 'Email format valid');
                isEmailAvailable = true;
            }
        }, 400);
    });

    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        validateRequirements(val);
        const result = checkPasswordStrength(val);
        updatePasswordStrengthBar(result);

        if (val.length < 6) {
            showInputFeedback(passwordInput, false, 'Password must be at least 6 characters');
        } else {
            showInputFeedback(passwordInput, true, 'Password meets length requirements');
        }

        if (confirmPasswordInput.value) {
            validateConfirmPassword();
        }
    });

    confirmPasswordInput.addEventListener('input', validateConfirmPassword);

    function validateConfirmPassword() {
        if (!confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Please confirm your password');
            return false;
        } else if (passwordInput.value !== confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Passwords do not match');
            return false;
        } else {
            showInputFeedback(confirmPasswordInput, true, 'Passwords match');
            return true;
        }
    }

    form.addEventListener('submit', (e) => {
        let valid = true;

        if (fullNameInput.value.trim().length < 2) {
            showInputFeedback(fullNameInput, false, 'Full name is required');
            valid = false;
        }
        if (usernameInput.value.trim().length < 3) {
            showInputFeedback(usernameInput, false, 'Username is required');
            valid = false;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value.trim())) {
            showInputFeedback(emailInput, false, 'Valid email is required');
            valid = false;
        }
        if (passwordInput.value.length < 6) {
            showInputFeedback(passwordInput, false, 'Password must be at least 6 characters');
            valid = false;
        }
        if (passwordInput.value !== confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Passwords do not match');
            valid = false;
        }
        
        // Smarter Verification Checkbox validations
        if (!termsViewed || !privacyViewed) {
            showInputFeedback(termsInput, false, 'Please accept the Terms & Conditions and Privacy Policy.');
            valid = false;
        } else if (!termsInput.checked) {
            showInputFeedback(termsInput, false, 'Please accept the Terms & Conditions and Privacy Policy.');
            valid = false;
        } else {
            clearInputFeedback(termsInput);
        }

        if (!valid) {
            e.preventDefault();
        } else {
            showLoading(form);
        }
    });
}

/**
 * Forgot Password Validation
 */
function initForgotPasswordForm() {
    const form = document.getElementById('forgot-password-form');
    if (!form) return;

    const emailInput = document.getElementById('email');

    form.addEventListener('submit', (e) => {
        const email = emailInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            e.preventDefault();
            showInputFeedback(emailInput, false, 'Please enter a valid email address');
        } else {
            showLoading(form);
        }
    });

    emailInput.addEventListener('input', () => {
        clearInputFeedback(emailInput);
    });
}

/**
 * Reset Password Page Logic
 */
function initResetPasswordForm() {
    const form = document.getElementById('reset-password-form');
    if (!form) return;

    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');

    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        validateRequirements(val);
        const result = checkPasswordStrength(val);
        updatePasswordStrengthBar(result);

        if (val.length < 6) {
            showInputFeedback(passwordInput, false, 'Password must be at least 6 characters');
        } else {
            showInputFeedback(passwordInput, true, 'Password length ok');
        }

        if (confirmPasswordInput.value) {
            validateConfirmPassword();
        }
    });

    confirmPasswordInput.addEventListener('input', validateConfirmPassword);

    function validateConfirmPassword() {
        if (!confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Confirm your passcode');
            return false;
        } else if (passwordInput.value !== confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Passwords do not match');
            return false;
        } else {
            showInputFeedback(confirmPasswordInput, true, 'Passwords match');
            return true;
        }
    }

    form.addEventListener('submit', (e) => {
        let valid = true;

        if (passwordInput.value.length < 6) {
            showInputFeedback(passwordInput, false, 'Password must be at least 6 characters');
            valid = false;
        }
        if (passwordInput.value !== confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Passwords do not match');
            valid = false;
        }

        if (!valid) {
            e.preventDefault();
        } else {
            showLoading(form);
        }
    });
}

/**
 * 2FA 6-digit Code verification form bindings
 */
function init2faForm() {
    const form = document.getElementById('2fa-form');
    if (!form) return;

    const otpBoxes = document.querySelectorAll('.otp-box');
    const hiddenInput = document.getElementById('otp_code');
    const backupToggle = document.getElementById('toggleBackupOption');
    const backupWrapper = document.getElementById('backupCodeWrapper');
    const otpWrapper = document.getElementById('otpInputsWrapper');
    const backupInput = document.getElementById('backup_code');
    const countdownVal = document.getElementById('countdownVal');
    const resendBtn = document.getElementById('resendBtn');

    // 1. Handle keyboard focus hopping
    otpBoxes.forEach((box, index) => {
        box.addEventListener('input', (e) => {
            box.value = box.value.replace(/[^0-9]/g, ''); // Numeric only
            
            // Hop forward
            if (box.value.length === 1 && index < otpBoxes.length - 1) {
                otpBoxes[index + 1].focus();
            }
            updateHiddenOtp();
        });

        box.addEventListener('keydown', (e) => {
            // Hop backward on backspace
            if (e.key === 'Backspace' && !box.value && index > 0) {
                otpBoxes[index - 1].focus();
            }
        });
    });

    // 2. Paste Support
    otpBoxes.forEach((box) => {
        box.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
            const digits = pasteData.replace(/[^0-9]/g, '').slice(0, 6);

            for (let i = 0; i < digits.length; i++) {
                if (otpBoxes[i]) {
                    otpBoxes[i].value = digits[i];
                }
            }
            // Focus last filled box
            const targetIndex = Math.min(digits.length, otpBoxes.length - 1);
            if (otpBoxes[targetIndex]) {
                otpBoxes[targetIndex].focus();
            }
            updateHiddenOtp();
        });
    });

    function updateHiddenOtp() {
        let code = '';
        otpBoxes.forEach(box => {
            code += box.value;
        });
        hiddenInput.value = code;
    }

    // 3. Toggle Backup Option
    if (backupToggle && backupWrapper && otpWrapper) {
        backupToggle.addEventListener('click', (e) => {
            e.preventDefault();
            if (backupWrapper.classList.contains('d-none')) {
                backupWrapper.classList.remove('d-none');
                otpWrapper.classList.add('d-none');
                backupInput.required = true;
                backupInput.focus();
                hiddenInput.disabled = true; // Disable hidden input so backup code is submitted instead
                backupToggle.textContent = 'Use standard authenticator app code';
            } else {
                backupWrapper.classList.add('d-none');
                otpWrapper.classList.remove('d-none');
                backupInput.required = false;
                hiddenInput.disabled = false;
                otpBoxes[0].focus();
                backupToggle.textContent = 'Use security backup recovery code';
            }
        });
    }

    // 4. Timer Countdown (60 seconds)
    if (countdownVal && resendBtn) {
        let duration = 60;
        resendBtn.disabled = true;

        const countdownInterval = setInterval(() => {
            duration--;
            let mins = Math.floor(duration / 60);
            let secs = duration % 60;
            countdownVal.textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;

            if (duration <= 0) {
                clearInterval(countdownInterval);
                resendBtn.disabled = false;
                countdownVal.parentElement.classList.add('d-none');
            }
        }, 1000);

        resendBtn.addEventListener('click', (e) => {
            // Re-submit verification request or trigger refresh endpoint
            // Usually, this post calls an API to send a new email/SMS code
            showLoading(form);
        });
    }

    // Form Submission check
    form.addEventListener('submit', (e) => {
        // If standard OTP is active, make sure 6 digits are entered
        if (backupWrapper.classList.contains('d-none')) {
            updateHiddenOtp();
            if (hiddenInput.value.length < 6) {
                e.preventDefault();
                alert('Please enter a complete 6-digit security code.');
                otpBoxes[0].focus();
                return;
            }
        }
        showLoading(form);
    });
}

/**
 * Validation feedback UI helpers
 */
function showInputFeedback(input, isValid, message) {
    const parent = input.closest('.input-group-custom');
    if (!parent) return;

    input.classList.remove('is-valid-input', 'is-invalid-input');

    let validMsg = parent.querySelector('.validation-message.is-valid');
    let invalidMsg = parent.querySelector('.validation-message.is-invalid');

    if (!validMsg) {
        validMsg = document.createElement('div');
        validMsg.className = 'validation-message is-valid';
        validMsg.innerHTML = '<i class="fas fa-circle-check"></i> <span class="msg-text"></span>';
        parent.appendChild(validMsg);
    }
    if (!invalidMsg) {
        invalidMsg = document.createElement('div');
        invalidMsg.className = 'validation-message is-invalid';
        invalidMsg.innerHTML = '<i class="fas fa-circle-exclamation"></i> <span class="msg-text"></span>';
        parent.appendChild(invalidMsg);
    }

    validMsg.style.display = 'none';
    invalidMsg.style.display = 'none';

    if (isValid) {
        input.classList.add('is-valid-input');
        input.setAttribute('aria-invalid', 'false');
        validMsg.querySelector('.msg-text').textContent = message;
        validMsg.style.display = 'flex';
    } else {
        input.classList.add('is-invalid-input');
        input.setAttribute('aria-invalid', 'true');
        invalidMsg.querySelector('.msg-text').textContent = message;
        invalidMsg.style.display = 'flex';

        const liveStatus = document.getElementById('aria-live-status');
        if (liveStatus) {
            liveStatus.textContent = `Validation error in ${input.id}: ${message}`;
        }
    }
}

function clearInputFeedback(input) {
    const parent = input.closest('.input-group-custom');
    if (!parent) return;

    input.classList.remove('is-valid-input', 'is-invalid-input');
    input.removeAttribute('aria-invalid');

    parent.querySelectorAll('.validation-message').forEach(el => {
        el.style.display = 'none';
    });
}

/**
 * Live validation requirements checkbox check
 */
function validateRequirements(val) {
    const reqs = {
        length: val.length >= 6,
        upper: /[A-Z]/.test(val),
        lower: /[a-z]/.test(val),
        number: /[0-9]/.test(val),
        special: /[^A-Za-z0-9]/.test(val)
    };

    for (const [key, met] of Object.entries(reqs)) {
        const item = document.getElementById(`req-${key}`);
        if (item) {
            const icon = item.querySelector('i');
            if (met) {
                item.classList.add('valid');
                if (icon) icon.className = 'fas fa-circle-check text-success';
            } else {
                item.classList.remove('valid');
                if (icon) icon.className = 'fas fa-circle-xmark text-muted';
            }
        }
    }
}

/**
 * Strength evaluation algorithm
 */
function checkPasswordStrength(password) {
    let score = 0;
    let feedback = 'Weak';

    if (password.length === 0) return { score: 0, feedback: 'None' };
    if (password.length >= 6) score += 1;
    if (password.length >= 10) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    if (score < 3) {
        feedback = 'Weak';
        return { score: 25, color: '#EF4444', feedback };
    } else if (score < 5) {
        feedback = 'Medium';
        return { score: 60, color: '#F59E0B', feedback };
    } else {
        feedback = 'Strong';
        return { score: 100, color: '#22C55E', feedback };
    }
}

function updatePasswordStrengthBar(result) {
    const bar = document.getElementById('password-strength-bar');
    const text = document.getElementById('password-strength-text');
    if (!bar || !text) return;

    if (result.score === 0) {
        bar.style.width = '0%';
        text.textContent = '';
        return;
    }

    bar.style.width = `${result.score}%`;
    bar.style.backgroundColor = result.color;
    text.textContent = `Strength: ${result.feedback}`;
    text.style.color = result.color;
}
