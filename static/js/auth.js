/**
 * AI Shield Authentication System - Client-side JS
 * Author: Frontend Architect & Senior Product Designer
 */

document.addEventListener('DOMContentLoaded', () => {
    // Add enter class for animations
    const mainContainer = document.querySelector('.auth-split-container');
    if (mainContainer) {
        mainContainer.classList.add('auth-page-enter');
    }

    // Initialize forms
    initPasswordToggles();
    initLoginForm();
    initRegisterForm();
    initForgotPasswordForm();
    initVerifyEmailForm();
    initAlertDismissal();
});

/**
 * Global CSRF helper
 */
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
}

/**
 * Handle password show/hide buttons
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
 * Setup global loading overlay triggers
 */
function showLoading(form) {
    const overlay = form.querySelector('.loading-overlay');
    if (overlay) {
        overlay.style.display = 'flex';
        overlay.setAttribute('aria-hidden', 'false');
    }
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        // Keep original content if stored, or save it
        if (!submitBtn.dataset.originalHtml) {
            submitBtn.dataset.originalHtml = submitBtn.innerHTML;
        }
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> processing...';
    }
}

function hideLoading(form) {
    const overlay = form.querySelector('.loading-overlay');
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

/**
 * Setup close button logic for custom alerts
 */
function initAlertDismissal() {
    document.querySelectorAll('.alert-custom-close').forEach(button => {
        button.addEventListener('click', () => {
            const alert = button.closest('.alert-custom');
            if (alert) {
                alert.style.transition = 'opacity 0.2s ease';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 200);
            }
        });
    });
}

/**
 * Login Form Validation and Logic
 */
function initLoginForm() {
    const form = document.getElementById('login-form');
    if (!form) return;

    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');

    form.addEventListener('submit', (e) => {
        let valid = true;

        // Perform basic validations
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

    // Clear alerts on input
    [emailInput, passwordInput].forEach(input => {
        input.addEventListener('input', () => {
            if (input.classList.contains('is-invalid-input')) {
                clearInputFeedback(input);
            }
        });
    });
}

/**
 * Register Form Live Validation & Async Checks
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

    // Full Name Validation
    fullNameInput.addEventListener('input', () => {
        const value = fullNameInput.value.trim();
        if (value.length < 2) {
            showInputFeedback(fullNameInput, false, 'Enter your full name (at least 2 chars)');
        } else {
            showInputFeedback(fullNameInput, true, 'Name is valid');
        }
    });

    // Username Availability API Check (Debounced)
    usernameInput.addEventListener('input', () => {
        clearTimeout(usernameCheckTimeout);
        const username = usernameInput.value.trim();
        
        if (username.length < 3) {
            showInputFeedback(usernameInput, false, 'Username must be at least 3 characters');
            isUsernameAvailable = false;
            return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            showInputFeedback(usernameInput, false, 'Alphanumeric characters and underscores only');
            isUsernameAvailable = false;
            return;
        }

        // Debounce API call
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
                    // Fail gracefully if API is blocked or locked
                    showInputFeedback(usernameInput, true, 'Username format ok');
                    isUsernameAvailable = true; 
                }
            } catch (err) {
                // Network fail safety
                showInputFeedback(usernameInput, true, 'Username format ok');
                isUsernameAvailable = true;
            }
        }, 400);
    });

    // Email Validation & API Check (Debounced)
    emailInput.addEventListener('input', () => {
        clearTimeout(emailCheckTimeout);
        const email = emailInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            showInputFeedback(emailInput, false, 'Please enter a valid email address');
            isEmailAvailable = false;
            return;
        }

        // Debounce API call
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
                        showInputFeedback(emailInput, false, 'Email address is already registered');
                        isEmailAvailable = false;
                    }
                } else {
                    // Fallback
                    showInputFeedback(emailInput, true, 'Email address structure valid');
                    isEmailAvailable = true;
                }
            } catch (err) {
                // Fallback
                showInputFeedback(emailInput, true, 'Email address structure valid');
                isEmailAvailable = true;
            }
        }, 400);
    });

    // Password Validation & Strength Meter
    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        const result = checkPasswordStrength(val);
        updatePasswordStrengthBar(result);

        if (val.length < 6) {
            showInputFeedback(passwordInput, false, 'Password must be at least 6 characters');
        } else {
            showInputFeedback(passwordInput, true, 'Password meets length requirements');
        }

        // Revalidate confirm password if it contains text
        if (confirmPasswordInput.value) {
            validateConfirmPassword();
        }
    });

    // Confirm Password Validation
    confirmPasswordInput.addEventListener('input', validateConfirmPassword);

    function validateConfirmPassword() {
        if (passwordInput.value !== confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Passwords do not match');
            return false;
        } else if (!confirmPasswordInput.value) {
            showInputFeedback(confirmPasswordInput, false, 'Please confirm your password');
            return false;
        } else {
            showInputFeedback(confirmPasswordInput, true, 'Passwords match');
            return true;
        }
    }

    // Form submission validation
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
        if (!termsInput.checked) {
            const termsBox = document.querySelector('.checkbox-custom-input');
            termsBox.style.borderColor = 'var(--threat-red)';
            setTimeout(() => { termsBox.style.borderColor = ''; }, 3000);
            
            const errorRegion = document.getElementById('aria-live-status');
            if (errorRegion) {
                errorRegion.innerText = 'You must accept the terms & conditions to create an account.';
            }
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
 * Verify Email Form Logic
 */
function initVerifyEmailForm() {
    const form = document.getElementById('verify-email-resend-form');
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
 * Input Feedback Helper
 */
function showInputFeedback(input, isValid, message) {
    const parent = input.closest('.input-group-custom');
    if (!parent) return;

    // Remove old state
    input.classList.remove('is-valid-input', 'is-invalid-input');
    
    // Find validation message nodes
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

    // Hide both initially
    validMsg.style.display = 'none';
    invalidMsg.style.display = 'none';

    // Set accessibility
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
        
        // Announce error to screen readers
        const liveStatus = document.getElementById('aria-live-status');
        if (liveStatus) {
            liveStatus.textContent = `Error in ${input.id} field: ${message}`;
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
 * Password strength evaluation algorithm
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

    // Normalize rating
    if (score < 3) {
        feedback = 'Weak';
        return { score: 25, color: 'var(--threat-red)', feedback };
    } else if (score < 5) {
        feedback = 'Medium';
        return { score: 60, color: 'var(--cyber-blue)', feedback };
    } else {
        feedback = 'Strong';
        return { score: 100, color: 'var(--security-green)', feedback };
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
