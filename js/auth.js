// Verification state
let currentVerificationType = null; // 'signup' or 'login'
let pendingUsername = null;

// DOM Elements
const verificationOverlay = document.getElementById('verificationOverlay');
const verificationMessage = document.getElementById('verificationMessage');
const verificationCode = document.getElementById('verificationCode');
const verificationError = document.getElementById('verificationError');
const verifyBtn = document.getElementById('verifyBtn');
const resendBtn = document.getElementById('resendBtn');
const closeVerification = document.getElementById('closeVerification');
const otpDigits = document.querySelectorAll('.otp-digit');

// Handle URL parameters for email verification
function handleUrlParameters() {
  const urlParams = new URLSearchParams(window.location.search);
  const verified = urlParams.get('verified');
  const username = urlParams.get('username');
  const token = urlParams.get('token');
  const error = urlParams.get('error');
  
  if (verified === 'true' && username && token) {
    // Successful email verification
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', username);
    
    // Show success message and redirect
    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 1000);
  } else if (error) {
    // Handle verification errors
    const errorMessages = {
      'missing_params': 'Invalid verification link. Please try again.',
      'invalid_user': 'Invalid user or already verified.',
      'invalid_code': 'Invalid verification code.',
      'expired': 'Verification link has expired.',
      'verification_failed': 'Verification failed. Please try again.'
    };
    
    const errorMessage = errorMessages[error] || 'Verification error occurred.';
    
    // Show error on signup form
    if (signupError) {
      signupError.textContent = errorMessage;
      signupError.style.color = 'red';
    }
  }
}

// Check URL parameters on page load
document.addEventListener('DOMContentLoaded', handleUrlParameters);

// Global toggle password visibility
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('toggle-password')) {
    const targetId = e.target.getAttribute('data-target');
    const passwordInput = document.getElementById(targetId);
    
    if (passwordInput) {
      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        e.target.classList.remove('fa-eye');
        e.target.classList.add('fa-eye-slash');
      } else {
        passwordInput.type = 'password';
        e.target.classList.remove('fa-eye-slash');
        e.target.classList.add('fa-eye');
      }
    }
  }
});

// Show verification overlay
function showVerificationOverlay(type, username, message) {
  currentVerificationType = type;
  pendingUsername = username;
  verificationMessage.textContent = message;
  verificationError.textContent = '';
  verificationCode.value = '';

  // Clear OTP digits
  otpDigits.forEach(digit => digit.value = '');

  // Remove inline display:none and show the overlay
  verificationOverlay.style.display = 'flex';
  // Force browser reflow to ensure display change is processed
  void verificationOverlay.offsetWidth;
  // Add show class to trigger CSS transition
  verificationOverlay.classList.add('show');
}

// Hide verification overlay
function hideVerificationOverlay() {
  verificationOverlay.classList.remove('show');
  setTimeout(() => {
    verificationOverlay.style.display = 'none';
    currentVerificationType = null;
    pendingUsername = null;
  }, 300);
}

// Handle OTP input navigation with paste support
otpDigits.forEach((digit, index) => {
  digit.addEventListener('input', (e) => {
    // Only allow digits
    e.target.value = e.target.value.replace(/\D/g, '');

    if (e.target.value.length === 1 && index < otpDigits.length - 1) {
      otpDigits[index + 1].focus();
    }
    // Update hidden input
    const otpValue = Array.from(otpDigits).map(d => d.value).join('');
    verificationCode.value = otpValue;
  });

  digit.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
      otpDigits[index - 1].focus();
    }
  });

  // Handle paste event for the entire OTP
  digit.addEventListener('paste', (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);

    if (pastedData.length > 0) {
      pastedData.split('').forEach((char, i) => {
        if (otpDigits[i]) {
          otpDigits[i].value = char;
        }
      });
      // Update hidden input
      verificationCode.value = pastedData;
      // Focus the next empty digit or the last one
      const nextIndex = Math.min(pastedData.length, otpDigits.length - 1);
      otpDigits[nextIndex].focus();
    }
  });
});

// Sync main input with OTP digits
verificationCode.addEventListener('input', (e) => {
  const value = e.target.value.replace(/\D/g, '').slice(0, 6);
  e.target.value = value;
  
  // Update OTP digits
  value.split('').forEach((digit, index) => {
    if (otpDigits[index]) {
      otpDigits[index].value = digit;
    }
  });
});

// Close button handler
closeVerification.addEventListener('click', hideVerificationOverlay);

// Click outside to close
verificationOverlay.addEventListener('click', (e) => {
  if (e.target === verificationOverlay) {
    hideVerificationOverlay();
  }
});

// Verify button handler
verifyBtn.addEventListener('click', async () => {
  // Collect values from all six OTP digit inputs using Array.from for robustness
  const code = Array.from(otpDigits).map(input => input.value).join('');
  
  if (!code || code.length !== 6) {
    verificationError.textContent = 'Please enter a 6-digit code';
    verificationError.style.color = 'red';
    return;
  }
  
  verifyBtn.disabled = true;
  verifyBtn.textContent = 'Verifying...';
  
  try {
    const endpoint = currentVerificationType === 'signup' ? '/api/verify-signup' : '/api/verify-login';
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: pendingUsername, code })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      verificationError.textContent = data.message;
      verificationError.style.color = 'green';

      // Store token for both signup and login verification
      if (data.token) {
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('username', data.username);
      }

      if (currentVerificationType === 'signup') {
        // For signup, show success then redirect to dashboard (auto-login)
        setTimeout(() => {
          if (data.token) {
            hideVerificationOverlay();
            window.location.href = 'dashboard.html';
          } else {
            // Fallback: hide overlay and switch to login panel if no token
            hideVerificationOverlay();
            setTimeout(() => {
              document.getElementById('signInBtn').click();
            }, 350);
          }
        }, 2000);
      } else {
        // For login, redirect to dashboard
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1500);
      }
    } else {
      verificationError.textContent = data.error;
      verificationError.style.color = 'red';
    }
  } catch (error) {
    console.error('Verification error:', error);
    verificationError.textContent = 'Network error. Please try again.';
    verificationError.style.color = 'red';
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Verify';
  }
});

// Resend button handler
resendBtn.addEventListener('click', async () => {
  resendBtn.disabled = true;
  resendBtn.textContent = 'Sending...';
  
  try {
    if (currentVerificationType === 'signup') {
      // For signup, we need to call register again (backend will handle email)
      const email = document.getElementById('reg-email').value;
      const password = document.getElementById('reg-password').value;
      
      const response = await fetch(`${API_BASE_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: pendingUsername, email, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        verificationError.textContent = 'Verification code sent!';
        verificationError.style.color = 'green';
      } else {
        verificationError.textContent = data.error;
        verificationError.style.color = 'red';
      }
    } else {
      // For login, we need to call login again to trigger new OTP
      const password = document.getElementById('login-password').value;
      
      const response = await fetch(`${API_BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: pendingUsername, password })
      });
      
      const data = await response.json();
      
      if (response.ok && data.status === 'verification_required') {
        verificationError.textContent = 'New verification code sent!';
        verificationError.style.color = 'green';
      } else {
        verificationError.textContent = data.error || 'Failed to resend code';
        verificationError.style.color = 'red';
      }
    }
  } catch (error) {
    console.error('Resend error:', error);
    verificationError.textContent = 'Network error. Please try again.';
    verificationError.style.color = 'red';
  } finally {
    resendBtn.disabled = false;
    resendBtn.textContent = 'Resend Code';
  }
});

// Handle User Registration
const signupBtn = document.getElementById("signupBtn");
const signupError = document.getElementById("signup-error");
if (signupBtn) {
  // Clear error when user starts typing
  const signupInputs = document.querySelectorAll("#signupForm input");
  signupInputs.forEach(input => {
    input.addEventListener("input", () => {
      signupError.textContent = "";
    });
  });

  signupBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    signupError.textContent = ""; // Clear previous error

    const username = document.getElementById("reg-username").value;
    const email = document.getElementById("reg-email").value;
    const password = document.getElementById("reg-password").value;
    const confirmPassword = document.getElementById("reg-confirm-password").value;

    // Validate password confirmation
    if (password !== confirmPassword) {
      signupError.textContent = "Passwords do not match";
      signupError.style.color = "red";
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });
      const data = await response.json();

      if (response.ok) {
        // Check if this is a new registration (201) or recovery of unverified user (200)
        const isRecovery = response.status === 200 && data.message && data.message.includes('resent');
        
        // Hide form inputs and show email confirmation message
        const signupForm = document.getElementById('signupForm');
        const formInputs = signupForm.querySelectorAll('input:not([type="button"])');
        const socialContainer = signupForm.querySelector('.social-container');
        const formSpan = signupForm.querySelector('span');
        
        // Hide all form elements except the button
        formInputs.forEach(input => input.style.display = 'none');
        if (socialContainer) socialContainer.style.display = 'none';
        if (formSpan) formSpan.style.display = 'none';
        
        // Show success message and change button
        signupError.innerHTML = '✅ Registration initiated!<br><br><strong>Go check your email</strong> and select "Complete Registration" below to create your account.';
        signupError.style.color = "#4CAF50";
        signupError.style.fontSize = "1.1rem";
        signupError.style.lineHeight = "1.6";
        
        // Change button to "Complete Registration"
        signupBtn.textContent = 'Complete Registration';
        signupBtn.onclick = () => showVerificationOverlay('signup', username, 'Please enter the 6-digit verification code sent to your email to complete your registration.');
      } else {
        signupError.textContent = data.error;
        signupError.style.color = "red";
      }
    } catch (error) {
      console.error("Auth Error:", error);
      signupError.textContent = "Network error. Please try again.";
      signupError.style.color = "red";
    }
  });
}

// Handle User Login
const loginBtn = document.getElementById("loginBtn");
const loginError = document.getElementById("login-error");
if (loginBtn) {
  // Clear error when user starts typing
  const loginInputs = document.querySelectorAll("#loginForm input");
  loginInputs.forEach(input => {
    input.addEventListener("input", () => {
      loginError.textContent = "";
    });
  });

  loginBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    loginError.textContent = ""; // Clear previous error

    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    try {
      const response = await fetch(`${API_BASE_URL}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();

      if (response.ok) {
        if (data.status === 'verification_required') {
          // Check if this is an unverified account recovery (from login) or new IP verification
          const isUnverifiedRecovery = data.message && data.message.includes('verify your email');
          const verificationType = isUnverifiedRecovery ? 'signup' : 'login';
          const overlayMessage = isUnverifiedRecovery 
            ? 'Please enter the 6-digit verification code sent to your email to complete your registration.'
            : 'New IP detected. Please enter the 6-digit verification code sent to your email.';
          
          loginError.textContent = data.message;
          loginError.style.color = isUnverifiedRecovery ? "orange" : "blue";
          showVerificationOverlay(verificationType, username, overlayMessage);
        } else {
          // Normal login successful
          console.log("Login successful!");
          
          // Store token if provided
          if (data.token) {
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('username', data.username);
          }
          
          window.location.href = "dashboard.html";
        }
      } else {
        loginError.textContent = data.error;
        loginError.style.color = "red";
      }
    } catch (error) {
      console.error("Auth Error:", error);
      loginError.textContent = "Network error. Please try again.";
      loginError.style.color = "red";
    }
  });
}
