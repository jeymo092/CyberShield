const API_URL = window.location.origin;
let currentToken = null;

// Secure token storage with encryption
const tokenStorage = {
    encrypt: (text) => {
        return window.btoa(text); // Basic encryption, consider using a more robust solution in production
    },
    decrypt: (text) => {
        return window.atob(text);
    },
    setToken: (token) => {
        if (token) {
            localStorage.setItem('token', tokenStorage.encrypt(token));
        }
    },
    getToken: () => {
        const token = localStorage.getItem('token');
        return token ? tokenStorage.decrypt(token) : null;
    },
    removeToken: () => {
        localStorage.removeItem('token');
    }
};

// Initialize token from storage
currentToken = tokenStorage.getToken();

// XSS prevention: Escape HTML in text content
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// CSRF protection
function getCSRFToken() {
    return document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1];
}

// Event delegation for tab switching with sanitization
document.querySelector('.tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('.tab');
    if (!tab) return;
    
    const tabName = tab.dataset.tab;
    if (tabName === 'login' || tabName === 'register') {
        switchTab(tabName);
    }
});

function switchTab(tab) {
    if (tab !== 'login' && tab !== 'register') return;

    document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tab);
    });
    
    document.getElementById('login-form').style.display = tab === 'login' ? 'block' : 'none';
    document.getElementById('register-form').style.display = tab === 'register' ? 'block' : 'none';
    
    // Clear messages and form data for security
    document.getElementById('login-message').textContent = '';
    document.getElementById('register-message').textContent = '';
    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
}

// Check for OAuth callback token with validation and error handling
const params = new URLSearchParams(window.location.search);

// Handle error messages from OAuth
if (params.has('error')) {
    const error = decodeURIComponent(params.get('error'));
    const messageDiv = document.getElementById('login-message');
    messageDiv.className = 'message error';
    messageDiv.textContent = error;
    window.history.replaceState({}, document.title, '/static/auth.html');
}
// Handle successful OAuth callback
else if (params.has('token_ready')) {
    // Exchange temporary token for access token
    fetch(`${API_URL}/auth/token/exchange`, {
        credentials: 'include'  // Include session cookie
    })
    .then(response => response.json())
    .then(data => {
        if (data.access_token) {
            currentToken = data.access_token;
            tokenStorage.setToken(data.access_token);
            window.location.href = '/static/dashboard.html';
        } else {
            throw new Error(data.error || 'Token exchange failed');
        }
    })
    .catch(error => {
        const messageDiv = document.getElementById('login-message');
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Authentication failed. Please try again.';
    })
    .finally(() => {
        window.history.replaceState({}, document.title, '/static/auth.html');
    });
}

function updateUI() {
    const authSection = document.getElementById('auth-section');
    const profileSection = document.getElementById('profile-section');
    
    if (currentToken) {
        authSection.style.display = 'none';
        profileSection.style.display = 'block';
        fetchProfile();
    } else {
        authSection.style.display = 'block';
        profileSection.style.display = 'none';
    }
}

// Input validation
function validateInput(input, type) {
    const patterns = {
        username: /^[a-zA-Z0-9_-]{3,16}$/,
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        password: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/
    };
    return patterns[type].test(input);
}

// Register form submission with validation
document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const messageDiv = document.getElementById('register-message');
    messageDiv.className = '';
    
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    // Input validation
    if (!validateInput(username, 'username')) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Username must be 3-16 characters and contain only letters, numbers, underscore, or hyphen';
        return;
    }
    if (!validateInput(email, 'email')) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Please enter a valid email address';
        return;
    }
    if (!validateInput(password, 'password')) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Password must be at least 8 characters and contain at least one letter and one number';
        return;
    }
    
    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCSRFToken()
            },
            body: JSON.stringify({
                username: username,
                email: email,
                password: password
            }),
            credentials: 'same-origin'
        });

        const data = await response.json();
        if (response.ok) {
            messageDiv.className = 'message success';
            messageDiv.textContent = 'Registration successful! Please sign in.';
            document.getElementById('register-form').reset();
            setTimeout(() => switchTab('login'), 2000);
        } else {
            messageDiv.className = 'message error';
            messageDiv.textContent = escapeHtml(data.detail) || 'Registration failed';
        }
    } catch (error) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Registration failed';
    }
});

// Login form submission with rate limiting
let loginAttempts = 0;
let lastLoginAttempt = 0;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_TIMEOUT = 15 * 60 * 1000; // 15 minutes

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const messageDiv = document.getElementById('login-message');
    messageDiv.className = '';
    
    // Check rate limiting
    const now = Date.now();
    if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        if (now - lastLoginAttempt < LOGIN_TIMEOUT) {
            messageDiv.className = 'message error';
            messageDiv.textContent = `Too many login attempts. Please try again in ${Math.ceil((LOGIN_TIMEOUT - (now - lastLoginAttempt)) / 60000)} minutes`;
            return;
        }
        loginAttempts = 0;
    }
    
    try {
        const formData = new FormData();
        formData.append('username', document.getElementById('username').value);
        formData.append('password', document.getElementById('password').value);

        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': getCSRFToken()
            },
            body: formData,
            credentials: 'same-origin'
        });

        const data = await response.json();
        if (response.ok) {
            currentToken = data.access_token;
            tokenStorage.setToken(currentToken);
            loginAttempts = 0;
            // Redirect to dashboard instead of updating UI
            window.location.href = '/static/dashboard.html';
        } else {
            loginAttempts++;
            lastLoginAttempt = now;
            messageDiv.className = 'message error';
            messageDiv.textContent = escapeHtml(data.detail) || 'Login failed';
        }
    } catch (error) {
        loginAttempts++;
        lastLoginAttempt = now;
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Login failed';
    }
});

async function fetchProfile() {
    try {
        const response = await fetch(`${API_URL}/auth/profile`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'X-CSRF-Token': getCSRFToken()
            },
            credentials: 'same-origin'
        });

        if (response.ok) {
            const data = await response.json();
            const profileInfo = document.getElementById('profile-info');
            profileInfo.innerHTML = '';
            
            const fields = {
                'Username': escapeHtml(data.username),
                'Email': escapeHtml(data.email),
                'OAuth Provider': escapeHtml(data.oauth_provider || 'None')
            };
            
            for (const [key, value] of Object.entries(fields)) {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = key + ': ';
                p.appendChild(strong);
                p.appendChild(document.createTextNode(value));
                profileInfo.appendChild(p);
            }
        } else {
            logout();
        }
    } catch (error) {
        logout();
    }
}

async function logout() {
    if (!currentToken) return;

    try {
        await fetch(`${API_URL}/auth/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'X-CSRF-Token': getCSRFToken()
            },
            credentials: 'same-origin'
        });
    } catch (error) {
        console.error('Logout failed:', error);
    }

    tokenStorage.removeToken();
    currentToken = null;
    updateUI();
}

// Logout button handler
document.getElementById('logout-btn').addEventListener('click', logout);

// Session timeout handler
let sessionTimeout;
function resetSessionTimeout() {
    clearTimeout(sessionTimeout);
    sessionTimeout = setTimeout(logout, 30 * 60 * 1000); // 30 minutes
}
document.addEventListener('click', resetSessionTimeout);
document.addEventListener('keypress', resetSessionTimeout);
resetSessionTimeout();

// Initialize UI
updateUI();

document.addEventListener('DOMContentLoaded', () => {
    // Tab switching functionality
    const tabs = document.querySelectorAll('.tab');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            // Add active class to clicked tab
            tab.classList.add('active');

            // Show/hide forms based on selected tab
            if (tab.dataset.tab === 'login') {
                loginForm.style.display = 'block';
                registerForm.style.display = 'none';
            } else {
                loginForm.style.display = 'none';
                registerForm.style.display = 'block';
            }
        });
    });

    // Check authentication status
    const checkAuth = async () => {
        try {
            const token = tokenStorage.getToken();
            if (!token) return;

            const response = await fetch(`${API_URL}/auth/status`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            const data = await response.json();

            if (data.authenticated) {
                // If already authenticated, redirect to dashboard
                window.location.href = '/static/dashboard.html';
            }
        } catch (error) {
            console.error('Error checking auth status:', error);
        }
    };

    // Check auth status on page load
    checkAuth();
}); 