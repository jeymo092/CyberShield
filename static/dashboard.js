const API_URL = window.location.origin;

// Token management
const tokenStorage = {
    encrypt: (text) => window.btoa(text),
    decrypt: (text) => window.atob(text),
    getToken: () => {
        // First try localStorage
        const token = localStorage.getItem('token');
        if (token) {
            return tokenStorage.decrypt(token);
        }
        
        // Then try cookie
        const cookieToken = document.cookie
            .split('; ')
            .find(row => row.startsWith('auth_token='))
            ?.split('=')[1];
            
        if (cookieToken) {
            // Store in localStorage for persistence
            localStorage.setItem('token', tokenStorage.encrypt(cookieToken));
            return cookieToken;
        }
        
        return null;
    },
    setToken: (token) => {
        if (token) {
            localStorage.setItem('token', tokenStorage.encrypt(token));
            // Also set as cookie for better persistence
            const maxAge = 7 * 24 * 60 * 60; // 7 days
            document.cookie = `auth_token=${token}; path=/; max-age=${maxAge}; samesite=lax`;
        }
    },
    removeToken: () => {
        localStorage.removeItem('token');
        document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }
};

// Check authentication
async function checkAuth() {
    try {
        const token = tokenStorage.getToken();
        if (!token) {
            console.log('No token found, redirecting to auth page');
            window.location.href = '/static/auth.html';
            return;
        }

        const response = await fetch(`${API_URL}/auth/status`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Auth check failed');
        }

        const data = await response.json();
        if (!data.authenticated) {
            console.log('Not authenticated, redirecting to auth page');
            tokenStorage.removeToken();
            window.location.href = '/static/auth.html';
            return;
        }

        console.log('Authentication successful');
        updateProfileInfo(data.user);
        
    } catch (error) {
        console.error('Auth check failed:', error);
        tokenStorage.removeToken();
        window.location.href = '/static/auth.html';
    }
}

// Update profile information
function updateProfileInfo(user) {
    // Update username
    const userNameElement = document.getElementById('user-name');
    if (userNameElement) {
        userNameElement.textContent = user.username;
    }

    // Update email
    const userEmailElement = document.getElementById('user-email');
    if (userEmailElement) {
        userEmailElement.textContent = user.email;
    }

    // Update avatar if available from OAuth
    const userAvatarElement = document.getElementById('user-avatar');
    if (userAvatarElement && user.oauth_data && user.oauth_data.picture) {
        userAvatarElement.src = user.oauth_data.picture;
    }
}

// Security score calculation
function calculateSecurityScore(user) {
    let score = 50; // Base score
    
    // Add points for various security measures
    if (user.email) score += 10;
    if (user.oauth_provider) score += 15;
    // Add more security checks here
    
    return Math.min(score, 100); // Cap at 100
}

// Update security recommendations
function updateRecommendations(user) {
    const recommendationsList = document.getElementById('recommendations-list');
    const recommendations = [];

    if (!user.oauth_provider) {
        recommendations.push({
            icon: '🔗',
            title: 'Link Social Account',
            description: 'Connect your Google account for enhanced security'
        });
    }

    recommendations.push({
        icon: '🔐',
        title: 'Enable Two-Factor Authentication',
        description: 'Add an extra layer of security to your account'
    });

    recommendationsList.innerHTML = recommendations.map(rec => `
        <li class="recommendation-item">
            <span class="recommendation-icon">${rec.icon}</span>
            <div class="recommendation-content">
                <h3>${escapeHtml(rec.title)}</h3>
                <p>${escapeHtml(rec.description)}</p>
            </div>
        </li>
    `).join('');
}

// Update activity list
function updateActivityList() {
    const activityList = document.getElementById('activity-list');
    const currentTime = new Date().toLocaleTimeString();
    
    activityList.innerHTML = `
        <div class="activity-item">
            <span class="activity-time">${escapeHtml(currentTime)}</span>
            <span class="activity-text">Logged in successfully</span>
        </div>
    `;
}

// Logout functionality
async function logout() {
    const token = tokenStorage.getToken();
    if (!token) return;

    try {
        await fetch(`${API_URL}/auth/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
    } catch (error) {
        console.error('Logout failed:', error);
    }

    tokenStorage.removeToken();
    window.location.href = '/static/auth.html';
}

// XSS prevention
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Event listeners
document.getElementById('logout-btn').addEventListener('click', logout);

document.getElementById('change-password-btn').addEventListener('click', () => {
    // Implement password change functionality
    alert('Password change functionality coming soon!');
});

document.getElementById('enable-2fa-btn').addEventListener('click', () => {
    // Implement 2FA functionality
    alert('2FA functionality coming soon!');
});

// Handle sticky header
function handleStickyHeader() {
    const navbar = document.querySelector('.navbar');
    const scrolled = window.scrollY > 10;
    navbar.classList.toggle('scrolled', scrolled);
}

// Add scroll event listener
window.addEventListener('scroll', handleStickyHeader);
handleStickyHeader(); // Initial call

// Initialize dashboard
checkAuth(); 