/**
 * Cybersecurity Platform - Dashboard JavaScript
 * White-label Product Edition
 */

let state = {
  authToken: null,
  currentUser: null,
  lastLoginPassword: '',
  requiresPasswordChange: false,
  scans: [],
  lastStatuses: {},
  selectedScanId: null,
  pollTimer: null,
  reportSelections: {},
  searchQuery: '',
  newsHeadlines: [],
  newsIndex: 0,
  newsTypeTimer: null,
  newsRotateTimer: null,
  newsRefreshTimer: null,
  durationTicker: null,
  scanDateFilter: '',
  scanStatusFilter: 'all',
  postureSummary: null,
  postureFetchedAt: 0,
  onboardingProfile: null,
  onboardingFetchedAt: 0
};
const CHATBOT_AVATAR = {
  dark: '/static/dragon_ai_icon.svg?v=9',
  light: '/static/dragon_ai_icon_light.svg?v=2'
};

function getCurrentTheme() {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function getChatbotAvatarSrc(theme) {
  const t = theme === 'light' ? 'light' : 'dark';
  return CHATBOT_AVATAR[t] || CHATBOT_AVATAR.dark;
}

const LOADING_MIN_VISIBLE_MS = 4600;
const LOADING_FINALE_MS = 1500;
const LOADING_FADEOUT_MS = 520;
const ADMIN_ONLY_PAGES = new Set(['onboarding']);

// ============================================
// THEME (DARK/LIGHT) - persisted in localStorage
// ============================================
const THEME_STORAGE_KEY = 'dih_theme';

function getPreferredTheme() {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch (e) {}
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function dockThemeToggle(mode) {
  const btn = document.getElementById('themeToggleBtn');
  if (!btn) return;

  // Mode: 'floating' (login) or 'docked' (navbar status area)
  const wantDocked = mode === 'docked';
  btn.classList.toggle('docked', wantDocked);

  if (wantDocked) {
    const statusIndicator = document.querySelector('.top-navbar .status-indicator');
    const dot = statusIndicator?.querySelector('.status-dot');
    if (statusIndicator) {
      // Put toggle between the dot and the text (left-side free space requested)
      if (dot && dot.parentElement === statusIndicator) {
        dot.insertAdjacentElement('afterend', btn);
      } else {
        statusIndicator.insertBefore(btn, statusIndicator.firstChild);
      }
      return;
    }
  }

  // fallback: keep it at end of body (top-right floating)
  document.body.appendChild(btn);
}

function applyTheme(theme) {
  const next = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch (e) {}

  // Update icon
  const icon = document.getElementById('themeToggleIcon');
  if (icon) {
    icon.classList.remove('fa-sun', 'fa-moon');
    icon.classList.add(next === 'light' ? 'fa-moon' : 'fa-sun');
  }

  // Swap any themed logos (data-logo-dark/light)
  document.querySelectorAll('img[data-logo-dark][data-logo-light]').forEach((img) => {
    const darkSrc = img.getAttribute('data-logo-dark');
    const lightSrc = img.getAttribute('data-logo-light');
    if (!darkSrc || !lightSrc) return;
    img.src = next === 'light' ? lightSrc : darkSrc;
  });

  updateChatbotBranding(next);
}


function updateChatbotBranding(theme) {
  const currentTheme = theme === 'light' ? 'light' : 'dark';
  const avatarSrc = getChatbotAvatarSrc(currentTheme);

  // Update assistant avatars inside chat messages / typing indicator
  document.querySelectorAll('img.chatbot-avatar-logo').forEach((img) => {
    if (img.getAttribute('src') !== avatarSrc) img.setAttribute('src', avatarSrc);
  });

  // Update ALL branded dragon logos/icons (welcome logo, AI card icon, etc.)
  document.querySelectorAll('img.chatbot-brand-logo, img.card-dragon-icon').forEach((img) => {
    const darkSrc = img.getAttribute('data-logo-dark') || '/static/dragon_ai_icon.svg?v=9';
    const lightSrc = img.getAttribute('data-logo-light') || '/static/dragon_ai_icon_light.svg?v=2';
    img.src = currentTheme === 'light' ? lightSrc : darkSrc;
  });
}


function setupThemeToggle() {
  const btn = document.getElementById('themeToggleBtn');
  // Apply immediately (also keeps loading/login consistent after navigation)
  applyTheme(getPreferredTheme());
  dockThemeToggle('floating');
  if (!btn) return;

  btn.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'light' ? 'dark' : 'light');
  });
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function setAuth(username, password) {
  state.authToken = 'Basic ' + btoa(`${username}:${password}`);
  state.lastLoginPassword = password || '';
}

async function fetchWithAuth(url, options = {}) {
  if (!state.authToken) throw new Error('Not authenticated');
  const headers = options.headers ? { ...options.headers } : {};
  headers.Authorization = state.authToken;
  return fetch(url, { ...options, headers });
}

function isAdminUser() {
  return !!state.currentUser?.is_admin;
}

function shouldPromptStepUp() {
  return !!state.currentUser && !isAdminUser();
}

function buildAvatarDataUri(username) {
  const label = encodeURIComponent(((username || 'U').trim().charAt(0) || 'U').toUpperCase());
  return `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='40' height='40'%3E%3Ccircle cx='20' cy='20' r='20' fill='%2300ff9f'/%3E%3Ctext x='50%25' y='50%25' text-anchor='middle' dy='.3em' fill='%230a0e27' font-family='Arial' font-size='16' font-weight='bold'%3E${label}%3C/text%3E%3C/svg%3E`;
}

function updateCurrentUser(user) {
  state.currentUser = user || null;
  state.requiresPasswordChange = !!user?.must_change_password;
  const profile = document.getElementById('userProfile');
  const userName = profile?.querySelector('.user-name');
  const userRole = document.getElementById('userRoleLabel');
  const avatar = profile?.querySelector('img');
  if (userName) userName.textContent = user?.username || 'User';
  if (userRole) userRole.textContent = (user?.role || 'user').toUpperCase();
  if (avatar) {
    avatar.src = buildAvatarDataUri(user?.username || 'U');
    avatar.alt = user?.username || 'User';
  }
  document.querySelectorAll('.admin-only').forEach((el) => {
    el.style.display = isAdminUser() ? 'flex' : 'none';
  });
  if (!isAdminUser()) {
    const onboardingPage = document.getElementById('onboardingPage');
    if (onboardingPage?.classList.contains('active')) {
      showPage('dashboard');
    }
  }
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatDate(value) {
  if (!value) return 'Unknown';
  return new Date(value).toLocaleString('en-US', { timeZone: 'Asia/Dubai', hour12: true });
}

function parseTimestampMs(value) {
  if (!value) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  const utcLike = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw;
  const ms = Date.parse(utcLike);
  return Number.isFinite(ms) ? ms : null;
}

function computeScanDurationSeconds(scan, nowMs = Date.now()) {
  const status = String(scan?.status || '').toLowerCase();
  const createdMs = parseTimestampMs(scan?.created_at);
  const startedMs = parseTimestampMs(scan?.started_at);
  const completedMs = parseTimestampMs(scan?.completed_at);

  if (status === 'pending') return 0;
  if (status === 'running') {
    if (!startedMs) return 0;
    return Math.max(0, Math.floor((nowMs - startedMs) / 1000));
  }
  const baseMs = startedMs ?? createdMs;
  if (!baseMs) return Math.max(0, Number(scan?.duration || 0));
  const endMs = completedMs ?? nowMs;
  return Math.max(0, Math.floor((endMs - baseMs) / 1000));
}

function formatDuration(seconds) {
  const value = Math.max(0, Math.floor(Number(seconds) || 0));
  return `${value}s`;
}

function updateLiveDurationLabels() {
  const nodes = document.querySelectorAll('.scan-duration-live');
  if (!nodes.length) return;
  const nowMs = Date.now();
  nodes.forEach((node) => {
    const status = String(node.dataset.status || '').toLowerCase();
    const scan = {
      status,
      created_at: node.dataset.createdAt || '',
      started_at: node.dataset.startedAt || '',
      completed_at: node.dataset.completedAt || '',
      duration: Number(node.dataset.duration || 0)
    };
    const seconds = computeScanDurationSeconds(scan, nowMs);
    node.textContent = formatDuration(seconds);
  });
}

function ensureDurationTicker() {
  if (state.durationTicker) return;
  state.durationTicker = setInterval(updateLiveDurationLabels, 1000);
}

function notify(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  document.body.appendChild(notification);
  setTimeout(() => notification.classList.add('show'), 100);
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 300);
  }, 3200);
}

let pendingActionPasswordResolve = null;

function closeActionPasswordModal(value = null) {
  const modal = document.getElementById('actionPasswordModal');
  const input = document.getElementById('actionPasswordInput');
  const error = document.getElementById('actionPasswordError');
  if (modal) modal.style.display = 'none';
  if (input) input.value = '';
  if (error) {
    error.style.display = 'none';
    error.textContent = '';
  }
  if (pendingActionPasswordResolve) {
    pendingActionPasswordResolve(value);
    pendingActionPasswordResolve = null;
  }
}

function requestActionPassword(actionLabel) {
  if (!shouldPromptStepUp()) return Promise.resolve('');
  const modal = document.getElementById('actionPasswordModal');
  const subtitle = document.getElementById('actionPasswordSubtitle');
  const input = document.getElementById('actionPasswordInput');
  const error = document.getElementById('actionPasswordError');
  if (!modal || !input) return Promise.resolve(null);
  if (error) {
    error.style.display = 'none';
    error.textContent = '';
  }
  if (subtitle) subtitle.textContent = `Re-enter your password to continue: ${actionLabel}.`;
  modal.style.display = 'flex';
  setTimeout(() => input.focus(), 0);
  return new Promise((resolve) => {
    pendingActionPasswordResolve = resolve;
  });
}

async function fetchSensitiveWithStepUp(url, options = {}, actionLabel = 'this action') {
  if (!shouldPromptStepUp()) return fetchWithAuth(url, options);
  const password = await requestActionPassword(actionLabel);
  if (!password) throw new Error('Password verification cancelled.');
  const headers = options.headers ? { ...options.headers } : {};
  headers['X-Action-Password'] = password;
  return fetchWithAuth(url, { ...options, headers });
}

function showLoadingOverlay(overlay) {
  if (!overlay) return 0;
  const container = overlay.querySelector('.loading-container');
  if (container) container.classList.remove('complete', 'kali-sequence');
  overlay.style.display = 'block';
  // Force reflow so transitions restart when logging in again.
  void overlay.offsetWidth;
  overlay.classList.add('is-visible');
  return performance.now();
}

async function hideLoadingOverlay(overlay, shownAt = 0) {
  if (!overlay) return;
  if (!overlay.classList.contains('is-visible') && overlay.style.display === 'none') return;
  const elapsed = performance.now() - shownAt;
  if (shownAt > 0 && elapsed < LOADING_MIN_VISIBLE_MS) {
    await wait(LOADING_MIN_VISIBLE_MS - elapsed);
  }
  const container = overlay.querySelector('.loading-container');
  if (container) {
    container.classList.add('kali-sequence');
    await wait(LOADING_FINALE_MS);
  }
  if (container) container.classList.add('complete');
  overlay.classList.remove('is-visible');
  await wait(LOADING_FADEOUT_MS);
  if (container) container.classList.remove('complete', 'kali-sequence');
  overlay.style.display = 'none';
}

// ============================================
// LOGIN HANDLING
// ============================================

document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();

  const loginForm = document.getElementById('loginForm');
  const loginScreen = document.getElementById('loginScreen');
  const mainDashboard = document.getElementById('mainDashboard');
  const loginError = document.getElementById('loginError');
  const loadingOverlay = document.getElementById('loadingOverlay');
  const forgotPasswordBtn = document.getElementById('forgotPasswordBtn');
  const passwordModal = document.getElementById('passwordModal');
  const passwordModalTitle = document.getElementById('passwordModalTitle');
  const passwordModalSubtitle = document.getElementById('passwordModalSubtitle');
  const closePasswordModalBtn = document.getElementById('closePasswordModal');
  const cancelPasswordModalBtn = document.getElementById('cancelPasswordModal');
  const changePasswordForm = document.getElementById('changePasswordForm');
  const changePasswordError = document.getElementById('changePasswordError');
  const changePasswordSuccess = document.getElementById('changePasswordSuccess');
  const changePasswordSubmitBtn = document.getElementById('changePasswordSubmitBtn');
  const actionPasswordModal = document.getElementById('actionPasswordModal');
  const closeActionPasswordModalBtn = document.getElementById('closeActionPasswordModal');
  const cancelActionPasswordBtn = document.getElementById('cancelActionPasswordBtn');
  const confirmActionPasswordBtn = document.getElementById('confirmActionPasswordBtn');
  const actionPasswordInput = document.getElementById('actionPasswordInput');
  const actionPasswordError = document.getElementById('actionPasswordError');
  const createUserBtn = document.getElementById('createUserBtn');
  const createUserModal = document.getElementById('createUserModal');
  const closeCreateUserModalBtn = document.getElementById('closeCreateUserModal');
  const closeUserManagementBtn = document.getElementById('closeUserManagementBtn');
  const createUserForm = document.getElementById('createUserForm');
  const createUserError = document.getElementById('createUserError');
  const createUserSuccess = document.getElementById('createUserSuccess');
  const createUserSubmitBtn = document.getElementById('createUserSubmitBtn');
  const deleteUserForm = document.getElementById('deleteUserForm');
  const deleteUserSelect = document.getElementById('deleteUserSelect');
  const deleteUserError = document.getElementById('deleteUserError');
  const deleteUserSuccess = document.getElementById('deleteUserSuccess');
  const deleteUserSubmitBtn = document.getElementById('deleteUserSubmitBtn');
  const userManagementListBody = document.getElementById('userManagementListBody');
  const downloadAuditBtn = document.getElementById('downloadAuditBtn');

  const resetChangePasswordFeedback = () => {
    if (changePasswordError) {
      changePasswordError.style.display = 'none';
      changePasswordError.textContent = '';
    }
    if (changePasswordSuccess) {
      changePasswordSuccess.style.display = 'none';
      changePasswordSuccess.textContent = '';
    }
  };

  const resetCreateUserFeedback = () => {
    if (createUserError) {
      createUserError.style.display = 'none';
      createUserError.textContent = '';
    }
    if (createUserSuccess) {
      createUserSuccess.style.display = 'none';
      createUserSuccess.textContent = '';
    }
  };

  const resetDeleteUserFeedback = () => {
    if (deleteUserError) {
      deleteUserError.style.display = 'none';
      deleteUserError.textContent = '';
    }
    if (deleteUserSuccess) {
      deleteUserSuccess.style.display = 'none';
      deleteUserSuccess.textContent = '';
    }
  };

  const renderManagedUsers = (users = []) => {
    if (!userManagementListBody) return;
    if (!users.length) {
      userManagementListBody.innerHTML = '<tr><td colspan="5" class="history-empty">No users found.</td></tr>';
      return;
    }
    userManagementListBody.innerHTML = users.map((entry) => {
      const username = String(entry?.username || '');
      const role = String(entry?.role || 'user').toUpperCase();
      const isActive = Number(entry?.is_active || 0) === 1;
      const statusLabel = isActive ? 'Active' : 'Disabled';
      return `
        <tr>
          <td>${escapeHtml(username)}</td>
          <td>${escapeHtml(role)}</td>
          <td>${statusLabel}</td>
          <td>${formatDate(entry?.last_login_at)}</td>
          <td>${formatDate(entry?.created_at)}</td>
        </tr>
      `;
    }).join('');
  };

  const refreshAdminUserDirectory = async () => {
    if (!isAdminUser()) return [];
    const res = await fetchWithAuth('/api/admin/users');
    if (!res.ok) throw new Error(await readErrorDetail(res));
    const users = await res.json();
    renderManagedUsers(users);

    if (deleteUserSelect) {
      const currentId = Number(state.currentUser?.id || 0);
      const candidates = (users || []).filter((entry) => {
        const entryId = Number(entry?.id || 0);
        const username = String(entry?.username || '').trim().toLowerCase();
        if (!entryId || username === 'admin') return false;
        if (entryId === currentId) return false;
        return true;
      });
      const options = candidates.map((entry) => {
        const label = `${entry.username} (${String(entry.role || 'user').toUpperCase()})`;
        return `<option value="${entry.id}">${escapeHtml(label)}</option>`;
      });
      deleteUserSelect.innerHTML = `<option value="">Select user to delete</option>${options.join('')}`;
    }
    return users;
  };

  const openPasswordModal = ({ forced = false, username = '', currentPassword = '' } = {}) => {
    if (!passwordModal) return;
    resetChangePasswordFeedback();
    const cpUsername = document.getElementById('cpUsername');
    const cpCurrentPassword = document.getElementById('cpCurrentPassword');
    if (cpUsername) {
      cpUsername.value = username || cpUsername.value || '';
      cpUsername.readOnly = forced;
    }
    if (cpCurrentPassword && currentPassword) cpCurrentPassword.value = currentPassword;
    state.requiresPasswordChange = forced;
    if (passwordModalTitle) {
      passwordModalTitle.textContent = forced ? 'Password Setup Required' : 'Change Password';
    }
    if (passwordModalSubtitle) {
      passwordModalSubtitle.textContent = forced
        ? 'First login requires a new password before accessing the dashboard.'
        : 'Update your security console password securely.';
    }
    if (closePasswordModalBtn) closePasswordModalBtn.style.display = forced ? 'none' : '';
    if (cancelPasswordModalBtn) cancelPasswordModalBtn.style.display = forced ? 'none' : '';
    passwordModal.style.display = 'flex';
  };

  const closePasswordModal = (force = false) => {
    if (state.requiresPasswordChange && !force) return;
    if (!passwordModal) return;
    passwordModal.style.display = 'none';
    if (changePasswordForm) changePasswordForm.reset();
    resetChangePasswordFeedback();
    if (changePasswordSubmitBtn) {
      changePasswordSubmitBtn.disabled = false;
      changePasswordSubmitBtn.innerHTML = '<i class="fas fa-save"></i> Update Password';
    }
  };

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();

      const loginBtn = loginForm.querySelector('.login-btn');
      loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> AUTHENTICATING...';
      loginBtn.disabled = true;
      if (loginError) {
        loginError.style.display = 'none';
        loginError.textContent = '';
      }

      if (!username || !password) {
        if (loginError) {
          loginError.textContent = 'Please enter username and password.';
          loginError.style.display = 'block';
        }
        loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> SECURE LOGIN';
        loginBtn.disabled = false;
        return;
      }

      try {
        setAuth(username, password);
        const res = await fetchWithAuth('/api/auth/login', { method: 'POST' });
        if (!res.ok) {
          throw new Error(await readErrorDetail(res));
        }
        const authData = await res.json();
        updateCurrentUser(authData?.user || {});

        if (authData?.user?.must_change_password) {
          if (loginError) {
            loginError.textContent = 'Password reset is required before first access.';
            loginError.style.display = 'block';
          }
          loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> SECURE LOGIN';
          loginBtn.disabled = false;
          openPasswordModal({ forced: true, username, currentPassword: password });
          return;
        }

        const health = await fetchWithAuth('/api/health');
        if (!health.ok) throw new Error('Backend unreachable');

        const loadingShownAt = showLoadingOverlay(loadingOverlay);
        loginScreen.classList.add('fade-out');
        setTimeout(async () => {
          loginScreen.style.display = 'none';
          mainDashboard.style.display = 'grid';
          dockThemeToggle('docked');
          mainDashboard.classList.add('fade-in');
          try {
            await initializeDashboard();
          } finally {
            await hideLoadingOverlay(loadingOverlay, loadingShownAt);
          }
        }, 900);
      } catch (err) {
        await hideLoadingOverlay(loadingOverlay);
        if (loginError) {
          loginError.textContent = err.message || 'Invalid credentials.';
          loginError.style.display = 'block';
        }
        loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> SECURE LOGIN';
        loginBtn.disabled = false;
      }
    });
  }

  const passwordInput = document.getElementById('password');
  const strengthBar = document.querySelector('.strength-bar');
  if (passwordInput && strengthBar) {
    passwordInput.addEventListener('input', function() {
      const password = this.value;
      let strength = 0;
      if (password.length > 6) strength += 25;
      if (password.length > 10) strength += 25;
      if (/[A-Z]/.test(password)) strength += 25;
      if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) strength += 25;
      strengthBar.style.width = strength + '%';
      if (strength < 50) strengthBar.style.background = 'var(--critical)';
      else if (strength < 75) strengthBar.style.background = 'var(--medium)';
      else strengthBar.style.background = 'var(--success)';
    });
  }

  if (forgotPasswordBtn) {
    forgotPasswordBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const usernameInput = document.getElementById('username');
      openPasswordModal({ username: usernameInput?.value.trim() || '' });
    });
  }

  if (closePasswordModalBtn) closePasswordModalBtn.addEventListener('click', closePasswordModal);
  if (cancelPasswordModalBtn) cancelPasswordModalBtn.addEventListener('click', closePasswordModal);
  if (passwordModal) {
    passwordModal.addEventListener('click', (e) => {
      if (e.target === passwordModal) closePasswordModal();
    });
  }

  if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      resetChangePasswordFeedback();

      const username = document.getElementById('cpUsername')?.value.trim() || '';
      const currentPassword = document.getElementById('cpCurrentPassword')?.value || '';
      const newPassword = document.getElementById('cpNewPassword')?.value || '';
      const confirmPassword = document.getElementById('cpConfirmPassword')?.value || '';

      if (!username || !currentPassword || !newPassword || !confirmPassword) {
        if (changePasswordError) {
          changePasswordError.textContent = 'Please fill in all fields.';
          changePasswordError.style.display = 'block';
        }
        return;
      }
      if (newPassword !== confirmPassword) {
        if (changePasswordError) {
          changePasswordError.textContent = 'New password and confirm password do not match.';
          changePasswordError.style.display = 'block';
        }
        return;
      }

      if (changePasswordSubmitBtn) {
        changePasswordSubmitBtn.disabled = true;
        changePasswordSubmitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
      }

      try {
        const form = new FormData();
        form.append('username', username);
        form.append('current_password', currentPassword);
        form.append('new_password', newPassword);
        form.append('confirm_password', confirmPassword);

        const res = await fetch('/api/auth/change-password', { method: 'POST', body: form });
        const raw = await res.text();
        let data = {};
        try { data = JSON.parse(raw); } catch (_) {}
        if (!res.ok) {
          throw new Error(data?.detail || raw || `Failed (${res.status})`);
        }

        if (changePasswordSuccess) {
          changePasswordSuccess.textContent = data?.message || 'Password updated successfully.';
          changePasswordSuccess.style.display = 'block';
        }
        const usernameInput = document.getElementById('username');
        const passwordInputLocal = document.getElementById('password');
        if (usernameInput) usernameInput.value = username;
        if (passwordInputLocal) passwordInputLocal.value = newPassword;
        state.requiresPasswordChange = false;
        if (state.currentUser) {
          updateCurrentUser({ ...state.currentUser, must_change_password: false });
        }
        setTimeout(() => closePasswordModal(true), 800);
        if (state.currentUser && loginScreen?.style.display !== 'none') {
          setTimeout(() => loginForm?.requestSubmit(), 900);
        }
      } catch (err) {
        if (changePasswordError) {
          changePasswordError.textContent = err.message || 'Could not update password.';
          changePasswordError.style.display = 'block';
        }
      } finally {
        if (changePasswordSubmitBtn) {
          changePasswordSubmitBtn.disabled = false;
          changePasswordSubmitBtn.innerHTML = '<i class="fas fa-save"></i> Update Password';
        }
      }
    });
  }

  const openCreateUserModal = async () => {
    if (!createUserModal) return;
    resetCreateUserFeedback();
    resetDeleteUserFeedback();
    createUserForm?.reset();
    deleteUserForm?.reset();
    createUserModal.style.display = 'flex';
    try {
      await refreshAdminUserDirectory();
    } catch (err) {
      notify(err.message || 'Failed to load user directory', 'error');
    }
  };

  const closeCreateUserModal = () => {
    if (!createUserModal) return;
    createUserModal.style.display = 'none';
    createUserForm?.reset();
    deleteUserForm?.reset();
    resetCreateUserFeedback();
    resetDeleteUserFeedback();
  };

  if (closeActionPasswordModalBtn) closeActionPasswordModalBtn.addEventListener('click', () => closeActionPasswordModal(null));
  if (cancelActionPasswordBtn) cancelActionPasswordBtn.addEventListener('click', () => closeActionPasswordModal(null));
  if (confirmActionPasswordBtn) {
    confirmActionPasswordBtn.addEventListener('click', () => {
      const value = (actionPasswordInput?.value || '').trim();
      if (!value) {
        if (actionPasswordError) {
          actionPasswordError.textContent = 'Please enter your password.';
          actionPasswordError.style.display = 'block';
        }
        return;
      }
      closeActionPasswordModal(value);
    });
  }
  if (actionPasswordInput) {
    actionPasswordInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        confirmActionPasswordBtn?.click();
      }
    });
  }
  if (actionPasswordModal) {
    actionPasswordModal.addEventListener('click', (event) => {
      if (event.target === actionPasswordModal) closeActionPasswordModal(null);
    });
  }

  if (createUserBtn) {
    createUserBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      if (!isAdminUser()) {
        notify('Admin privileges required', 'error');
        return;
      }
      await openCreateUserModal();
    });
  }
  if (closeCreateUserModalBtn) closeCreateUserModalBtn.addEventListener('click', closeCreateUserModal);
  if (closeUserManagementBtn) closeUserManagementBtn.addEventListener('click', closeCreateUserModal);
  if (createUserModal) {
    createUserModal.addEventListener('click', (event) => {
      if (event.target === createUserModal) closeCreateUserModal();
    });
  }
  if (createUserForm) {
    createUserForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!isAdminUser()) {
        notify('Admin privileges required', 'error');
        return;
      }
      resetCreateUserFeedback();
      const username = document.getElementById('newUsername')?.value.trim() || '';
      const role = document.getElementById('newUserRole')?.value || 'user';
      const tempPassword = document.getElementById('newUserTempPassword')?.value || '';
      if (!username) {
        if (createUserError) {
          createUserError.textContent = 'Username is required.';
          createUserError.style.display = 'block';
        }
        return;
      }
      if (createUserSubmitBtn) {
        createUserSubmitBtn.disabled = true;
        createUserSubmitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
      }
      try {
        const body = new URLSearchParams();
        body.append('username', username);
        body.append('role', role);
        if (tempPassword) body.append('temp_password', tempPassword);
        const res = await fetchWithAuth('/api/admin/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body
        });
        if (!res.ok) throw new Error(await readErrorDetail(res));
        const data = await res.json();
        if (createUserSuccess) {
          createUserSuccess.textContent = `User ${data.username} created. Temporary password: ${data.temporary_password}`;
          createUserSuccess.style.display = 'block';
        }
        createUserForm.reset();
        await refreshAdminUserDirectory();
      } catch (err) {
        if (createUserError) {
          createUserError.textContent = err.message || 'Failed to create user.';
          createUserError.style.display = 'block';
        }
      } finally {
        if (createUserSubmitBtn) {
          createUserSubmitBtn.disabled = false;
          createUserSubmitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create User';
        }
      }
    });
  }

  if (deleteUserForm) {
    deleteUserForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!isAdminUser()) {
        notify('Admin privileges required', 'error');
        return;
      }
      resetDeleteUserFeedback();
      const targetUserId = Number(deleteUserSelect?.value || 0);
      if (!targetUserId) {
        if (deleteUserError) {
          deleteUserError.textContent = 'Please select a user to delete.';
          deleteUserError.style.display = 'block';
        }
        return;
      }
      const selectedOption = deleteUserSelect?.selectedOptions?.[0];
      const selectedLabel = selectedOption?.textContent?.trim() || `User ID ${targetUserId}`;
      const confirmed = window.confirm(`Delete ${selectedLabel}? This action cannot be undone.`);
      if (!confirmed) return;

      if (deleteUserSubmitBtn) {
        deleteUserSubmitBtn.disabled = true;
        deleteUserSubmitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
      }
      try {
        const res = await fetchWithAuth(`/api/admin/users/${targetUserId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await readErrorDetail(res));
        const data = await res.json();
        if (deleteUserSuccess) {
          deleteUserSuccess.textContent = data?.message || 'User deleted successfully.';
          deleteUserSuccess.style.display = 'block';
        }
        notify(data?.message || 'User deleted successfully.', 'success');
        deleteUserForm.reset();
        await refreshAdminUserDirectory();
      } catch (err) {
        if (deleteUserError) {
          deleteUserError.textContent = err.message || 'Failed to delete user.';
          deleteUserError.style.display = 'block';
        }
      } finally {
        if (deleteUserSubmitBtn) {
          deleteUserSubmitBtn.disabled = false;
          deleteUserSubmitBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Delete User';
        }
      }
    });
  }

  if (downloadAuditBtn) {
    downloadAuditBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      if (!isAdminUser()) {
        notify('Admin privileges required', 'error');
        return;
      }
      await openReportUrlWithAuth('/api/admin/audit/report/html?limit=2000');
    });
  }
});

function handleLogout() {
  if (confirm('Are you sure you want to logout?')) {
    if (state.pollTimer) clearInterval(state.pollTimer);
    if (state.newsTypeTimer) clearTimeout(state.newsTypeTimer);
    if (state.newsRotateTimer) clearTimeout(state.newsRotateTimer);
    if (state.newsRefreshTimer) clearInterval(state.newsRefreshTimer);
    if (state.durationTicker) clearInterval(state.durationTicker);
    state = {
      authToken: null,
      currentUser: null,
      lastLoginPassword: '',
      requiresPasswordChange: false,
      scans: [],
      lastStatuses: {},
      selectedScanId: null,
      pollTimer: null,
      reportSelections: {},
      searchQuery: '',
      newsHeadlines: [],
      newsIndex: 0,
      newsTypeTimer: null,
      newsRotateTimer: null,
      newsRefreshTimer: null,
      durationTicker: null,
      scanDateFilter: '',
      scanStatusFilter: 'all',
      postureSummary: null,
      postureFetchedAt: 0,
      onboardingProfile: null,
      onboardingFetchedAt: 0
    };
    location.reload();
  }
}

// ============================================
// DASHBOARD INITIALIZATION
// ============================================

async function initializeDashboard() {
  initializeNavigation();
  initializeGlobalSearch();
  const newsInitPromise = initializeCyberNewsTicker();
  ensureDurationTicker();
  initializeChatInterface();
  initializeQuickActions();
  initializeExampleQuestions();
  initializeChatControls();
  initializeLogModal();
  initializeExports();
  initializeNewScanForm();
  initializePosturePage();
  initializeOnboardingPage();
  wireShortcuts();
  await Promise.allSettled([
    refreshAuthStatus(),
    updateHealth(),
    refreshScans(),
    newsInitPromise
  ]);
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollUpdates, 8000);
}

async function refreshAuthStatus() {
  try {
    const res = await fetchWithAuth('/api/auth/status');
    if (!res.ok) return;
    const data = await res.json();
    updateCurrentUser(data || {});
  } catch (_) {
    // Keep current user context if status probe fails.
  }
}

function initializeGlobalSearch() {
  const searchInput = document.getElementById('globalSearchInput');
  if (!searchInput) return;
  searchInput.addEventListener('input', () => {
    state.searchQuery = (searchInput.value || '').trim().toLowerCase();
    applySearchFilters();
  });
  searchInput.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const raw = (searchInput.value || '').trim();
    const match = raw.match(/^#?(\d+)$/);
    if (!match) return;
    const scanId = Number(match[1]);
    if (!scanId) return;
    event.preventDefault();
    const exists = (state.scans || []).some(scan => Number(scan.id) === scanId);
    if (!exists) {
      notify(`Scan #${scanId} not found in current history`, 'info');
      return;
    }
    notify(`Opening report for scan #${scanId}`, 'success');
    openReport(scanId);
  });
}

function filterScans(scans, query) {
  if (!query) return scans || [];
  const value = query.toLowerCase();
  return (scans || []).filter(scan => {
    const id = String(scan.id ?? '');
    const searchable = [
      id,
      `#${id}`,
      `scan ${id}`,
      scan.target || '',
      scan.tool || '',
      scan.status || '',
      formatDate(scan.created_at)
    ].join(' ').toLowerCase();
    return searchable.includes(value);
  });
}

function scanDateDubai(scan) {
  const ms = parseTimestampMs(scan?.created_at);
  if (!Number.isFinite(ms)) return '';
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Dubai' }).format(new Date(ms));
}

function filterScanHistoryControls(scans, dateFilter = '', statusFilter = 'all') {
  const targetDate = String(dateFilter || '').trim();
  const targetStatus = String(statusFilter || 'all').trim().toLowerCase();
  return (scans || []).filter((scan) => {
    if (targetStatus && targetStatus !== 'all') {
      const status = String(scan?.status || '').trim().toLowerCase();
      if (status !== targetStatus) return false;
    }
    if (targetDate) {
      if (scanDateDubai(scan) !== targetDate) return false;
    }
    return true;
  });
}

function getHistoryFilteredScans() {
  const searched = filterScans(state.scans || [], state.searchQuery || '');
  return filterScanHistoryControls(searched, state.scanDateFilter, state.scanStatusFilter);
}

function applySearchFilters() {
  const filtered = filterScans(state.scans || [], state.searchQuery || '');
  const historyFiltered = filterScanHistoryControls(filtered, state.scanDateFilter, state.scanStatusFilter);
  renderRecentScans(filtered);
  renderScanHistory(historyFiltered);
  updateReports(filtered);
}

async function initializeCyberNewsTicker() {
  const ticker = document.getElementById('cyberNewsTypewriter');
  if (!ticker) return;
  await refreshCyberNews();
  if (state.newsRefreshTimer) clearInterval(state.newsRefreshTimer);
  state.newsRefreshTimer = setInterval(refreshCyberNews, 300000);
  playCyberNewsTicker();
}

async function refreshCyberNews() {
  const fallback = [
    {
      title: "Ransomware groups are intensifying double-extortion campaigns against critical infrastructure.",
      source: "Threat Intelligence"
    },
    {
      title: "Attackers are exploiting unpatched internet-facing services within hours of vulnerability disclosure.",
      source: "Threat Intelligence"
    },
    {
      title: "Phishing operations are increasingly using AI-generated lures to bypass user awareness controls.",
      source: "Threat Intelligence"
    }
  ];
  try {
    const res = await fetchWithAuth('/api/news/cyber');
    if (!res.ok) throw new Error(`News feed unavailable (${res.status})`);
    const data = await res.json();
    const headlines = (data?.items || [])
      .map(item => ({
        title: String(item?.title || '').trim(),
        source: String(item?.source || 'Unknown').trim()
      }))
      .filter(item => !!item.title);
    state.newsHeadlines = headlines.length ? headlines : fallback;
  } catch (_) {
    state.newsHeadlines = fallback;
  }
}

function playCyberNewsTicker() {
  const ticker = document.getElementById('cyberNewsTypewriter');
  const source = document.getElementById('cyberNewsSource');
  if (!ticker) return;
  if (!state.newsHeadlines.length) {
    ticker.textContent = 'Cyber threat intelligence feed is loading...';
    if (source) source.textContent = 'Source: Threat Intelligence';
    return;
  }
  if (state.newsTypeTimer) clearTimeout(state.newsTypeTimer);
  if (state.newsRotateTimer) clearTimeout(state.newsRotateTimer);
  const current = state.newsHeadlines[state.newsIndex % state.newsHeadlines.length] || {};
  const rawHeadline = String(current.title || 'Threat intelligence update is loading.');
  const maxHeadlineChars = 180;
  const headline = rawHeadline.length > maxHeadlineChars
    ? `${rawHeadline.slice(0, maxHeadlineChars - 1).trimEnd()}…`
    : rawHeadline;
  const sourceName = String(current.source || 'Threat Intelligence');
  state.newsIndex += 1;
  if (source) source.textContent = `Source: ${sourceName}`;
  ticker.innerHTML = '';
  let cursor = 0;
  const type = () => {
    const typed = escapeHtml(headline.slice(0, cursor));
    ticker.innerHTML = `${typed}<span class="ticker-inline-cursor">|</span>`;
    cursor += 1;
    if (cursor <= headline.length) {
      state.newsTypeTimer = setTimeout(type, 24);
      return;
    }
    state.newsRotateTimer = setTimeout(playCyberNewsTicker, 3800);
  };
  type();
}

function wireShortcuts() {
  const newScanBtn = document.getElementById('newScanShortcut');
  if (newScanBtn) newScanBtn.addEventListener('click', () => showPage('newScan'));
  const userProfile = document.getElementById('userProfile');
  const userMenu = document.getElementById('userMenu');
  const logoutBtn = document.getElementById('logoutBtn');
  if (userProfile && userMenu) {
    userProfile.addEventListener('click', (event) => {
      event.stopPropagation();
      userMenu.classList.toggle('open');
    });
    document.addEventListener('click', () => userMenu.classList.remove('open'));
  }
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
}

// ============================================
// NAVIGATION
// ============================================

function initializeNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const contentPages = document.querySelectorAll('.content-page');

  navItems.forEach(item => {
    item.addEventListener('click', function() {
      const targetPage = this.getAttribute('data-page');
      if (targetPage === 'logout') {
        handleLogout();
        return;
      }
      if (ADMIN_ONLY_PAGES.has(targetPage) && !isAdminUser()) {
        notify('Admin privileges required', 'error');
        return;
      }
      navItems.forEach(nav => nav.classList.remove('active'));
      this.classList.add('active');
      contentPages.forEach(page => page.classList.remove('active'));
      const targetElement = document.getElementById(targetPage + 'Page');
      if (targetElement) targetElement.classList.add('active');
      onPageShown(targetPage);
    });
  });
}

function showPage(page) {
  if (ADMIN_ONLY_PAGES.has(page) && !isAdminUser()) {
    notify('Admin privileges required', 'error');
    return;
  }
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(nav => {
    if (nav.getAttribute('data-page') === page) nav.classList.add('active');
    else nav.classList.remove('active');
  });
  document.querySelectorAll('.content-page').forEach(pageEl => pageEl.classList.remove('active'));
  const targetElement = document.getElementById(page + 'Page');
  if (targetElement) targetElement.classList.add('active');
  onPageShown(page);
}

function onPageShown(page) {
  if (page === 'posture') {
    maybeRefreshPostureSummary(true);
  } else if (page === 'onboarding' && isAdminUser()) {
    maybeRefreshOnboardingProfile(true);
  }
}

// ============================================
// HEALTH & SCANS
// ============================================

async function updateHealth() {
  try {
    const res = await fetchWithAuth('/api/health');
    const data = await res.json();
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    if (data.status === 'online') {
      statusDot?.classList.add('online');
      if (statusText) statusText.textContent = 'All Systems Operational';
    } else {
      if (statusText) statusText.textContent = 'System Degraded';
    }
    updateSystemHealth(data?.system);
    updateToolsStatus(data);
  } catch (e) {
    const statusText = document.querySelector('.status-text');
    if (statusText) statusText.textContent = 'Backend Unreachable';
  }
}

function updateSystemHealth(system) {
  const cpuValue = document.getElementById('cpuUsageValue');
  const memValue = document.getElementById('memoryUsageValue');
  const cpuBar = document.getElementById('cpuUsageBar');
  const memBar = document.getElementById('memoryUsageBar');
  if (!cpuValue || !memValue || !cpuBar || !memBar) return;
  const cpu = Number(system?.cpu_percent ?? 0);
  const memory = Number(system?.memory_percent ?? 0);
  const cpuPct = Math.max(0, Math.min(100, Number.isFinite(cpu) ? cpu : 0));
  const memPct = Math.max(0, Math.min(100, Number.isFinite(memory) ? memory : 0));
  cpuValue.textContent = `${Math.round(cpuPct)}%`;
  memValue.textContent = `${Math.round(memPct)}%`;
  cpuBar.style.width = `${cpuPct}%`;
  memBar.style.width = `${memPct}%`;
}

async function refreshScans() {
  try {
    const res = await fetchWithAuth('/api/scans');
    if (!res.ok) throw new Error('Failed to load scans');
    state.scans = await res.json();
    applySearchFilters();
    updateStats(state.scans);
    if (isPosturePageActive()) {
      // Keep posture view reasonably fresh without hammering the backend every poll tick.
      maybeRefreshPostureSummary(false);
    }
  } catch (e) {
    console.error(e);
  }
}

// ============================================
// POSTURE & COMPLIANCE (DASHBOARD)
// ============================================

function isPosturePageActive() {
  const page = document.getElementById('posturePage');
  return !!page && page.classList.contains('active');
}

async function maybeRefreshPostureSummary(force = false) {
  const ageMs = Date.now() - Number(state.postureFetchedAt || 0);
  if (!force && Number.isFinite(ageMs) && ageMs >= 0 && ageMs < 30000) return;
  await refreshPostureSummary({ silent: true });
}

async function refreshPostureSummary(options = {}) {
  const silent = !!options.silent;
  try {
    const res = await fetchWithAuth('/api/posture/summary');
    if (!res.ok) throw new Error('Failed to load posture summary');
    const data = await res.json();
    state.postureSummary = data;
    state.postureFetchedAt = Date.now();
    renderPostureSummary(data);
    if (!silent) notify('Posture summary refreshed', 'success');
  } catch (e) {
    console.error(e);
    if (!silent) notify(e.message || 'Could not refresh posture summary', 'error');
  }
}

function postureThemeLabel(key) {
  const map = {
    injection: 'Injection',
    security_headers: 'Headers',
    transport_security: 'Transport',
    sensitive_exposure: 'Exposure',
    vulnerability_exposure: 'CVE/Vuln',
    attack_surface: 'Attack Surface',
    coverage_gap: 'Coverage',
    assurance: 'Assurance'
  };
  return map[key] || String(key || '').replaceAll('_', ' ').trim() || 'Theme';
}

function postureFrameworkLabel(key) {
  const map = {
    iso27001: 'ISO 27001',
    soc2: 'SOC 2',
    nist: 'NIST',
    owasp: 'OWASP',
    cis: 'CIS Controls',
    uae_ias: 'UAE IAS'
  };
  return map[key] || String(key || '').toUpperCase();
}

function heatTintStyle(sev, count, maxCount) {
  const rgb = {
    critical: '255,51,102',
    high: '255,133,51',
    medium: '255,170,0',
    low: '51,204,255',
    info: '160,174,192'
  }[sev] || '160,174,192';
  const maxSafe = Math.max(1, Number(maxCount || 1));
  const c = Math.max(0, Number(count || 0));
  const alpha = c <= 0 ? 0.06 : Math.min(0.52, 0.10 + (0.42 * (c / maxSafe)));
  return `background: rgba(${rgb}, ${alpha});`;
}

function buildPostureKpi(icon, variant, value, label, sub) {
  const safeValue = escapeHtml(String(value ?? '0'));
  const safeLabel = escapeHtml(String(label ?? ''));
  const safeSub = escapeHtml(String(sub ?? ''));
  return `
    <div class="stat-card">
      <div class="stat-icon ${variant}">
        <i class="fas ${icon}"></i>
      </div>
      <div class="stat-content">
        <div class="stat-value">${safeValue}</div>
        <div class="stat-label">${safeLabel}</div>
        ${safeSub ? `<div class="stat-change">${safeSub}</div>` : ``}
      </div>
    </div>
  `;
}

function renderPostureSummary(data) {
  const kpis = document.getElementById('postureKpis');
  const heatmap = document.getElementById('postureHeatmap');
  const topTargets = document.getElementById('postureTopTargets');
  const frameworks = document.getElementById('postureFrameworks');
  const cards = document.getElementById('postureTargetCards');
  const targetSelect = document.getElementById('postureTargetSelect');
  if (!kpis || !heatmap || !topTargets || !frameworks || !cards || !targetSelect) return;

  const stats = data?.stats || {};
  const totals = stats?.totals || {};
  const targets = Array.isArray(data?.targets) ? data.targets : [];
  const generatedAt = data?.generated_at || '';

  // KPI cards (security posture display cards)
  const top = (stats?.top_targets && stats.top_targets[0]) ? stats.top_targets[0] : null;
  kpis.innerHTML = [
    buildPostureKpi('fa-bullseye', 'info', stats?.targets ?? targets.length, 'Targets', generatedAt ? `Updated: ${formatDate(generatedAt)}` : ''),
    buildPostureKpi('fa-skull-crossbones', 'critical', totals?.critical ?? 0, 'Critical Findings', 'Immediate attention required'),
    buildPostureKpi('fa-triangle-exclamation', 'high', totals?.high ?? 0, 'High Findings', 'Prioritize remediation'),
    buildPostureKpi('fa-shield-halved', 'info', stats?.coverage_gaps ?? 0, 'Coverage Gaps', 'Retest recommended'),
    buildPostureKpi('fa-gauge-high', 'info', top?.risk?.score ?? 0, 'Top Risk Score', top?.target ? `Target: ${String(top.target).slice(0, 42)}` : '')
  ].join('');

  // Heat Map Summary (targets x severity)
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  let maxCount = 0;
  targets.forEach(t => {
    severities.forEach(sev => {
      const n = Number(t?.counts?.[sev] ?? 0);
      if (Number.isFinite(n)) maxCount = Math.max(maxCount, n);
    });
  });

  const rows = targets.map(t => {
    const ref = String(t?.target_ref || '');
    const name = String(t?.target || ref || 'target');
    const last = t?.last_scan_at ? formatDate(t.last_scan_at) : 'Unknown';
    const score = Number(t?.risk?.score ?? 0);
    const lvl = String(t?.risk?.level || 'INFO').toUpperCase();
    const lvlClass = String(t?.risk?.class || 'info').toLowerCase();
    const targetCell = `
      <div class="hm-target">
        <div class="hm-name">${escapeHtml(name)}</div>
        <div class="hm-sub">${escapeHtml(last)} • <span class="severity-badge ${lvlClass}">${escapeHtml(lvl)}</span></div>
      </div>
    `;
    const cells = severities.map(sev => {
      const count = Number(t?.counts?.[sev] ?? 0);
      return `<td style="${heatTintStyle(sev, count, maxCount)}"><span class="hm-num">${Number.isFinite(count) ? count : 0}</span></td>`;
    }).join('');
    const scoreCell = `<td><span class="hm-score">${Number.isFinite(score) ? score.toFixed(1) : '0.0'}</span></td>`;
    return `<tr><td class="sticky-col">${targetCell}</td>${cells}${scoreCell}</tr>`;
  }).join('');

  heatmap.innerHTML = `
    <div class="posture-heatmap">
      <table class="posture-heatmap-table">
        <thead>
          <tr>
            <th class="sticky-col">Target</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Info</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="7" class="history-empty">No posture data available yet.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;

  // Top Risk Targets (overall summary list)
  const topList = Array.isArray(stats?.top_targets) ? stats.top_targets : [];
  topTargets.innerHTML = topList.length ? topList.map((t, idx) => {
    const name = String(t?.target || t?.target_ref || 'target');
    const score = Number(t?.risk?.score ?? 0);
    const lvl = String(t?.risk?.level || 'INFO').toUpperCase();
    const lvlClass = String(t?.risk?.class || 'info').toLowerCase();
    const c = t?.counts || {};
    const meta = `C:${c.critical ?? 0} H:${c.high ?? 0} M:${c.medium ?? 0} L:${c.low ?? 0}`;
    return `
      <div class="posture-top-item">
        <div class="posture-top-main">
          <div class="posture-top-title">${escapeHtml(name)}</div>
          <div class="posture-top-meta">${escapeHtml(meta)}</div>
        </div>
        <div>
          <div class="severity-badge ${lvlClass}">${escapeHtml(lvl)}</div>
          <div style="margin-top:6px; font-weight:900; text-align:right;">${Number.isFinite(score) ? score.toFixed(1) : '0.0'}</div>
        </div>
      </div>
    `;
  }).join('') : `<div class="empty-state">No target posture data yet. Run scans to populate.</div>`;

  // Framework alignment cards (ISO 27001, SOC 2, NIST, others)
  const fwKeys = ['iso27001', 'soc2', 'nist', 'owasp', 'cis', 'uae_ias'];
  const fwTargets = stats?.framework_targets || {};
  const tagCounts = {};
  fwKeys.forEach(k => tagCounts[k] = {});
  targets.forEach(t => {
    const fw = t?.frameworks || {};
    fwKeys.forEach(k => {
      const tags = Array.isArray(fw?.[k]) ? fw[k] : [];
      tags.forEach(tag => {
        const txt = String(tag || '').trim();
        if (!txt) return;
        tagCounts[k][txt] = (tagCounts[k][txt] || 0) + 1;
      });
    });
  });

  frameworks.innerHTML = `
    <div class="posture-frameworks">
      ${fwKeys.map(k => {
        const impacted = Number(fwTargets?.[k] ?? 0);
        const tagsSorted = Object.entries(tagCounts[k])
          .sort((a, b) => b[1] - a[1])
          .slice(0, 6)
          .map(([tag]) => `<span class="posture-chip info">${escapeHtml(tag)}</span>`)
          .join('');
        const title = postureFrameworkLabel(k);
        const subtitle = impacted ? `${impacted} target(s) with mapped findings` : 'No mapped findings yet';
        return `
          <div class="posture-fw-card">
            <div class="posture-fw-title">
              <span>${escapeHtml(title)}</span>
              <span class="posture-chip ${impacted ? 'medium' : 'info'}">${impacted ? 'Attention' : 'OK'}</span>
            </div>
            <div class="posture-fw-sub">${escapeHtml(subtitle)}</div>
            <div class="posture-fw-chips">${tagsSorted || `<span class="posture-chip info">No tags</span>`}</div>
          </div>
        `;
      }).join('')}
    </div>
  `;

  // Target dropdown
  const current = String(targetSelect.value || '');
  const options = targets.map(t => {
    const ref = String(t?.target_ref || '');
    const name = String(t?.target || ref);
    const score = Number(t?.risk?.score ?? 0);
    return `<option value="${escapeHtml(ref)}">${escapeHtml(name)} • Score ${Number.isFinite(score) ? score.toFixed(1) : '0.0'}</option>`;
  }).join('');
  targetSelect.innerHTML = `<option value="">Select a target…</option>${options}`;
  if (current && targets.some(t => String(t?.target_ref || '') === current)) targetSelect.value = current;

  // Target posture cards (targets with high findings + categorization chips)
  const themeOrder = ['injection', 'vulnerability_exposure', 'sensitive_exposure', 'security_headers', 'transport_security', 'attack_surface', 'coverage_gap', 'assurance'];
  cards.innerHTML = targets.map(t => {
    const ref = String(t?.target_ref || '');
    const name = String(t?.target || ref || 'target');
    const last = t?.last_scan_at ? formatDate(t.last_scan_at) : 'Unknown';
    const risk = t?.risk || {};
    const lvl = String(risk?.level || 'INFO').toUpperCase();
    const lvlClass = String(risk?.class || 'info').toLowerCase();
    const c = t?.counts || {};
    const themeCounts = t?.themes || {};
    const chips = themeOrder
      .filter(k => k !== 'assurance')
      .map(k => [k, Number(themeCounts?.[k] ?? 0)])
      .filter(([, n]) => Number.isFinite(n) && n > 0)
      .slice(0, 8)
      .map(([k, n]) => `<span class="posture-chip ${lvlClass}">${escapeHtml(postureThemeLabel(k))} ${n}</span>`)
      .join('') || `<span class="posture-chip info">No material themes</span>`;

    const meta = `C:${c.critical ?? 0} H:${c.high ?? 0} M:${c.medium ?? 0} L:${c.low ?? 0} I:${c.info ?? 0}`;
    return `
      <div class="posture-target-card">
        <div class="posture-target-head">
          <div style="min-width:0;">
            <div class="posture-target-name">${escapeHtml(name)}</div>
            <div class="posture-target-meta">${escapeHtml(last)} • ${escapeHtml(meta)}</div>
          </div>
          <div style="text-align:right;">
            <div class="severity-badge ${lvlClass}">${escapeHtml(lvl)}</div>
            <div style="margin-top:6px; font-weight:900;">${Number(risk?.score ?? 0).toFixed(1)}</div>
          </div>
        </div>
        <div class="posture-fw-chips">${chips}</div>
        <div class="posture-target-actions">
          <button class="btn btn-primary" onclick="openTargetComplianceReport('${ref}')">
            <i class="fas fa-file-lines"></i> Compliance
          </button>
          <button class="btn btn-secondary" onclick="openTargetConsolidatedReport('${ref}')">
            <i class="fas fa-file-alt"></i> Consolidated
          </button>
        </div>
      </div>
    `;
  }).join('');
}

async function openTargetComplianceReport(targetRef) {
  const ref = encodeURIComponent(String(targetRef || '').trim());
  if (!ref) {
    notify('Select a target first', 'info');
    return;
  }
  await openReportUrlWithAuth(`/api/report/target/${ref}/compliance_html`, { actionLabel: 'download compliance report' });
}

async function openTargetConsolidatedReport(targetRef) {
  const ref = encodeURIComponent(String(targetRef || '').trim());
  if (!ref) {
    notify('Select a target first', 'info');
    return;
  }
  await openReportUrlWithAuth(`/api/report/target/${ref}/html`, { actionLabel: 'download report' });
}

function renderRecentScans(scans) {
  const list = document.getElementById('recentScanList');
  if (!list) return;
  if (!scans || scans.length === 0) {
    const message = state.searchQuery
      ? `No scans match "${escapeHtml(state.searchQuery)}".`
      : 'No scans yet.';
    list.innerHTML = `<div class="scan-item"><div class="scan-info">${message}</div></div>`;
    return;
  }
  const recent = scans.slice(0, 12);
  list.innerHTML = recent.map(s => {
    const status = (s.status || 'pending').toLowerCase();
    const icon = status === 'running' ? 'fa-sync fa-spin' : status === 'completed' ? 'fa-check' : status === 'failed' ? 'fa-triangle-exclamation' : 'fa-clock';
    const progress = s.progress || null;
    const progressPercent = progress?.percent ?? null;
    const durationSeconds = computeScanDurationSeconds(s);
    const isActive = status === 'running' || status === 'pending';
    const progressMeta = progress
      ? `Templates: ${progress.templates} | Requests: ${progress.requests_done}/${progress.requests_total} | Elapsed: ${progress.elapsed || (durationSeconds ? formatDuration(durationSeconds) : 'n/a')}`
      : '';
    return `
      <div class="scan-item">
        <div class="scan-icon ${status}"><i class="fas ${icon}"></i></div>
        <div class="scan-info">
          <div class="scan-name">Scan #${s.id}</div>
          <div class="scan-target">${s.target}</div>
          <div class="scan-meta">
            <span><i class="fas fa-calendar"></i> ${formatDate(s.created_at)}</span>
            <span><i class="fas fa-tools"></i> ${s.tool}</span>
            ${progressMeta ? `<span><i class="fas fa-tachometer-alt"></i> ${progressMeta}</span>` : ''}
          </div>
        </div>
        <div class="scan-status">
          <div class="status-badge ${status}">${status}</div>
          ${isActive && progressPercent !== null ? `
            <div class="progress-circle" data-progress="${progressPercent}">
              <svg viewBox="0 0 36 36">
                <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
                <path class="circle" stroke-dasharray="${progressPercent}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
              </svg>
              <div class="progress-text">${progressPercent}%</div>
            </div>
            <button class="btn-icon danger" onclick="stopScan(${s.id})" title="Stop Scan">
              <i class="fas fa-stop"></i>
            </button>
          ` : isActive ? `
            <button class="btn-icon danger" onclick="stopScan(${s.id})" title="Stop Scan">
              <i class="fas fa-stop"></i>
            </button>
          ` : `
            <button class="btn-icon" onclick="openReport(${s.id})" title="View Report">
              <i class="fas fa-file-alt"></i>
            </button>
            <button class="btn-icon" onclick="openLogs(${s.id})" title="View Logs">
              <i class="fas fa-list"></i>
            </button>
          `}
        </div>
      </div>
    `;
  }).join('');
}

function renderScanHistory(scans) {
  const body = document.getElementById('scanHistoryBody');
  if (!body) return;
  if (!scans || scans.length === 0) {
    const message = state.searchQuery
      ? `No scan results match "${escapeHtml(state.searchQuery)}".`
      : 'No scans available.';
    body.innerHTML = `<tr><td colspan="7" class="history-empty">${message}</td></tr>`;
    return;
  }
  body.innerHTML = (scans || []).map(s => {
    const status = String(s.status || '').toLowerCase();
    const durationSeconds = computeScanDurationSeconds(s);
    return `
      <tr>
        <td>#${s.id}</td>
        <td>${s.target}</td>
        <td>${s.tool}</td>
        <td><span class="status-badge ${status}">${s.status}</span></td>
        <td>${formatDate(s.created_at)}</td>
        <td>
          <span class="scan-duration-live"
            data-status="${escapeHtml(status)}"
            data-created-at="${escapeHtml(s.created_at || '')}"
            data-started-at="${escapeHtml(s.started_at || '')}"
            data-completed-at="${escapeHtml(s.completed_at || '')}"
            data-duration="${durationSeconds}">
            ${formatDuration(durationSeconds)}
          </span>
        </td>
        <td>
          <div class="action-buttons">
            <button class="btn-icon" onclick="openReport(${s.id})" title="View Report"><i class="fas fa-file-alt"></i></button>
            <button class="btn-icon" onclick="openLogs(${s.id})" title="Logs"><i class="fas fa-list"></i></button>
            ${(['running', 'pending'].includes(status)) ? `<button class="btn-icon danger" onclick="stopScan(${s.id})" title="Stop Scan"><i class="fas fa-stop"></i></button>` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');
  updateLiveDurationLabels();
}

function updateStats(scans) {
  const total = scans.length;
  const failed = scans.filter(s => s.status === 'failed').length;
  const completed = scans.filter(s => s.status === 'completed').length;
  const running = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
  const score = total ? Math.round((completed / total) * 100) : 0;

  const statCritical = document.getElementById('statCritical');
  const statTotalScans = document.getElementById('statTotalScans');
  const statSecurityScore = document.getElementById('statSecurityScore');
  const statActiveScans = document.getElementById('statActiveScans');

  if (statCritical) statCritical.textContent = failed;
  if (statTotalScans) statTotalScans.textContent = total;
  if (statSecurityScore) statSecurityScore.textContent = `${score}%`;
  if (statActiveScans) statActiveScans.textContent = running;
}

function updateToolsStatus(health) {
  const tools = health?.tools || {};
  const ai = health?.ai || {};
  const aiReady = ai.status && ai.status.toLowerCase() === 'ready' ? true : !!ai.llama_available;
  const aiStatusText = document.getElementById('aiModelStatusText');
  if (aiStatusText) {
    aiStatusText.textContent = `AI Analysis Engine: ${aiReady ? 'Online' : 'Unavailable'}`;
  }
  const sidebarList = document.getElementById('sidebarToolsStatus');

  const rows = [
    { key: 'sqlmap', name: 'SQLMap', icon: 'fa-database', desc: 'SQL Injection Scanner' },
    { key: 'nuclei', name: 'Nuclei', icon: 'fa-crosshairs', desc: 'Vulnerability Scanner' },
    { key: 'nikto', name: 'Nikto', icon: 'fa-spider', desc: 'Web Server Scanner' },
    { key: 'katana', name: 'Katana', icon: 'fa-project-diagram', desc: 'Crawling & Discovery' },
    { key: 'ai', name: 'AI Analysis Engine', icon: 'fa-brain', desc: 'Natural-language security intelligence' }
  ];

  const render = (container) => {
    if (!container) return;
    container.innerHTML = rows.map(row => {
      const available = row.key === 'ai' ? aiReady : !!tools[row.key];
      const statusClass = available ? 'online' : 'offline';
      return `
        <div class="sidebar-tool-item">
          <div class="sidebar-tool-icon"><i class="fas ${row.icon}"></i></div>
          <div class="sidebar-tool-body">
            <div class="sidebar-tool-name">${row.name}</div>
            <div class="sidebar-tool-desc">${row.desc}</div>
          </div>
          <div class="sidebar-tool-status ${statusClass}">
            <span class="status-dot"></span>
            <span>${available ? 'Ready' : 'Offline'}</span>
          </div>
        </div>
      `;
    }).join('');
  };

  render(sidebarList);
}

function updateReports(scans) {
  const grid = document.getElementById('reportsGrid');
  if (!grid) return;
  const completed = (scans || []).filter(s => ['completed', 'failed'].includes((s.status || '').toLowerCase()));
  if (!completed.length) {
    const message = state.searchQuery
      ? `No reportable scans match "${escapeHtml(state.searchQuery)}".`
      : 'No reportable scans yet. Run a scan to generate reports.';
    grid.innerHTML = `<div class="empty-state">${message}</div>`;
    return;
  }

  completed.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  state.selectedScanId = completed[0]?.id;
  const tools = ["katana", "sqlmap", "nuclei", "nikto"];
  const toolOverview = {
    katana: "Crawls the target to discover endpoints and linked assets.",
    sqlmap: "Tests input parameters for SQL injection behavior.",
    nuclei: "Runs lightweight templates for CVEs and misconfigurations.",
    nikto: "Checks web server hardening, risky files, and header gaps.",
    all: "Builds a consolidated report from completed tools for the selected target."
  };

  const scansByTool = tools.reduce((acc, t) => {
    acc[t] = completed.filter(s => (s.tool || "").toLowerCase() === t);
    return acc;
  }, {});

  const targetsWithAll = [];
  const groupedByTarget = {};
  completed.forEach(s => {
    const key = s.target;
    groupedByTarget[key] = groupedByTarget[key] || new Set();
    groupedByTarget[key].add((s.tool || "").toLowerCase());
  });
  Object.entries(groupedByTarget).forEach(([target, set]) => {
    if (tools.every(t => set.has(t))) targetsWithAll.push(target);
  });

  // Targets with at least one reportable scan (for per-target compliance report).
  const latestByTarget = {};
  for (const s of completed) {
    const key = String(s.target || '');
    if (!key) continue;
    if (!latestByTarget[key]) latestByTarget[key] = s;
  }
  const targetsAny = Object.keys(latestByTarget);
  if (!state.reportSelections.compliance) state.reportSelections.compliance = { value: '' };
  if (!targetsAny.length) state.reportSelections.compliance.value = '';
  else if (!targetsAny.includes(state.reportSelections.compliance.value)) state.reportSelections.compliance.value = targetsAny[0];

  const getSelection = (mode) => {
    if (!state.reportSelections[mode]) {
      state.reportSelections[mode] = { tool: mode === 'both' ? 'all' : 'all', value: '', valueType: 'target' };
    }
    return state.reportSelections[mode];
  };

  const ensureValidSelection = (mode) => {
    const selection = getSelection(mode);
    const validToolChoices = mode === 'both' ? ['all'] : ['all', ...tools];
    if (!validToolChoices.includes(selection.tool)) selection.tool = 'all';

    if (selection.tool === 'all') {
      selection.valueType = 'target';
      if (!targetsWithAll.length) {
        selection.value = '';
      } else if (!targetsWithAll.includes(selection.value)) {
        selection.value = targetsWithAll[0];
      }
      return selection;
    }

    selection.valueType = 'scan';
    const options = scansByTool[selection.tool] || [];
    const ids = options.map(x => String(x.id));
    if (!ids.length) selection.value = '';
    else if (!ids.includes(String(selection.value))) selection.value = options[0].id;
    return selection;
  };

  const renderValueOptions = (mode, selection) => {
    if (selection.tool === 'all') {
      if (!targetsWithAll.length) return '<option value="">Run all 4 tools on one target first</option>';
      return targetsWithAll.map(target => {
        const latest = completed.find(s => s.target === target);
        const selected = selection.value === target ? 'selected' : '';
        return `<option value="${target}" ${selected}>${target} • ${formatDate(latest?.created_at)}</option>`;
      }).join('');
    }
    const items = scansByTool[selection.tool] || [];
    if (!items.length) return '<option value="">No scans for selected tool</option>';
    return items.map(item => {
      const selected = String(selection.value) === String(item.id) ? 'selected' : '';
      return `<option value="${item.id}" ${selected}>Scan #${item.id} • ${item.target} • ${formatDate(item.created_at)}</option>`;
    }).join('');
  };

  const modeFocus = (mode) => {
    if (mode === "executive") return "This executive brief highlights business exposure, risk posture, and immediate priorities.";
    if (mode === "technical") return "This technical report includes evidence, reproduction guidance, and remediation actions.";
    return "This combined report provides both executive risk context and full technical detail.";
  };

  const renderToolNames = (toolKeys) => {
    const labels = {
      katana: "Katana",
      sqlmap: "SQLMap",
      nuclei: "Nuclei",
      nikto: "Nikto"
    };
    if (!toolKeys || !toolKeys.length) return "the completed tools";
    const names = toolKeys.map(t => labels[t] || t);
    if (names.length === 1) return names[0];
    if (names.length === 2) return `${names[0]} and ${names[1]}`;
    return `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
  };

  const reportDescription = (mode, selection) => {
    if (selection.tool === "all") {
      const selectedTarget = selection.value;
      const targetSet = selectedTarget ? groupedByTarget[selectedTarget] : null;
      const used = targetSet ? tools.filter(t => targetSet.has(t)) : [];
      return `Consolidated assessment generated from ${renderToolNames(used)} for the selected target. ${modeFocus(mode)}`;
    }
    const base = toolOverview[selection.tool] || "Tool-specific report.";
    return `${base} ${modeFocus(mode)}`;
  };

  const renderModeCard = (mode, title, subtitle, buttonLabel) => {
    const selection = ensureValidSelection(mode);
    const modeIcon = mode === 'executive' ? 'fa-user-tie' : mode === 'technical' ? 'fa-microscope' : 'fa-layer-group';
    const toolOptions = (mode === 'both' ? ['all'] : ['all', ...tools]).map(t => {
      const selected = selection.tool === t ? 'selected' : '';
      const label = t === 'all' ? 'All Tools' : t.toUpperCase();
      return `<option value="${t}" ${selected}>${label}</option>`;
    }).join('');
    const currentToolDesc = reportDescription(mode, selection);
    const valueLabel = selection.tool === 'all' ? 'Target' : 'Report ID';
    return `
      <div class="report-card mode-card mode-${mode}">
        <div class="report-header">
          <div class="report-icon"><i class="fas ${modeIcon}"></i></div>
          <div class="report-type">
            <h4>${title}</h4>
            <span>${subtitle}</span>
          </div>
        </div>
        <div class="report-info">
          <div class="report-desc">${currentToolDesc}</div>
          <div class="report-select-grid" role="group" aria-label="Report selection">
            <label class="report-select-label">
              Tool
              <select class="report-select" data-mode="${mode}" data-field="tool" onchange="handleReportSelectionChange(this)">
                ${toolOptions}
              </select>
            </label>
            <label class="report-select-label">
              ${valueLabel}
              <select class="report-select" data-mode="${mode}" data-field="value" onchange="handleReportSelectionChange(this)">
                ${renderValueOptions(mode, selection)}
              </select>
            </label>
          </div>
        </div>
        <div class="report-actions">
          <button class="btn btn-primary" onclick="openSelectedReport('${mode}')">${buttonLabel}</button>
        </div>
      </div>
    `;
  };

  const renderComplianceCard = () => {
    const selection = state.reportSelections.compliance || { value: '' };
    const options = targetsAny.length
      ? targetsAny.map(target => {
          const latest = latestByTarget[target];
          const selected = String(selection.value) === String(target) ? 'selected' : '';
          return `<option value="${escapeHtml(target)}" ${selected}>${escapeHtml(target)} • ${formatDate(latest?.created_at)}</option>`;
        }).join('')
      : '<option value="">Run a scan first to unlock compliance reporting</option>';
    const desc = 'Framework-aligned compliance summary mapped to ISO 27001, SOC 2, NIST, CIS, and OWASP. Includes heat map, posture cards, and remediation appendix.';
    return `
      <div class="report-card mode-card mode-compliance">
        <div class="report-header">
          <div class="report-icon"><i class="fas fa-shield-alt"></i></div>
          <div class="report-type">
            <h4>Compliance Summary</h4>
            <span>Standards mapping and audit-ready posture view</span>
          </div>
        </div>
        <div class="report-info">
          <div class="report-desc">${escapeHtml(desc)}</div>
          <div class="report-select-grid" role="group" aria-label="Compliance report selection">
            <label class="report-select-label">
              Target
              <select class="report-select" data-mode="compliance" data-field="value" onchange="handleReportSelectionChange(this)">
                ${options}
              </select>
            </label>
            <div></div>
          </div>
        </div>
        <div class="report-actions">
          <button class="btn btn-primary" onclick="openSelectedComplianceReport()">
            Open Compliance
          </button>
        </div>
      </div>
    `;
  };

  grid.innerHTML = `
    <div class="report-section">
      <div class="section-title">Professional Reports</div>
      <div class="section-grid reports-three-col">
        ${renderModeCard('executive', 'Executive Report', 'Executive risk posture and strategic action plan', 'Open Executive')}
        ${renderModeCard('technical', 'Technical Report', 'Engineer-focused evidence and remediation guidance', 'Open Technical')}
        ${renderModeCard('both', 'Combined Report', 'Unified leadership and technical assurance report', 'Open Combined')}
        ${renderComplianceCard()}
      </div>
    </div>
  `;
}

function handleReportSelectionChange(selectEl) {
  const mode = selectEl.dataset.mode;
  const field = selectEl.dataset.field;
  if (!mode || !field) return;
  if (!state.reportSelections[mode]) state.reportSelections[mode] = { tool: 'all', value: '', valueType: 'target' };
  if (field === 'tool') {
    state.reportSelections[mode].tool = selectEl.value || 'all';
    state.reportSelections[mode].value = '';
    const scrollEl = document.querySelector('.main-content');
    const scrollTop = scrollEl ? scrollEl.scrollTop : null;
    updateReports(state.scans || []);
    if (scrollEl && scrollTop != null) scrollEl.scrollTop = scrollTop;
    return;
  }
  if (field === 'value') {
    state.reportSelections[mode].value = selectEl.value;
  }
}

async function ensureCombinedReport(target) {
  try {
    const latest = (state.scans || [])
      .filter(s => s.target === target && ['completed', 'failed'].includes((s.status || '').toLowerCase()))
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
    if (!latest) {
      notify('No scans found for that target', 'error');
      return false;
    }
    const res = await fetchSensitiveWithStepUp(
      `/api/scan/${latest.id}/report?report_type=both`,
      { method: 'POST' },
      'generate consolidated report'
    );
    if (!res.ok) {
      const detail = await res.text();
      notify(detail || 'Could not generate combined report', 'error');
      return false;
    }
    return true;
  } catch (e) {
    notify(e.message || 'Could not generate combined report', 'error');
    return false;
  }
}

async function openSelectedReport(mode) {
  try {
    const selection = state.reportSelections[mode];
    if (!selection || !selection.value) {
      notify('Select a report first', 'info');
      return;
    }
    if (selection.tool === 'all') {
      const targetRef = encodeURIComponent((selection.value || "").trim());
      let url = `/api/report/target/${targetRef}/html`;
      if (mode === "executive") url = `/api/report/target/${targetRef}/executive_html`;
      if (mode === "technical") url = `/api/report/target/${targetRef}/technical_html`;
      await openReportUrlWithAuth(url, {
        onNotFound: async () => ensureCombinedReport(selection.value)
      });
      return;
    }
    const scanId = Number(selection.value);
    if (!scanId) {
      notify('Invalid scan selection', 'error');
      return;
    }
    if (mode === 'both') {
      notify('Combined report requires All Tools selection.', 'info');
      return;
    }
    let endpoint = `/api/report/${scanId}/executive_html`;
    if (mode === "technical") endpoint = `/api/report/${scanId}/technical_html`;
    await openReportUrlWithAuth(endpoint, {
      onNotFound: async () => {
        await generateReport(scanId, mode);
        return true;
      }
    });
  } catch (e) {
    notify(e.message || 'Could not open report', 'error');
  }
}

async function openSelectedComplianceReport() {
  try {
    const selection = state.reportSelections?.compliance;
    if (!selection || !selection.value) {
      notify('Select a target first', 'info');
      return;
    }
    await openTargetComplianceReport(selection.value);
  } catch (e) {
    notify(e.message || 'Could not open compliance report', 'error');
  }
}

async function readErrorDetail(res) {
  const raw = await res.text();
  let detail = raw;
  try {
    const parsed = JSON.parse(raw);
    if (parsed?.detail) detail = parsed.detail;
  } catch (_) {}
  return detail || `Request failed (${res.status})`;
}

async function openReportUrlWithAuth(url, options = {}) {
  const onNotFound = options.onNotFound;
  const actionLabel = options.actionLabel || (url.startsWith('/api/report/') ? 'download report' : '');
  const fetchReport = () => actionLabel
    ? fetchSensitiveWithStepUp(url, {}, actionLabel)
    : fetchWithAuth(url);
  try {
    let res = await fetchReport();
    if (res.status === 404 && typeof onNotFound === 'function') {
      const built = await onNotFound();
      if (built) res = await fetchReport();
    }
    if (!res.ok) {
      const detail = await readErrorDetail(res);
      throw new Error(detail || `Failed to open report (${res.status})`);
    }
    const blob = await res.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
  } catch (e) {
    notify(e.message || 'Could not open report', 'error');
  }
}

function openReport(scanId) {
  state.selectedScanId = scanId;
  downloadReport('html');
}

// ============================================
// NEW SCAN FORM
// ============================================

function initializeNewScanForm() {
  const form = document.getElementById('newScanForm');
  const resetBtn = document.getElementById('scanFormReset');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      const target = document.getElementById('scanTarget');
      const tool = document.getElementById('scanTool');
      if (target) target.value = '';
      if (tool) tool.value = 'katana';
    });
  }
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const targetEl = document.getElementById('scanTarget');
    const toolEl = document.getElementById('scanTool');
    const target = targetEl?.value.trim();
    const tool = toolEl?.value;
    if (!target) {
      notify('Please enter a target', 'error');
      return;
    }
    if (tool === 'all') {
      await sendChatRequest(`scan ${target} with all tools`);
      notify('Queued all tools for scan', 'info');
      await refreshScans();
      showPage('scanHistory');
      return;
    }
    try {
      const formBody = new URLSearchParams();
      formBody.append('target', target);
      formBody.append('tool', tool);
      const res = await fetchSensitiveWithStepUp('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formBody
      }, 'start scan');
      if (!res.ok) throw new Error('Failed to start scan');
      const data = await res.json();
      notify(`Scan ${data.scan_id} started`, 'success');
      await refreshScans();
      showPage('scanHistory');
    } catch (err) {
      notify(err.message || 'Scan failed to start', 'error');
    }
  });
}

function initializePosturePage() {
  const refreshBtn = document.getElementById('postureRefreshBtn');
  const targetSelect = document.getElementById('postureTargetSelect');
  const openComplianceBtn = document.getElementById('postureOpenComplianceBtn');
  const openConsolidatedBtn = document.getElementById('postureOpenConsolidatedBtn');

  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshPostureSummary({ silent: false });
    });
  }

  if (openComplianceBtn) {
    openComplianceBtn.addEventListener('click', async () => {
      const ref = (targetSelect?.value || '').trim();
      await openTargetComplianceReport(ref);
    });
  }

  if (openConsolidatedBtn) {
    openConsolidatedBtn.addEventListener('click', async () => {
      const ref = (targetSelect?.value || '').trim();
      await openTargetConsolidatedReport(ref);
    });
  }
}

// ============================================
// COMPANY ONBOARDING (ADMIN ONLY)
// ============================================

const ONBOARDING_FIELD_MAP = {
  company_legal_name: 'onboardingCompanyLegalName',
  brand_display_name: 'onboardingBrandDisplayName',
  platform_title: 'onboardingPlatformTitle',
  primary_domain: 'onboardingPrimaryDomain',
  additional_domains: 'onboardingAdditionalDomains',
  primary_contact_name: 'onboardingContactName',
  primary_contact_email: 'onboardingContactEmail',
  primary_contact_phone: 'onboardingContactPhone',
  industry_sector: 'onboardingIndustrySector',
  compliance_scope: 'onboardingComplianceScope',
  logo_dark_url: 'onboardingLogoDarkUrl',
  logo_light_url: 'onboardingLogoLightUrl',
  mark_dark_url: 'onboardingMarkDarkUrl',
  mark_light_url: 'onboardingMarkLightUrl',
  avatar_url: 'onboardingAvatarUrl',
  onboarding_notes: 'onboardingNotes'
};

function collectOnboardingFormProfile() {
  const payload = {};
  Object.entries(ONBOARDING_FIELD_MAP).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (!el) return;
    payload[key] = String(el.value || '').trim();
  });
  return payload;
}

function populateOnboardingForm(profile = {}) {
  Object.entries(ONBOARDING_FIELD_MAP).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.value = String(profile?.[key] || '');
  });
}

function renderOnboardingPreview(profile = {}) {
  const get = (key, fallback = '-') => String(profile?.[key] || '').trim() || fallback;
  const contactBits = [
    get('primary_contact_name', ''),
    get('primary_contact_email', ''),
    get('primary_contact_phone', '')
  ].filter(Boolean);

  const company = document.getElementById('onboardingPreviewCompany');
  const brand = document.getElementById('onboardingPreviewBrand');
  const platform = document.getElementById('onboardingPreviewPlatform');
  const domain = document.getElementById('onboardingPreviewDomain');
  const contact = document.getElementById('onboardingPreviewContact');
  const compliance = document.getElementById('onboardingPreviewCompliance');
  const meta = document.getElementById('onboardingPreviewMeta');

  if (company) company.textContent = get('company_legal_name');
  if (brand) brand.textContent = get('brand_display_name');
  if (platform) platform.textContent = get('platform_title');
  if (domain) domain.textContent = get('primary_domain');
  if (contact) contact.textContent = contactBits.length ? contactBits.join(' • ') : '-';
  if (compliance) compliance.textContent = get('compliance_scope');

  const updatedBy = String(profile?.updated_by || '').trim();
  const updatedAt = String(profile?.updated_at || '').trim();
  if (meta) {
    if (!updatedAt) {
      meta.textContent = 'Last updated: -';
    } else {
      meta.textContent = `Last updated: ${formatDate(updatedAt)}${updatedBy ? ` by ${updatedBy}` : ''}`;
    }
  }
}

async function fetchOnboardingProfile() {
  const res = await fetchWithAuth('/api/admin/company-onboarding');
  if (!res.ok) throw new Error(await readErrorDetail(res));
  const data = await res.json();
  return data?.profile || {};
}

async function maybeRefreshOnboardingProfile(force = false) {
  if (!isAdminUser()) return;
  const ageMs = Date.now() - Number(state.onboardingFetchedAt || 0);
  if (!force && Number.isFinite(ageMs) && ageMs >= 0 && ageMs < 30000) return;
  try {
    const profile = await fetchOnboardingProfile();
    state.onboardingProfile = profile;
    state.onboardingFetchedAt = Date.now();
    populateOnboardingForm(profile);
    renderOnboardingPreview(profile);
  } catch (e) {
    notify(e.message || 'Could not load onboarding profile', 'error');
  }
}

function resetOnboardingFeedback() {
  const err = document.getElementById('onboardingError');
  const ok = document.getElementById('onboardingSuccess');
  if (err) {
    err.style.display = 'none';
    err.textContent = '';
  }
  if (ok) {
    ok.style.display = 'none';
    ok.textContent = '';
  }
}

function initializeOnboardingPage() {
  const form = document.getElementById('companyOnboardingForm');
  const reloadBtn = document.getElementById('onboardingReloadBtn');
  const resetBtn = document.getElementById('onboardingResetBtn');
  const saveBtn = document.getElementById('onboardingSaveBtn');
  if (!form) return;

  Object.values(ONBOARDING_FIELD_MAP).forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', () => renderOnboardingPreview(collectOnboardingFormProfile()));
  });

  if (reloadBtn) {
    reloadBtn.addEventListener('click', async () => {
      await maybeRefreshOnboardingProfile(true);
      notify('Onboarding profile reloaded', 'success');
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      populateOnboardingForm(state.onboardingProfile || {});
      renderOnboardingPreview(state.onboardingProfile || {});
      resetOnboardingFeedback();
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!isAdminUser()) {
      notify('Admin privileges required', 'error');
      return;
    }
    resetOnboardingFeedback();
    const payload = collectOnboardingFormProfile();
    const errBox = document.getElementById('onboardingError');
    const okBox = document.getElementById('onboardingSuccess');

    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    }
    try {
      const res = await fetchWithAuth('/api/admin/company-onboarding', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(await readErrorDetail(res));
      const data = await res.json();
      const profile = data?.profile || payload;
      state.onboardingProfile = profile;
      state.onboardingFetchedAt = Date.now();
      populateOnboardingForm(profile);
      renderOnboardingPreview(profile);
      if (okBox) {
        okBox.textContent = data?.message || 'Company onboarding profile updated.';
        okBox.style.display = 'block';
      }
      notify('Company onboarding profile saved', 'success');
    } catch (e) {
      if (errBox) {
        errBox.textContent = e.message || 'Could not save onboarding profile.';
        errBox.style.display = 'block';
      }
      notify(e.message || 'Could not save onboarding profile.', 'error');
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Save Onboarding Profile';
      }
    }
  });

  renderOnboardingPreview(state.onboardingProfile || {});
}

// ============================================
// CHAT
// ============================================

function initializeChatInterface() {
  const chatInput = document.querySelector('.chat-input');
  const sendBtn = document.querySelector('.send-btn');
  if (sendBtn) sendBtn.addEventListener('click', sendMessage);
  if (chatInput) {
    chatInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    chatInput.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = `${this.scrollHeight}px`;
    });
  }
}

function initializeQuickActions() {
  // No prompt chips
}

function initializeExampleQuestions() {
  document.querySelectorAll('.example-question').forEach(item => {
    item.addEventListener('click', () => {
      sendMessageText(item.textContent.replace(/\"/g, '').trim());
    });
  });
}

function initializeChatControls() {
  const exportBtn = document.getElementById('exportChatBtn');
  const clearBtn = document.getElementById('clearChatBtn');
  if (exportBtn) exportBtn.addEventListener('click', exportChat);
  if (clearBtn) clearBtn.addEventListener('click', clearChat);
}

function initializeExports() {
  const exportDataBtn = document.getElementById('exportDataBtn');
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const scanDateFilter = document.getElementById('scanDateFilter');
  const scanStatusFilter = document.getElementById('scanStatusFilter');
  const viewAllLink = document.getElementById('viewAllScansLink');
  if (exportDataBtn) exportDataBtn.addEventListener('click', async () => exportScans('json', { historyFilters: false }));
  if (exportCsvBtn) exportCsvBtn.addEventListener('click', async () => exportScans('csv', { historyFilters: true }));
  if (scanDateFilter) {
    scanDateFilter.value = state.scanDateFilter || '';
    scanDateFilter.addEventListener('change', () => {
      state.scanDateFilter = scanDateFilter.value || '';
      applySearchFilters();
    });
  }
  if (scanStatusFilter) {
    scanStatusFilter.value = state.scanStatusFilter || 'all';
    scanStatusFilter.addEventListener('change', () => {
      state.scanStatusFilter = (scanStatusFilter.value || 'all').toLowerCase();
      applySearchFilters();
    });
  }
  if (viewAllLink) viewAllLink.addEventListener('click', (e) => { e.preventDefault(); showPage('scanHistory'); });
}

async function exportScans(format = 'csv', options = {}) {
  try {
    if (!state.scans || !state.scans.length) {
      await refreshScans();
    }
    const useHistoryFilters = !!options.historyFilters;
    const scans = useHistoryFilters ? getHistoryFilteredScans() : (state.scans || []);
    if (!scans.length) {
      notify(useHistoryFilters ? 'No filtered scan data to export' : 'No scan data to export', 'info');
      return;
    }
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(scans, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'scans.json';
      a.click();
      URL.revokeObjectURL(url);
      notify('Exported scans as JSON', 'success');
      return;
    }
    // CSV
    const headers = ['id', 'target', 'tool', 'status', 'created_at', 'started_at', 'completed_at', 'duration'];
    const rows = scans.map(s => {
      const duration = computeScanDurationSeconds(s);
      const row = {
        ...s,
        duration
      };
      return headers.map(h => `"${String(row[h] ?? '').replace(/\"/g, '\"\"')}"`).join(',');
    });
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = useHistoryFilters ? 'scans_filtered.csv' : 'scans.csv';
    a.click();
    URL.revokeObjectURL(url);
    notify('Exported scans as CSV', 'success');
  } catch (e) {
    console.error(e);
    notify('Export failed', 'error');
  }
}

async function stopScan(scanId) {
  if (!scanId) return;
  const confirmStop = confirm(`Stop scan #${scanId}?`);
  if (!confirmStop) return;
  try {
    const res = await fetchWithAuth(`/api/scan/${scanId}/stop`, { method: 'POST' });
    if (!res.ok) {
      const detail = await res.text();
      if (res.status === 404) {
        throw new Error('Scan is no longer running.');
      }
      throw new Error(detail || 'Stop failed');
    }
    notify(`Scan #${scanId} stopped`, 'success');
    refreshScans();
  } catch (e) {
    notify(e.message || 'Failed to stop scan', 'error');
  }
}

function sendMessageText(text) {
  const chatInput = document.querySelector('.chat-input');
  if (chatInput) chatInput.value = text;
  sendMessage();
}

function sendMessage() {
  const chatInput = document.querySelector('.chat-input');
  const chatMessages = document.getElementById('chatMessages');
  if (!chatInput || !chatMessages) return;
  const message = chatInput.value.trim();
  if (!message) return;
  chatInput.value = '';
  addChatMessage('user', escapeHtml(message));
  showTypingIndicator();
  sendChatRequest(message);
}

function isSensitiveChatMessage(message) {
  const lower = (message || '').trim().toLowerCase();
  if (!lower) return false;
  if (/\bscan\b/.test(lower) || /\breport\b/.test(lower)) return true;
  if (/^(executive|technical|both|combined)$/.test(lower)) return true;
  if (/^(katana|nikto|nuclei|sqlmap|all tools|all)$/.test(lower)) return true;
  return false;
}

async function sendChatRequest(message) {
  try {
    const form = new URLSearchParams();
    form.append('message', message);
    const requestOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form
    };
    let res = null;
    if (isSensitiveChatMessage(message)) {
      res = await fetchSensitiveWithStepUp('/api/chat', requestOptions, 'run chat scan/report action');
    } else {
      res = await fetchWithAuth('/api/chat', requestOptions);
      if (res.status === 401 && shouldPromptStepUp()) {
        const detail = await readErrorDetail(res);
        if ((detail || '').toLowerCase().includes('password verification')) {
          res = await fetchSensitiveWithStepUp('/api/chat', requestOptions, 'run chat scan/report action');
        } else {
          throw new Error(detail || `Chat request failed (${res.status})`);
        }
      }
    }
    if (!res.ok) {
      removeTypingIndicator();
      const detail = await res.text();
      if (res.status === 401) {
        addChatMessage('ai', 'Session expired. Please log in again.');
        return;
      }
      addChatMessage('ai', `Chat error (${res.status}): ${escapeHtml(detail || res.statusText)}`);
      return;
    }
    removeTypingIndicator();
    const data = await res.json();
    const reply = escapeHtml(data.reply || 'OK').replaceAll('\n', '<br>');
    addChatMessage('ai', reply);
    if (data.actions?.type === 'history' && data.data?.scans) {
      renderRecentScans(data.data.scans);
      renderScanHistory(data.data.scans);
    }
    if (data.actions?.type === 'scan_started') {
      await refreshScans();
      showPage('scanHistory');
    }
    if (data.actions?.type === 'report' && data.data) {
      const link =
        data.data.html ||
        data.data.executive_html ||
        data.data.technical_html ||
        data.data.markdown;
      if (link) {
        await openReportUrlWithAuth(link);
      }
    }
    if (data.actions?.type === 'logs' && data.data?.logs) {
      showLogsModal(data.data.logs);
    }
  } catch (e) {
    removeTypingIndicator();
    addChatMessage('ai', 'Chat error: ' + escapeHtml(e.message));
  }
}

function addChatMessage(role, content) {
  const chatMessages = document.getElementById('chatMessages');
  if (!chatMessages) return;
  const welcomeMsg = chatMessages.querySelector('.chat-welcome');
  if (welcomeMsg) welcomeMsg.remove();
  const messageDiv = document.createElement('div');
  messageDiv.className = `message ${role}-message`;
  const avatarHtml = role === 'user'
    ? '<i class="fas fa-user"></i>'
    : `<img src="${getChatbotAvatarSrc(getCurrentTheme())}" alt="AI assistant" class="chatbot-avatar-logo">`;
  const avatarClass = role === 'user' ? '' : 'ai-avatar';
  const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  messageDiv.innerHTML = `
    <div class="message-avatar ${avatarClass}">${avatarHtml}</div>
    <div class="message-content">
      <div class="message-text">${content}</div>
      <div class="message-time">${time}</div>
    </div>
  `;
  chatMessages.appendChild(messageDiv);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function openLogs(scanId) {
  try {
    const res = await fetchWithAuth(`/api/scan/${scanId}/logs`);
    if (!res.ok) throw new Error(`Log fetch failed (${res.status})`);
    const data = await res.json();
    showLogsModal(data);
  } catch (e) {
    notify(e.message || 'Failed to load logs', 'error');
  }
}

function initializeLogModal() {
  const modal = document.getElementById('logModal');
  const closeBtn = document.getElementById('closeLogModal');
  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => modal.style.display = 'none');
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
  }
}

function showLogsModal(logs) {
  const modal = document.getElementById('logModal');
  const logContent = document.getElementById('logContent');
  if (!modal || !logContent) return;
  const text = typeof logs === 'string' ? logs : JSON.stringify(logs, null, 2);
  logContent.textContent = text || 'No logs available.';
  modal.style.display = 'flex';
}

function showTypingIndicator() {
  const chatMessages = document.getElementById('chatMessages');
  if (!chatMessages) return;
  const indicator = document.createElement('div');
  indicator.className = 'message ai-message typing-indicator';
  indicator.innerHTML = `
    <div class="message-avatar ai-avatar"><img src="${getChatbotAvatarSrc(getCurrentTheme())}" alt="AI assistant" class="chatbot-avatar-logo typing-avatar-logo"></div>
    <div class="message-content">
      <div class="message-text">
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
      </div>
    </div>
  `;
  chatMessages.appendChild(indicator);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function removeTypingIndicator() {
  const indicator = document.querySelector('.typing-indicator');
  if (indicator) indicator.remove();
}

function exportChat() {
  const chatMessages = document.querySelectorAll('#chatMessages .message');
  if (!chatMessages.length) {
    notify('No chat history to export', 'info');
    return;
  }
  const lines = Array.from(chatMessages).map(msg => {
    const role = msg.classList.contains('user-message') ? 'User' : 'Assistant';
    const text = msg.querySelector('.message-text')?.textContent || '';
    const time = msg.querySelector('.message-time')?.textContent || '';
    return `[${time}] ${role}: ${text}`;
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'ai-pentest-chat.txt';
  a.click();
  URL.revokeObjectURL(url);
}

function clearChat() {
  const chatMessages = document.getElementById('chatMessages');
  if (!chatMessages) return;
  chatMessages.innerHTML = '';
  notify('Chat history cleared', 'info');
}

// ============================================
// REPORT DOWNLOADS
// ============================================

async function downloadReport(format) {
  if (!state.selectedScanId) {
    notify('Select a scan first', 'error');
    return;
  }
  const reportType = format === 'executive_html'
    ? 'executive'
    : format === 'technical_html'
      ? 'technical'
      : 'both';
  let endpoint = 'html';
  if (format === 'markdown') endpoint = 'markdown';
  if (format === 'executive_html') endpoint = 'executive_html';
  if (format === 'technical_html') endpoint = 'technical_html';
  if (format === 'raw_txt') endpoint = 'raw_summary';
  let res = await fetchSensitiveWithStepUp(
    `/api/report/${state.selectedScanId}/${endpoint}`,
    {},
    'download report'
  );
  if (res.status === 404 && format !== 'raw_txt') {
    try {
      await generateReport(state.selectedScanId, reportType);
      res = await fetchSensitiveWithStepUp(
        `/api/report/${state.selectedScanId}/${endpoint}`,
        {},
        'download report'
      );
    } catch (err) {
      notify(err.message || 'Report generation failed', 'error');
      return;
    }
  }
  if (!res.ok) {
    notify(await readErrorDetail(res), 'error');
    return;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  if (format === 'markdown') a.download = `report_scan_${state.selectedScanId}.md`;
  else if (format === 'executive_html') a.download = `report_scan_${state.selectedScanId}_executive.html`;
  else if (format === 'technical_html') a.download = `report_scan_${state.selectedScanId}_technical.html`;
  else if (format === 'raw_txt') a.download = `report_scan_${state.selectedScanId}_raw.txt`;
  else a.download = `report_scan_${state.selectedScanId}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

async function generateReport(scanId, reportType) {
  const res = await fetchSensitiveWithStepUp(
    `/api/scan/${scanId}/report?report_type=${reportType}`,
    { method: 'POST' },
    'generate report'
  );
  if (!res.ok) {
    throw new Error(await readErrorDetail(res));
  }
  return res.json();
}

// ============================================
// POLLING
// ============================================

async function pollUpdates() {
  await updateHealth();
  const before = state.scans.reduce((acc, s) => { acc[s.id] = s.status; return acc; }, {});
  await refreshScans();
  state.scans.forEach(s => {
    if (before[s.id] && before[s.id] !== s.status) {
      addChatMessage('ai', `Scan #${s.id} status changed: ${s.status}.`);
    }
  });
}

console.log('Cybersecurity Platform - White-label Product Edition');
