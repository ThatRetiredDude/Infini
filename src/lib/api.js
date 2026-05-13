// Thin wrapper around fetch — same-origin, cookie-based auth + CSRF for unsafe methods.

const CSRF_COOKIE_NAME = import.meta.env.VITE_CSRF_COOKIE_NAME || 'mi_csrf';

function readCsrfCookie() {
  if (typeof document === 'undefined') return '';
  const parts = document.cookie.split(';');
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const kRaw = p.slice(0, idx).trim();
    const vRaw = p.slice(idx + 1);
    if (kRaw === CSRF_COOKIE_NAME) {
      try {
        return decodeURIComponent(vRaw);
      } catch {
        return vRaw;
      }
    }
  }
  return '';
}

export async function fetchWithCsrf(url, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { ...(opts.headers && typeof opts.headers === 'object' ? opts.headers : {}) };
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const t = readCsrfCookie();
    if (t) headers['X-CSRF-Token'] = t;
  }
  return fetch(url, { credentials: 'include', ...opts, headers });
}

async function request(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { ...(opts.headers || {}) };
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const t = readCsrfCookie();
    if (t) headers['X-CSRF-Token'] = t;
    if (!headers['Content-Type'] && opts.body && typeof opts.body === 'string') {
      headers['Content-Type'] = 'application/json';
    }
  }
  const res = await fetch(path, {
    credentials: 'include',
    headers,
    ...opts,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(data?.error || `request_failed_${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body: JSON.stringify(body || {}) }),
  put: (path, body) => request(path, { method: 'PUT', body: JSON.stringify(body || {}) }),
  patch: (path, body) => request(path, { method: 'PATCH', body: JSON.stringify(body || {}) }),
  delete: (path) => request(path, { method: 'DELETE' }),
};

export async function fetchMe() {
  return api.get('/api/auth/me');
}

export async function login(username, password) {
  return api.post('/api/auth/login', { username, password });
}

export async function verifyMfaTotp(ticket, code) {
  return api.post('/api/auth/mfa/totp-verify', { ticket, code });
}

export async function logout() {
  return api.post('/api/auth/logout');
}

export async function changePassword(current_password, new_password) {
  return api.post('/api/auth/change-password', { current_password, new_password });
}

export async function forgotPassword(username) {
  return api.post('/api/auth/forgot-password', { username });
}

export async function register(username, password, email = '') {
  return api.post('/api/auth/register', {
    username: username.trim(),
    password,
    email: email ? email.trim() : null,
  });
}
