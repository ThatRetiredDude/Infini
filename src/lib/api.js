// Thin wrapper around fetch — same-origin, cookie-based auth.

async function request(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
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

export async function logout() {
  return api.post('/api/auth/logout');
}

export async function changePassword(current_password, new_password) {
  return api.post('/api/auth/change-password', { current_password, new_password });
}
