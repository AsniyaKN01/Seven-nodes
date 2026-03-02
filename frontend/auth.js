const API_BASE = window.API_BASE || "";

function getAuthToken() {
  return localStorage.getItem("auth_token");
}

function setAuthToken(token) {
  if (token) {
    localStorage.setItem("auth_token", token);
  } else {
    localStorage.removeItem("auth_token");
  }
}

function getUser() {
  try {
    return JSON.parse(localStorage.getItem("user") || "null");
  } catch {
    return null;
  }
}

function setUser(user) {
  if (user) {
    localStorage.setItem("user", JSON.stringify(user));
  } else {
    localStorage.removeItem("user");
  }
}

function updateUI() {
  const token = getAuthToken();
  const user = getUser();
  const authStatus = document.getElementById("auth-status");
  const loginSection = document.getElementById("login-section");
  const signupSection = document.getElementById("signup-section");
  const dashboard = document.getElementById("dashboard");

  if (token && user) {
    authStatus.textContent = `Logged in as ${user.email}`;
    loginSection.style.display = "none";
    signupSection.style.display = "none";
    dashboard.style.display = "block";
    document.getElementById("user-info").textContent =
      `${user.first_name} ${user.last_name} (${user.email}) - ${user.organisation_type}`;
  } else {
    authStatus.textContent = "";
    loginSection.style.display = "block";
    signupSection.style.display = "block";
    dashboard.style.display = "none";
  }
}

async function apiPost(path, body, useAuth = false) {
  const opts = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
  if (useAuth) {
    const token = getAuthToken();
    if (token) opts.headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = Array.isArray(data.detail) ? data.detail.map(d => d.msg || d).join(", ") : (data.detail || data.message || res.statusText || "Request failed");
    throw new Error(msg);
  }
  return data;
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    const data = await apiPost("/api/login", {
      email: form.email.value,
      password: form.password.value,
      remember_me: form.remember_me.checked,
    });
    setAuthToken(data.auth_token);
    setUser(data.user);
    updateUI();
    form.reset();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

document.getElementById("signup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById("signup-error");
  errEl.textContent = "";
  try {
    const data = await apiPost("/api/register", {
      first_name: form.first_name.value,
      last_name: form.last_name.value,
      email: form.email.value,
      password: form.password.value,
      organisation_type: form.organisation_type.value,
      remember_me: form.remember_me.checked,
    });
    setAuthToken(data.auth_token);
    setUser(data.user);
    updateUI();
    form.reset();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  try {
    await apiPost("/api/logout", {}, true);
  } catch (_) {}
  setAuthToken(null);
  setUser(null);
  updateUI();
});

updateUI();
