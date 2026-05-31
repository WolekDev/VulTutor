/**
 * VulTutor – shared frontend utilities
 *
 * All pages extend base.html which loads this file.
 * Provides:
 *   requireAuth()        – redirect to login if no token
 *   apiFetch(url, opts)  – fetch with Authorization header + JSON defaults
 *   showFlash(msg, type) – show a Bootstrap alert in #flashArea
 *   escHtml(str)         – HTML-escape a string before inserting into the DOM
 *   buildNav()           – populate the navbar auth links
 */

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

function getToken() {
  return localStorage.getItem("vt_token");
}

/**
 * Redirect to /login if no JWT is stored.
 * Returns the token if present.
 */
function requireAuth() {
  const token = getToken();
  if (!token) {
    window.location.href = "/login";
    throw new Error("Unauthenticated - redirecting");
  }
  return token;
}

// ---------------------------------------------------------------------------
// API fetch wrapper
// ---------------------------------------------------------------------------

/**
 * Wrapper around fetch() that:
 *  - Adds Authorization: Bearer <token> header
 *  - Sets Content-Type: application/json for POST/PUT
 *  - Handles 401 responses by redirecting to /login
 */
async function apiFetch(url, options = {}) {
  const token = getToken();
  const headers = {
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    localStorage.removeItem("vt_token");
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  return res;
}

// ---------------------------------------------------------------------------
// Flash messages
// ---------------------------------------------------------------------------

function showFlash(message, type = "info") {
  const area = document.getElementById("flashArea");
  const msg = document.getElementById("flashMsg");
  const text = document.getElementById("flashText");
  if (!area) return;

  msg.className = `alert alert-${type} alert-dismissible fade show`;
  text.textContent = message;
  area.style.display = "";
}

// ---------------------------------------------------------------------------
// HTML escaping (prevent XSS in JS-rendered content)
// ---------------------------------------------------------------------------

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---------------------------------------------------------------------------
// Navbar
// ---------------------------------------------------------------------------

function buildNav() {
  const nav = document.getElementById("authNav");
  if (!nav) return;

  const token = getToken();
  if (token) {
    nav.innerHTML = `
      <li class="nav-item">
        <a class="nav-link" href="/home"><i class="bi bi-house me-1"></i>Dashboard</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/account"><i class="bi bi-person-circle me-1"></i>Account</a>
      </li>
      <li class="nav-item">
        <button class="btn btn-outline-danger btn-sm ms-1" id="logoutBtn">
          <i class="bi bi-box-arrow-right me-1"></i>Logout
        </button>
      </li>`;

    document.getElementById("logoutBtn").addEventListener("click", async () => {
      try {
        await apiFetch("/api/sessions", { method: "DELETE" });
      } catch {
        // Ignore errors – remove token regardless
      }
      localStorage.removeItem("vt_token");
      window.location.href = "/login";
    });
  } else {
    nav.innerHTML = `
      <li class="nav-item">
        <a class="nav-link" href="/login">Sign In</a>
      </li>
      <li class="nav-item">
        <a class="btn btn-success btn-sm ms-1" href="/register">Register</a>
      </li>`;
  }
}

// Run on every page
document.addEventListener("DOMContentLoaded", buildNav);
