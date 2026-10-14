/**
 * Central API Client & Notification System
 * Protocol Mimicry Engine Laboratory
 * Integrated with configurable API Base URL and Authentication
 */

import { getApiBaseUrl, getApiKey } from "./config.js";

/**
 * Build a full URL from a relative API path.
 */
function resolveUrl(path) {
  if (!path) return "";
  if (path.startsWith("http://") || path.startsWith("https://")) {
    return path;
  }
  const base = getApiBaseUrl();
  if (!base) return path;
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${base}${cleanPath}`;
}

/**
 * Build request headers with optional API key.
 */
function getHeaders(customHeaders = {}) {
  const headers = { ...customHeaders };
  const key = getApiKey();
  if (key) {
    headers["X-API-Key"] = key;
  }
  return headers;
}

/**
 * Handle API responses and extract meaningful error messages.
 */
async function handleResponse(res, url) {
  if (!res.ok) {
    let errMessage = `HTTP ${res.status} (${res.statusText})`;
    try {
      const errJson = await res.json();
      if (errJson && errJson.error) {
        errMessage = errJson.error;
      }
    } catch (_) {
      try {
        const text = await res.text();
        if (text) errMessage = text.substring(0, 160);
      } catch (__) {}
    }
    const error = new Error(errMessage);
    error.status = res.status;
    error.url = url;
    throw error;
  }
  return await res.json();
}

/**
 * Handle network / fetch failures with clear actionable diagnosis.
 */
function handleNetworkError(e, url) {
  const base = getApiBaseUrl();
  console.error(`Fetch failed for ${url}:`, e);
  if (e.message && (e.message.includes("Failed to fetch") || e.message.includes("NetworkError"))) {
    const hint = base 
      ? `Cannot reach backend at ${base}. Check that the backend service is running and CORS is configured.`
      : "Cannot reach backend API. If deployed on Vercel, configure your Backend API URL in the topbar settings.";
    const err = new Error(`Connection Error: ${hint}`);
    err.isNetworkError = true;
    throw err;
  }
  throw e;
}

export const API = {
  /**
   * Helper to format a full URL for direct links (e.g. export download hrefs).
   */
  url(path) {
    return resolveUrl(path);
  },

  async get(path) {
    const fullUrl = resolveUrl(path);
    try {
      const res = await fetch(fullUrl, {
        method: "GET",
        headers: getHeaders()
      });
      return await handleResponse(res, fullUrl);
    } catch (e) {
      handleNetworkError(e, fullUrl);
    }
  },

  async post(path, data) {
    const fullUrl = resolveUrl(path);
    try {
      const res = await fetch(fullUrl, {
        method: "POST",
        headers: getHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(data || {})
      });
      return await handleResponse(res, fullUrl);
    } catch (e) {
      handleNetworkError(e, fullUrl);
    }
  },

  async put(path, data) {
    const fullUrl = resolveUrl(path);
    try {
      const res = await fetch(fullUrl, {
        method: "PUT",
        headers: getHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(data || {})
      });
      return await handleResponse(res, fullUrl);
    } catch (e) {
      handleNetworkError(e, fullUrl);
    }
  },

  async delete(path) {
    const fullUrl = resolveUrl(path);
    try {
      const res = await fetch(fullUrl, {
        method: "DELETE",
        headers: getHeaders()
      });
      return await handleResponse(res, fullUrl);
    } catch (e) {
      handleNetworkError(e, fullUrl);
    }
  }
};

/**
 * Toast Notification System
 */
export function showToast(message, type = "info") {
  let container = document.getElementById("toastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "toastContainer";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  const icon = type === "success" ? "✓" : type === "error" ? "⚠" : "ℹ";
  toast.innerHTML = `<span style="font-weight:700;">${icon}</span> <span>${message}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(40px)";
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

/**
 * Number Counter Animation
 */
export function animateCounter(elementId, targetValue, duration = 800, suffix = "") {
  const el = document.getElementById(elementId);
  if (!el) return;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const current = Math.floor(progress * targetValue);
    el.innerText = `${current}${suffix}`;
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.innerText = `${targetValue}${suffix}`;
    }
  }
  requestAnimationFrame(update);
}
