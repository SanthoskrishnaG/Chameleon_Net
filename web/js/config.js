/**
 * Protocol Mimicry Engine - Frontend API Configuration
 * Manages the backend API base URL and access credentials for Vercel and local environments.
 */

const STORAGE_KEY_BASE_URL = "chameleon_api_base_url";
const STORAGE_KEY_API_KEY = "chameleon_api_key";

/**
 * Determine the active API Base URL.
 * Priority:
 * 1. window.CHAMELEON_API_BASE_URL (runtime window injection)
 * 2. localStorage.chameleon_api_base_url (user configured in browser UI)
 * 3. Default fallback based on hostname:
 *    - On localhost/127.0.0.1: relative if on port 5000, else http://127.0.0.1:5000
 *    - In production/Vercel: empty string (assumes relative or requires setting)
 */
export function getApiBaseUrl() {
  if (typeof window !== "undefined" && window.CHAMELEON_API_BASE_URL) {
    return cleanUrl(window.CHAMELEON_API_BASE_URL);
  }

  try {
    const stored = localStorage.getItem(STORAGE_KEY_BASE_URL);
    if (stored && stored.trim()) {
      return cleanUrl(stored.trim());
    }
  } catch (e) {
    // localStorage not accessible
  }

  // Detect local environment
  if (typeof window !== "undefined" && window.location) {
    const host = window.location.hostname;
    const port = window.location.port;

    if (host === "localhost" || host === "127.0.0.1") {
      // If already served directly by Flask backend on 5000, relative paths work
      if (port === "5000" || port === "") {
        return "";
      }
      // If served via local dev static server (e.g. port 3000, 5500, 8080)
      return `http://${host}:5000`;
    }
  }

  // Deployed production environment (e.g. Vercel)
  // If no backend URL configured yet, return empty (relative)
  return "";
}

/**
 * Clean trailing slashes from API base URL.
 */
function cleanUrl(url) {
  if (!url) return "";
  return url.replace(/\/+$/, "");
}

/**
 * Update the API Base URL in localStorage.
 */
export function setApiBaseUrl(url) {
  try {
    if (!url || !url.trim()) {
      localStorage.removeItem(STORAGE_KEY_BASE_URL);
    } else {
      localStorage.setItem(STORAGE_KEY_BASE_URL, cleanUrl(url.trim()));
    }
  } catch (e) {
    console.error("Failed to save API Base URL to localStorage:", e);
  }
}

/**
 * Retrieve the active API key.
 */
export function getApiKey() {
  if (typeof window !== "undefined" && window.CHAMELEON_API_KEY) {
    return window.CHAMELEON_API_KEY;
  }
  try {
    return localStorage.getItem(STORAGE_KEY_API_KEY) || "";
  } catch (e) {
    return "";
  }
}

/**
 * Update the API key in localStorage.
 */
export function setApiKey(key) {
  try {
    if (!key || !key.trim()) {
      localStorage.removeItem(STORAGE_KEY_API_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY_API_KEY, key.trim());
    }
  } catch (e) {
    console.error("Failed to save API key to localStorage:", e);
  }
}

/**
 * Reset all configuration settings.
 */
export function resetConfig() {
  try {
    localStorage.removeItem(STORAGE_KEY_BASE_URL);
    localStorage.removeItem(STORAGE_KEY_API_KEY);
  } catch (e) {
    console.error("Failed to reset config:", e);
  }
}
