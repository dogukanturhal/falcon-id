/**
 * Shared k6 configuration for Falcon ID load tests.
 *
 * Environment variables (all optional — defaults shown):
 *   FALCON_ID_URL   Base URL of the Falcon ID service  (default: http://localhost:8005)
 *   TENANT_SLUG     Tenant slug used for authentication (default: exampletenant)
 *   ADMIN_USERNAME  Platform admin username             (default: admin)
 *   ADMIN_PASSWORD  Platform admin password             (required, no default)
 */

import http from 'k6/http';
import { check } from 'k6';

// ---------------------------------------------------------------------------
// Base configuration
// ---------------------------------------------------------------------------

/** @type {string} Base URL — override with FALCON_ID_URL environment variable. */
export const BASE_URL = __ENV.FALCON_ID_URL || 'http://localhost:8005';

/** @type {string} Default tenant slug used in authentication requests. */
export const TENANT_SLUG = __ENV.TENANT_SLUG || 'exampletenant';

/** @type {{ username: string, password: string, tenant_slug: string }} */
export const ADMIN_CREDS = {
  username: __ENV.ADMIN_USERNAME || 'admin',
  password: requireEnv('ADMIN_PASSWORD'),
  tenant_slug: TENANT_SLUG,
};

/** Fail fast when a required secret is not supplied via the environment. */
function requireEnv(name) {
  const v = __ENV[name];
  if (!v) {
    throw new Error(`${name} must be set in the environment`);
  }
  return v;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * login authenticates against Falcon ID and returns the access token.
 *
 * Fails the current iteration (via check) if the login request does not
 * return HTTP 200 or if the response body does not include an access_token.
 *
 * @param {{ username: string, password: string, tenant_slug: string }} [creds]
 *   Credentials to use; defaults to ADMIN_CREDS.
 * @returns {string|null} The access token, or null when login failed.
 */
export function login(creds) {
  const payload = JSON.stringify(creds || ADMIN_CREDS);

  const res = http.post(`${BASE_URL}/api/v1/auth/login`, payload, {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'auth_login' },
  });

  const ok = check(res, {
    'login: status 200': (r) => r.status === 200,
    'login: has access_token': (r) => {
      try {
        return JSON.parse(r.body).access_token !== undefined;
      } catch (_) {
        return false;
      }
    },
  });

  if (!ok) {
    return null;
  }

  try {
    return JSON.parse(res.body).access_token;
  } catch (_) {
    return null;
  }
}

/**
 * authHeaders builds a standard JSON + Bearer-token header map.
 *
 * @param {string} token  Bearer token returned by login().
 * @returns {Object}      Headers object suitable for k6 http requests.
 */
export function authHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  };
}

/**
 * jsonBody serialises a value to JSON string.
 *
 * @param {*} obj
 * @returns {string}
 */
export function jsonBody(obj) {
  return JSON.stringify(obj);
}

// ---------------------------------------------------------------------------
// Common threshold presets — import and spread into your scenario's thresholds
// ---------------------------------------------------------------------------

/** Thresholds for interactive / user-facing endpoints. */
export const INTERACTIVE_THRESHOLDS = {
  http_req_failed: [{ threshold: 'rate<0.02', abortOnFail: false }],
  http_req_duration: [{ threshold: 'p(95)<2000', abortOnFail: false }],
};

/** Thresholds for fast machine-to-machine endpoints (e.g. /authorize). */
export const M2M_THRESHOLDS = {
  http_req_failed: [{ threshold: 'rate<0.01', abortOnFail: false }],
  http_req_duration: [
    { threshold: 'p(95)<100', abortOnFail: false },
    { threshold: 'p(99)<200', abortOnFail: false },
  ],
};

/** Thresholds for infrastructure/health endpoints. */
export const HEALTH_THRESHOLDS = {
  http_req_failed: [{ threshold: 'rate<0.001', abortOnFail: false }],
  http_req_duration: [{ threshold: 'p(99)<50', abortOnFail: false }],
};
