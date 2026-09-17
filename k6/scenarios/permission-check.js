/**
 * k6 load test — Falcon ID authorization endpoint (/authorize).
 *
 * Hammers the permission-check hot-path at a constant 200 requests/second
 * using the constant-arrival-rate executor. This mirrors real-world service
 * mesh traffic where every microservice call triggers an authorization check.
 *
 * Run:
 *   k6 run falcon-id/k6/scenarios/permission-check.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

import { BASE_URL, ADMIN_CREDS, authHeaders } from '../config.js';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const authzDuration   = new Trend('falcon_authz_duration', true);
const authzErrors     = new Rate('falcon_authz_errors');
const authzAllowed    = new Counter('falcon_authz_allowed');
const authzDenied     = new Counter('falcon_authz_denied');

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    permission_check: {
      executor: 'constant-arrival-rate',
      rate: 200,            // 200 iterations per second (≈ 200 RPS)
      timeUnit: '1s',
      duration: '3m',       // sustain for 3 minutes
      preAllocatedVUs: 50,  // VU pool; k6 warns if it needs more
      maxVUs: 100,
    },
  },

  thresholds: {
    falcon_authz_duration: [
      'p(95)<100',  // 95th percentile under 100 ms
      'p(99)<200',  // 99th percentile under 200 ms
    ],
    falcon_authz_errors: ['rate<0.01'],
    http_req_failed:     ['rate<0.01'],
  },
};

// ---------------------------------------------------------------------------
// Module-level setup: authenticate once per VU and reuse the token.
// k6 does NOT share state between VUs — each VU runs setup independently.
// ---------------------------------------------------------------------------

/** @type {string|null} VU-local access token. */
let token = null;

/** @type {string|null} VU-local tenant ID (read from /auth/me response). */
let tenantID = null;

/** @type {string|null} VU-local user ID. */
let userID = null;

/**
 * ensureAuth obtains (or reuses) the VU-local token.
 * Called at the start of each iteration.
 */
function ensureAuth() {
  if (token !== null) {
    return true;
  }

  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify(ADMIN_CREDS),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'setup_login' } },
  );

  if (res.status !== 200) {
    return false;
  }

  let parsed;
  try {
    parsed = JSON.parse(res.body);
  } catch (_) {
    return false;
  }

  token    = parsed.access_token  || null;
  userID   = parsed.user?.id      || parsed.user_id   || null;
  tenantID = parsed.tenant?.id    || parsed.tenant_id || null;

  // Fallback: fetch /me to get IDs when not embedded in login response.
  if (token && (!userID || !tenantID)) {
    const meRes = http.get(`${BASE_URL}/api/v1/auth/me`, {
      headers: authHeaders(token),
      tags: { name: 'setup_me' },
    });
    if (meRes.status === 200) {
      try {
        const me = JSON.parse(meRes.body);
        userID   = userID   || me.id        || me.user_id   || null;
        tenantID = tenantID || me.tenant_id || null;
      } catch (_) {}
    }
  }

  return token !== null;
}

// ---------------------------------------------------------------------------
// Default function: POST /authorize
// ---------------------------------------------------------------------------
export default function permissionCheck() {
  if (!ensureAuth()) {
    authzErrors.add(true);
    sleep(0.1);
    return;
  }

  // Build a representative authorization request.
  // The permission and resource values intentionally use stable, well-known
  // names so the SpiceDB cache can warm up naturally.
  const payload = JSON.stringify({
    permission:    'core:users:read',
    resource_type: 'tenant',
    resource_id:   tenantID || '*',
  });

  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/v1/authorize`, payload, {
    headers: authHeaders(token),
    tags: { name: 'authz_check' },
  });
  authzDuration.add(Date.now() - start);

  const ok = check(res, {
    'authz: status 200 or 403': (r) => r.status === 200 || r.status === 403,
    'authz: has allowed field':  (r) => {
      try { return typeof JSON.parse(r.body).allowed === 'boolean'; } catch (_) { return false; }
    },
  });

  authzErrors.add(!ok);

  if (ok) {
    try {
      const body = JSON.parse(res.body);
      if (body.allowed === true)  { authzAllowed.add(1); }
      if (body.allowed === false) { authzDenied.add(1);  }
    } catch (_) {}
  }

  // No sleep — constant-arrival-rate executor manages pacing.
}
