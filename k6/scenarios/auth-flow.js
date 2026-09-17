/**
 * k6 load test — Falcon ID authentication flow.
 *
 * Covers the full auth lifecycle: login → /me → token refresh → logout.
 * Uses ramping VUs (0 → 50 over 6 minutes) to simulate realistic traffic growth.
 *
 * Run:
 *   k6 run falcon-id/k6/scenarios/auth-flow.js
 *
 * Override defaults:
 *   FALCON_ID_URL=http://falcon-id:8005 TENANT_SLUG=my-tenant k6 run auth-flow.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

import { BASE_URL, ADMIN_CREDS, authHeaders } from '../config.js';

// ---------------------------------------------------------------------------
// Custom metrics (named per-endpoint for granular dashboarding)
// ---------------------------------------------------------------------------
const loginDuration   = new Trend('falcon_login_duration',   true);
const refreshDuration = new Trend('falcon_refresh_duration', true);
const meDuration      = new Trend('falcon_me_duration',      true);
const loginErrors     = new Rate('falcon_login_errors');
const refreshErrors   = new Rate('falcon_refresh_errors');
const meErrors        = new Rate('falcon_me_errors');

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    auth_flow: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m',  target: 10 },  // warm-up
        { duration: '2m',  target: 30 },  // ramp to moderate load
        { duration: '2m',  target: 50 },  // peak load
        { duration: '1m',  target: 0  },  // cool-down
      ],
      gracefulRampDown: '30s',
    },
  },

  thresholds: {
    // Per-endpoint latency SLOs
    falcon_login_duration:   ['p(95)<2000'],
    falcon_refresh_duration: ['p(95)<500'],
    falcon_me_duration:      ['p(95)<200'],

    // Global error rate
    http_req_failed: ['rate<0.02'],

    // Specific error counters must also stay low
    falcon_login_errors:   ['rate<0.02'],
    falcon_refresh_errors: ['rate<0.02'],
    falcon_me_errors:      ['rate<0.02'],
  },
};

// ---------------------------------------------------------------------------
// Scenario: login → GET /me → refresh → logout
// ---------------------------------------------------------------------------
export default function authFlow() {
  // ---- Step 1: Login ----
  const loginPayload = JSON.stringify(ADMIN_CREDS);
  const loginStart = Date.now();

  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, loginPayload, {
    headers: { 'Content-Type': 'application/json' },
    tags: { name: 'auth_login' },
  });

  loginDuration.add(Date.now() - loginStart);

  const loginOk = check(loginRes, {
    'login: status 200':        (r) => r.status === 200,
    'login: has access_token':  (r) => {
      try { return !!JSON.parse(r.body).access_token; } catch (_) { return false; }
    },
    'login: has refresh_token': (r) => {
      try { return !!JSON.parse(r.body).refresh_token; } catch (_) { return false; }
    },
  });

  loginErrors.add(!loginOk);

  if (!loginOk) {
    sleep(1);
    return;
  }

  let body;
  try {
    body = JSON.parse(loginRes.body);
  } catch (_) {
    loginErrors.add(true);
    sleep(1);
    return;
  }

  const accessToken  = body.access_token;
  const refreshToken = body.refresh_token;

  sleep(0.5);

  // ---- Step 2: GET /me ----
  const meStart = Date.now();
  const meRes = http.get(`${BASE_URL}/api/v1/auth/me`, {
    headers: authHeaders(accessToken),
    tags: { name: 'auth_me' },
  });
  meDuration.add(Date.now() - meStart);

  const meOk = check(meRes, {
    'me: status 200':   (r) => r.status === 200,
    'me: has user_id':  (r) => {
      try { return !!JSON.parse(r.body).id; } catch (_) { return false; }
    },
  });
  meErrors.add(!meOk);

  sleep(1);

  // ---- Step 3: Token refresh ----
  const refreshStart = Date.now();
  const refreshRes = http.post(
    `${BASE_URL}/api/v1/auth/refresh`,
    JSON.stringify({ refresh_token: refreshToken }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'auth_refresh' },
    },
  );
  refreshDuration.add(Date.now() - refreshStart);

  const refreshOk = check(refreshRes, {
    'refresh: status 200':       (r) => r.status === 200,
    'refresh: has access_token': (r) => {
      try { return !!JSON.parse(r.body).access_token; } catch (_) { return false; }
    },
  });
  refreshErrors.add(!refreshOk);

  let newAccessToken = accessToken;
  if (refreshOk) {
    try {
      newAccessToken = JSON.parse(refreshRes.body).access_token || accessToken;
    } catch (_) {}
  }

  sleep(0.5);

  // ---- Step 4: Logout ----
  const logoutRes = http.post(`${BASE_URL}/api/v1/auth/logout`, null, {
    headers: authHeaders(newAccessToken),
    tags: { name: 'auth_logout' },
  });

  check(logoutRes, {
    'logout: status 200 or 204': (r) => r.status === 200 || r.status === 204,
  });

  sleep(1);
}
