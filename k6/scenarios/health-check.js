/**
 * k6 load test — Falcon ID health endpoint stability.
 *
 * Hammers /health, /live, /ready, and /health/ready at high rate to verify
 * that health probes remain stable under concurrent load.  This test is
 * intentionally separate from functional tests so it can run continuously
 * in CI alongside a real cluster without affecting business-logic endpoints.
 *
 * Thresholds:
 *   - p(99) latency < 50 ms for all health endpoints
 *   - error rate < 0.1%
 *
 * Run:
 *   k6 run falcon-id/k6/scenarios/health-check.js
 */

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate } from 'k6/metrics';

import { BASE_URL } from '../config.js';

// ---------------------------------------------------------------------------
// Custom metrics — one per endpoint for granular dashboarding
// ---------------------------------------------------------------------------
const healthDuration  = new Trend('falcon_health_duration',  true);
const liveDuration    = new Trend('falcon_live_duration',    true);
const readyDuration   = new Trend('falcon_ready_duration',   true);
const hReadyDuration  = new Trend('falcon_hready_duration',  true);
const healthErrors    = new Rate('falcon_health_errors');

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    // Liveness endpoints: constant high rate
    liveness: {
      executor: 'constant-arrival-rate',
      rate:     100,       // 100 RPS
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 10,
      maxVUs: 30,
      exec: 'checkLiveness',
    },

    // Readiness endpoints: moderate rate (load balancer probe cadence)
    readiness: {
      executor: 'constant-arrival-rate',
      rate:     50,        // 50 RPS
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 10,
      maxVUs: 30,
      exec: 'checkReadiness',
    },
  },

  thresholds: {
    // All health endpoints must respond in < 50 ms at p99
    falcon_health_duration:  ['p(99)<50'],
    falcon_live_duration:    ['p(99)<50'],
    falcon_ready_duration:   ['p(99)<50'],
    falcon_hready_duration:  ['p(99)<50'],

    // Global error budget
    falcon_health_errors:    ['rate<0.001'],
    http_req_failed:         ['rate<0.001'],
  },
};

// ---------------------------------------------------------------------------
// Liveness scenario: GET /health and GET /live
// ---------------------------------------------------------------------------
export function checkLiveness() {
  // /health
  const healthStart = Date.now();
  const healthRes = http.get(`${BASE_URL}/health`, {
    tags: { name: 'health' },
  });
  healthDuration.add(Date.now() - healthStart);

  const healthOk = check(healthRes, {
    'health: status 200':       (r) => r.status === 200,
    'health: status is string': (r) => {
      try { return typeof JSON.parse(r.body).status === 'string'; } catch (_) { return false; }
    },
  });
  healthErrors.add(!healthOk);

  // /live (alias)
  const liveStart = Date.now();
  const liveRes = http.get(`${BASE_URL}/live`, {
    tags: { name: 'live' },
  });
  liveDuration.add(Date.now() - liveStart);

  const liveOk = check(liveRes, {
    'live: status 200':   (r) => r.status === 200,
    'live: body is JSON': (r) => {
      try { JSON.parse(r.body); return true; } catch (_) { return false; }
    },
  });
  healthErrors.add(!liveOk);
}

// ---------------------------------------------------------------------------
// Readiness scenario: GET /ready and GET /health/ready
// ---------------------------------------------------------------------------
export function checkReadiness() {
  // /ready (top-level alias)
  const readyStart = Date.now();
  const readyRes = http.get(`${BASE_URL}/ready`, {
    tags: { name: 'ready' },
  });
  readyDuration.add(Date.now() - readyStart);

  const readyOk = check(readyRes, {
    // Accept 200 (ready) or 503 (starting up / dependency down)
    'ready: status 200 or 503': (r) => r.status === 200 || r.status === 503,
    'ready: has status field':  (r) => {
      try { return typeof JSON.parse(r.body).status === 'string'; } catch (_) { return false; }
    },
    'ready: has checks field':  (r) => {
      try { return typeof JSON.parse(r.body).checks === 'object'; } catch (_) { return false; }
    },
    'ready: has version field': (r) => {
      try { return typeof JSON.parse(r.body).version === 'string'; } catch (_) { return false; }
    },
  });
  healthErrors.add(!readyOk);

  // /health/ready (canonical path)
  const hReadyStart = Date.now();
  const hReadyRes = http.get(`${BASE_URL}/health/ready`, {
    tags: { name: 'health_ready' },
  });
  hReadyDuration.add(Date.now() - hReadyStart);

  const hReadyOk = check(hReadyRes, {
    'health/ready: status 200 or 503': (r) => r.status === 200 || r.status === 503,
    'health/ready: has uptime_sec':    (r) => {
      try { return typeof JSON.parse(r.body).uptime_sec === 'number'; } catch (_) { return false; }
    },
  });
  healthErrors.add(!hReadyOk);
}
