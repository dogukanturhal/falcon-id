/**
 * k6 load test — Falcon ID user CRUD operations.
 *
 * Simulates 20 concurrent VUs exercising the full user management lifecycle:
 * list → create → get → update → delete.
 *
 * Each VU creates its own unique test user, modifies it, then cleans it up so
 * the database does not accumulate leftover test data across runs.
 *
 * Run:
 *   k6 run falcon-id/k6/scenarios/user-crud.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

import { BASE_URL, ADMIN_CREDS, authHeaders } from '../config.js';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const listDuration   = new Trend('falcon_user_list_duration',   true);
const createDuration = new Trend('falcon_user_create_duration', true);
const getDuration    = new Trend('falcon_user_get_duration',    true);
const updateDuration = new Trend('falcon_user_update_duration', true);
const deleteDuration = new Trend('falcon_user_delete_duration', true);
const crudErrors     = new Rate('falcon_user_crud_errors');

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    user_crud: {
      executor: 'constant-vus',
      vus:      20,
      duration: '3m',
      gracefulStop: '30s',
    },
  },

  thresholds: {
    falcon_user_list_duration:   ['p(95)<1000'],
    falcon_user_create_duration: ['p(95)<1500'],
    falcon_user_get_duration:    ['p(95)<500'],
    falcon_user_update_duration: ['p(95)<1000'],
    falcon_user_delete_duration: ['p(95)<1000'],
    falcon_user_crud_errors:     ['rate<0.05'],
    http_req_failed:             ['rate<0.05'],
  },
};

// ---------------------------------------------------------------------------
// VU-local state
// ---------------------------------------------------------------------------
let token = null;

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

  try {
    token = JSON.parse(res.body).access_token || null;
  } catch (_) {
    return false;
  }

  return token !== null;
}

// ---------------------------------------------------------------------------
// Default function: list → create → get → update → delete
// ---------------------------------------------------------------------------
export default function userCRUD() {
  if (!ensureAuth()) {
    crudErrors.add(true);
    sleep(1);
    return;
  }

  const hdrs = authHeaders(token);

  // ---- Step 1: List users (pagination check) ----
  const listStart = Date.now();
  const listRes = http.get(`${BASE_URL}/api/v1/users?page=1&limit=20`, {
    headers: hdrs,
    tags: { name: 'user_list' },
  });
  listDuration.add(Date.now() - listStart);

  const listOk = check(listRes, {
    'list users: status 200': (r) => r.status === 200,
  });
  crudErrors.add(!listOk);

  sleep(0.3);

  // ---- Step 2: Create a test user ----
  const uniqueSuffix = uuidv4().substring(0, 8);
  const testEmail    = `k6-test-${uniqueSuffix}@load-test.invalid`;
  const testUsername = `k6user_${uniqueSuffix}`;

  const createPayload = JSON.stringify({
    username:   testUsername,
    email:      testEmail,
    password:   `K6TestPwd!${uniqueSuffix}`,
    first_name: 'K6',
    last_name:  'LoadTest',
    is_active:  true,
  });

  const createStart = Date.now();
  const createRes = http.post(`${BASE_URL}/api/v1/users`, createPayload, {
    headers: hdrs,
    tags: { name: 'user_create' },
  });
  createDuration.add(Date.now() - createStart);

  const createOk = check(createRes, {
    'create user: status 201 or 200': (r) => r.status === 201 || r.status === 200,
    'create user: has id':            (r) => {
      try { return !!JSON.parse(r.body).id; } catch (_) { return false; }
    },
  });
  crudErrors.add(!createOk);

  if (!createOk) {
    sleep(1);
    return;
  }

  let createdUserID;
  try {
    createdUserID = JSON.parse(createRes.body).id;
  } catch (_) {
    crudErrors.add(true);
    sleep(1);
    return;
  }

  sleep(0.3);

  // ---- Step 3: Get user by ID ----
  const getStart = Date.now();
  const getRes = http.get(`${BASE_URL}/api/v1/users/${createdUserID}`, {
    headers: hdrs,
    tags: { name: 'user_get' },
  });
  getDuration.add(Date.now() - getStart);

  check(getRes, {
    'get user: status 200': (r) => r.status === 200,
    'get user: correct id': (r) => {
      try { return JSON.parse(r.body).id === createdUserID; } catch (_) { return false; }
    },
  });

  sleep(0.3);

  // ---- Step 4: Update user ----
  const updatePayload = JSON.stringify({
    first_name: 'K6Updated',
    last_name:  'LoadTest',
  });

  const updateStart = Date.now();
  const updateRes = http.put(`${BASE_URL}/api/v1/users/${createdUserID}`, updatePayload, {
    headers: hdrs,
    tags: { name: 'user_update' },
  });
  updateDuration.add(Date.now() - updateStart);

  check(updateRes, {
    'update user: status 200': (r) => r.status === 200,
  });

  sleep(0.3);

  // ---- Step 5: Delete user (cleanup) ----
  const deleteStart = Date.now();
  const deleteRes = http.del(`${BASE_URL}/api/v1/users/${createdUserID}`, null, {
    headers: hdrs,
    tags: { name: 'user_delete' },
  });
  deleteDuration.add(Date.now() - deleteStart);

  check(deleteRes, {
    'delete user: status 200 or 204': (r) => r.status === 200 || r.status === 204,
  });

  sleep(1);
}
