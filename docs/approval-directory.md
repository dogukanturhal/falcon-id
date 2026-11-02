# Approval directory (service-token API)

The authoritative scoped ID format is `{tenantUuid}/{moduleOrResourceId}` and
`{tenantUuid}/{userUuid}`. Business's historical underscore IDs are incompatible;
do not reuse its local shadow SpiceDB client for eligibility. No enforcement
switch is changed by these endpoints.

- `GET /internal/v1/tenants/{id}/approval-membership-summary`: `iam:members:read`.
  Counts all active non-guest memberships, including seat-free employee, kiosk
  and service classes; excludes external guests and inactive/deleted/expired members.
  `sole_user_id` is non-null only at count 1.
- `POST /api/v1/authorization/lookup-subjects`: `authz:lookup`. See the byte-identical
  business fixtures in `internal/handlers/testdata/approvals`. Module and relation
  resources share this endpoint. Complete, fully consistent lookup; conditional
  candidates are retained conservatively, never silently denied. Wildcards or
  malformed/cross-tenant subjects refuse the whole result with 503. Set
  `active_non_guest_only:true` for authoritative membership filtering.
- `POST /api/v1/authorization/check-batch`: `authz:check`. Body
  `{"tenant_id":"UUID","user_id":"UUID","checks":[{"resource_type":"module",
  "resource_id":"UUID/mm","permission":"purchase_orders_approve"}]}`.
  Response `{"tenant_id":"UUID","user_id":"UUID","allowed":[true],"complete":true}`.
  1–100 checks, order preserved, fully consistent reads. Inactive/non-member
  subjects are denied; conditional checks never grant. Backend/item failure is
  503, not a partial or fail-open response.

All three routes require service JWT authentication. The request/path tenant
must equal the service tenant, or the JWT must carry `tenant:act-as` (also required
for unbound platform service tokens). Caller identity headers are not consulted.
The existing user-token `/api/v1/authorize/batch` remains unchanged.

Deploy business's additive `authz:lookup`, `authz:check`, `tenant:act-as` scope
grants before this image; no client-secret rotation is required. Apply the schema
with `payroll_run.approve_any` before the business payroll guard checks it.

## Team scope (service-token API)

- `GET /internal/v1/tenants/{id}/users/{user_id}/team-scope`: scope `iam:teams:read`
  (dedicated; `iam:members:read` is not accepted). Same service-JWT + `tenant:act-as`
  rule as the routes above. Response:
  `{"tenant_id","user_id","has_team":bool,"member_user_ids":[uuid],"teams":[{"id","name","org_type","role","manages":bool,"member_user_ids":[uuid]}]}`.
  Member of a team/department: all members of it. Manager/lead/owner: also all members of
  descendant organizations. `member_user_ids` is the sorted union and includes the caller
  when `has_team`; with no team it is empty and `has_team:false`. Backend failure is 503
  `team_scope_unavailable`.
- Tenant admin CRUD, `/api/v1/tenants/me/teams` (read: `iam:users:read`, write: `iam:users:update`;
  org_type forced to `team`): `GET|POST /me/teams`, `GET|PATCH|DELETE /me/teams/{id}`,
  `GET|POST /me/teams/{id}/members`, `PATCH|DELETE /me/teams/{id}/members/{user_id}`.
  Member role is `member` or `manager`.
