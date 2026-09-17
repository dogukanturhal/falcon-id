// SPDX-License-Identifier: AGPL-3.0-or-later

// Package services — UserPreferencesService manages the per-user opaque
// JSONB stored at iam_users.preferences (migration 0003).
//
// Design notes (2026-06-02 Option C onboarding-state architecture):
//
//   - Preferences are an OPAQUE bag at the storage layer. The service
//     enforces two invariants at write time: (1) the top-level value MUST
//     be a JSON object, (2) writes to `products.<slug>.*` are gated on
//     <slug> being in productRegistry. Everything else is opaque to
//     falcon-id; product BFFs (Mearax, Hexx-Forge, …) own their subtree
//     shape and bump products.<slug>.schema_version independently.
//
//   - JSON Merge Patch (RFC 7396) is the WRITE shape. PATCHing
//     {"products":{"mearax":{"onboarding":{"tour_seen":true}}}} ONLY
//     touches that leaf — siblings (global/locale, other products) are
//     untouched. RFC 6902 JSON-Patch is out of scope: too easy to write
//     a bad client that nukes the whole document.
//
//   - Atomic SQL `jsonb_set` / `||` for merging at the DB layer
//     guarantees concurrent PATCHes from two browser tabs don't lose
//     state (last-tab-wins inside the same key path; siblings preserved).
//     The pgx UPDATE ... RETURNING preferences round-trip is the
//     authoritative read.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// productRegistry — slugs that may appear under preferences.products.<slug>.
// Adding a new product is a falcon-id source change (one-line edit) — NOT
// a DDL migration. Slugs use snake_case to match the JSONB convention
// across the platform.
//
// The registry intentionally does not declare per-product JSON schemas:
// each product BFF validates its own subtree shape before PATCHing. The
// platform's role is to gate access to the namespace, not to enforce
// inter-product contracts.
var productRegistry = map[string]struct{}{
	"mearax":              {},
	"hexx_forge":          {},
	"hexx_cloud":          {},
	"hexx_ops":            {},
	"hexx_shield":         {},
	"accounts":            {},
	"falcon_admin":        {},
	"platform_admin":      {},
	"unified_dashboard":   {},
	"public_website":      {},
	"landing_hexxlock":    {},
	"login":               {},
}

// Errors surfaced to handlers.
var (
	ErrPrefsNotObject     = errors.New("preferences must be a JSON object")
	ErrPrefsUnknownProduct = errors.New("unknown product slug")
	ErrPrefsInvalidShape   = errors.New("invalid preferences shape")
)

// UserPreferencesService is the read/write surface for iam_users.preferences.
type UserPreferencesService struct {
	pool *pgxpool.Pool
}

// NewUserPreferencesService constructs a service over the pgx pool.
func NewUserPreferencesService(pool *pgxpool.Pool) *UserPreferencesService {
	return &UserPreferencesService{pool: pool}
}

// Get returns the user's full preferences object. If the column is the
// zero-value `{}`, returns json.RawMessage("{}") — never nil.
func (s *UserPreferencesService) Get(ctx context.Context, userID uuid.UUID) (json.RawMessage, error) {
	var raw json.RawMessage
	row := s.pool.QueryRow(ctx, `SELECT preferences FROM iam_users WHERE id = $1`, userID)
	if err := row.Scan(&raw); err != nil {
		return nil, fmt.Errorf("user preferences read: %w", err)
	}
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	return raw, nil
}

// PatchGlobal applies a JSON Merge Patch (RFC 7396) to the
// `preferences.global` subtree only.
func (s *UserPreferencesService) PatchGlobal(ctx context.Context, userID uuid.UUID, patch json.RawMessage) (json.RawMessage, error) {
	return s.patchPath(ctx, userID, []string{"global"}, patch)
}

// PatchProduct applies a JSON Merge Patch (RFC 7396) to the
// `preferences.products.<slug>` subtree. Rejects unknown slugs.
func (s *UserPreferencesService) PatchProduct(ctx context.Context, userID uuid.UUID, slug string, patch json.RawMessage) (json.RawMessage, error) {
	if _, ok := productRegistry[slug]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrPrefsUnknownProduct, slug)
	}
	if err := assertJSONObject(patch); err != nil {
		return nil, err
	}
	return s.patchPath(ctx, userID, []string{"products", slug}, patch)
}

// patchPath does the actual UPDATE. Uses jsonb_set with create_missing=true
// plus the `||` merge operator on the leaf to preserve siblings within the
// subtree. Wrapped in a single SQL statement so concurrent tabs see
// consistent state.
//
// IMPORTANT: jsonb_set's create_missing flag ONLY creates the FINAL key in
// the path — intermediate ancestors must already exist. Per the Postgres
// docs: "All earlier steps in the path must exist, or the target is
// returned unchanged." That means a fresh row with preferences = '{}'
// silently no-ops on jsonb_set(preferences, ['products','mearax'], …)
// because `products` doesn't exist yet — the UPDATE "succeeds" but the
// column stays `{}`. This was the first-PATCH-loses-the-write bug observed
// 2026-06-04 (welcome dialog stuck open even though /api/v1/users/me/
// preferences/products/mearax returned 200).
//
// Fix: split the apply into two nested jsonb_set calls — the inner one
// pre-creates the parent path with an empty object if missing, the outer
// one then writes the leaf. For length-1 paths the parent IS root, so the
// inner call is a no-op (handled via the CASE branch).
//
// NOTE on merge depth: jsonb's `||` is a SHALLOW merge — overlapping keys
// at the immediate level replace wholesale. For nested patches like
// `{"onboarding":{"tour_seen":true}}` against an existing
// `{"onboarding":{"welcomed":true}}`, the `onboarding` key is REPLACED,
// losing `welcomed`. For the current scope (one shallow object per
// PATCH call) this is acceptable; deep-merge can be added later via a
// jsonb_deep_merge helper or a recursive CTE.
func (s *UserPreferencesService) patchPath(
	ctx context.Context, userID uuid.UUID, path []string, patch json.RawMessage,
) (json.RawMessage, error) {
	if err := assertJSONObject(patch); err != nil {
		return nil, err
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("%w: empty path", ErrPrefsInvalidShape)
	}
	// pgx parametrises the path as TEXT[]. Path validation upstream
	// (productRegistry / known global key) prevents injection of
	// arbitrary path elements.
	//
	// For path = ["a"]:        outer jsonb_set, no parent to create.
	// For path = ["a","b",…]:  inner jsonb_set creates the parent
	//                          subarray with an empty object if missing,
	//                          outer jsonb_set writes the leaf.
	const sql = `
		UPDATE iam_users
		   SET preferences = CASE
		     WHEN array_length($2::text[], 1) = 1 THEN
		       jsonb_set(
		         preferences,
		         $2::text[],
		         COALESCE(preferences #> $2::text[], '{}'::jsonb) || $3::jsonb,
		         true
		       )
		     ELSE
		       jsonb_set(
		         jsonb_set(
		           preferences,
		           ($2::text[])[1 : array_length($2::text[], 1) - 1],
		           COALESCE(
		             preferences #> ($2::text[])[1 : array_length($2::text[], 1) - 1],
		             '{}'::jsonb
		           ),
		           true
		         ),
		         $2::text[],
		         COALESCE(preferences #> $2::text[], '{}'::jsonb) || $3::jsonb,
		         true
		       )
		   END,
		       updated_at = NOW()
		 WHERE id = $1
		 RETURNING preferences
	`
	var out json.RawMessage
	row := s.pool.QueryRow(ctx, sql, userID, path, []byte(patch))
	if err := row.Scan(&out); err != nil {
		return nil, fmt.Errorf("user preferences patch: %w", err)
	}
	return out, nil
}

// assertJSONObject verifies that the bytes parse to a top-level JSON
// object (not array, scalar, or null). Same invariant the Postgres CHECK
// constraint enforces — we validate up-front so the request errors with
// a clean 400 before hitting the DB.
func assertJSONObject(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty body", ErrPrefsInvalidShape)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("%w: %v", ErrPrefsInvalidShape, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return fmt.Errorf("%w: top-level must be an object", ErrPrefsNotObject)
	}
	return nil
}

// IsKnownProduct exposes the registry for handlers and tests.
func IsKnownProduct(slug string) bool {
	_, ok := productRegistry[slug]
	return ok
}
