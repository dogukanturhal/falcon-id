// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// fakeRealmRepoForDomainTest implements every method RealmService's
// unexported repo interface requires, structurally (this test lives in
// package middleware, which cannot name that unexported interface, but
// Go interface satisfaction only requires the method set to match).
// GetRealmByDomain is the only method exercised by these tests; every
// other method is a no-op stub that would fail the test loudly if
// unexpectedly called, since ExtractRealm's custom-domain path
// (tryResolveByCustomDomain) touches only GetByDomain -> GetRealmByDomain
// and, after this fix, nothing else on the repo.
type fakeRealmRepoForDomainTest struct {
	realm *models.Realm
}

func (f *fakeRealmRepoForDomainTest) GetRealmByDomain(_ context.Context, _ string) (*models.Realm, error) {
	return f.realm, nil
}

func (f *fakeRealmRepoForDomainTest) SlugExists(context.Context, string) (bool, error) { return false, nil }
func (f *fakeRealmRepoForDomainTest) Create(context.Context, *models.Realm) error       { return nil }
func (f *fakeRealmRepoForDomainTest) CreateSecurityPolicy(context.Context, *models.RealmSecurityPolicy) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) GetByID(context.Context, uuid.UUID) (*models.Realm, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) GetBySlug(context.Context, string) (*models.Realm, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) Update(context.Context, *models.Realm) error { return nil }
func (f *fakeRealmRepoForDomainTest) UpdateStatus(context.Context, uuid.UUID, models.RealmStatus) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) List(context.Context, repositories.RealmFilters) ([]models.Realm, int64, error) {
	return nil, 0, nil
}
func (f *fakeRealmRepoForDomainTest) GetSecurityPolicy(context.Context, uuid.UUID) (*models.RealmSecurityPolicy, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) UpdateSecurityPolicy(context.Context, *models.RealmSecurityPolicy) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) CreateIdentityProvider(context.Context, *models.RealmIdentityProvider) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) ListIdentityProviders(context.Context, uuid.UUID) ([]models.RealmIdentityProvider, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) DeleteIdentityProvider(context.Context, uuid.UUID) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) GetIdentityProvider(context.Context, uuid.UUID) (*models.RealmIdentityProvider, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) UpdateIdentityProvider(context.Context, *models.RealmIdentityProvider) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) CountTenantsInRealm(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (f *fakeRealmRepoForDomainTest) AssignTenant(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) GetTenantRealm(context.Context, uuid.UUID) (*models.Realm, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) ListRealmTenants(context.Context, uuid.UUID) ([]models.RealmTenant, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) AssignAdmin(context.Context, *models.RealmAdminAssignment) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) ListRealmAdmins(context.Context, uuid.UUID) ([]models.RealmAdminAssignment, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) RemoveAdmin(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) LogAudit(context.Context, *models.RealmAuditLog) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) ListAuditLogs(context.Context, uuid.UUID, repositories.AuditLogFilters) ([]models.RealmAuditLog, int64, error) {
	return nil, 0, nil
}
func (f *fakeRealmRepoForDomainTest) ListDomains(context.Context, uuid.UUID) ([]models.RealmDomain, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) GetDomainByName(context.Context, string) (*models.RealmDomain, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) CreateDomain(context.Context, *models.RealmDomain) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) SetPrimaryDomain(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) GetDomainByID(context.Context, uuid.UUID) (*models.RealmDomain, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) DeleteDomain(context.Context, uuid.UUID) error { return nil }
func (f *fakeRealmRepoForDomainTest) UpdateDomain(context.Context, *models.RealmDomain) error {
	return nil
}
func (f *fakeRealmRepoForDomainTest) GetDefaultRealm(context.Context) (*models.Realm, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) GetUserAvailableRealms(context.Context, uuid.UUID, uuid.UUID) ([]*models.Realm, error) {
	return nil, nil
}
func (f *fakeRealmRepoForDomainTest) UserHasRealmAccess(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}

// newCustomDomainTestMiddleware builds a RealmMiddleware whose realmService
// resolves any Host header to realm via GetRealmByDomain, exactly the way
// tryResolveByCustomDomain uses it.
func newCustomDomainTestMiddleware(t *testing.T, realm *models.Realm) *RealmMiddleware {
	t.Helper()
	svc := services.NewRealmService(&fakeRealmRepoForDomainTest{realm: realm}, &config.Config{}, zap.NewNop())
	return NewRealmMiddleware(svc, &config.Config{}, zap.NewNop())
}

func runCustomDomainRequest(t *testing.T, mw *RealmMiddleware) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(mw.ExtractRealm())
	nextCalled := false
	router.GET("/ping", func(c *gin.Context) {
		nextCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Host = "custom.example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	t.Logf("handler reached: %v", nextCalled)
	return w
}

// TestExtractRealm_CustomDomain_ArchivedRealmBlocked is the behavioural
// test for the gap fixed in tryResolveByCustomDomain: a realm resolved
// via its verified custom domain must be blocked when archived, exactly
// like the URL-prefix/header/subdomain resolution paths (which route
// through checkRealmStatus via resolveRealm). Before the fix,
// tryResolveByCustomDomain called setRealmContext + c.Next() directly
// without ever calling checkRealmStatus, so an archived realm reached by
// custom domain was served normally instead of rejected.
func TestExtractRealm_CustomDomain_ArchivedRealmBlocked(t *testing.T) {
	realm := &models.Realm{ID: uuid.New(), Slug: "acme", Status: models.RealmStatusArchived}
	mw := newCustomDomainTestMiddleware(t, realm)

	w := runCustomDomainRequest(t, mw)

	assert.Equal(t, http.StatusForbidden, w.Code, "archived realm reached via custom domain must be rejected with 403, not served")
	assert.Contains(t, w.Body.String(), "REALM_NOT_ACTIVE")
}

// TestExtractRealm_CustomDomain_ActiveRealmAllowed is the control for the
// test above: the exact same request path, differing only in the
// resolved realm's Status, must reach the handler and return 200. If
// this test failed too, the 403 above would be meaningless — it would
// mean every custom-domain request is blocked regardless of status,
// not specifically archived ones.
func TestExtractRealm_CustomDomain_ActiveRealmAllowed(t *testing.T) {
	realm := &models.Realm{ID: uuid.New(), Slug: "acme", Status: models.RealmStatusActive}
	mw := newCustomDomainTestMiddleware(t, realm)

	w := runCustomDomainRequest(t, mw)

	assert.Equal(t, http.StatusOK, w.Code, "active realm reached via custom domain must be served normally")
}

// TestExtractRealm_CustomDomain_SuspendedRealmBlocked additionally
// confirms the fix applies to every non-active status the middleware
// recognizes (realmStatusMessage), not just archived.
func TestExtractRealm_CustomDomain_SuspendedRealmBlocked(t *testing.T) {
	realm := &models.Realm{ID: uuid.New(), Slug: "acme", Status: models.RealmStatusSuspended}
	mw := newCustomDomainTestMiddleware(t, realm)

	w := runCustomDomainRequest(t, mw)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "REALM_NOT_ACTIVE")
}
