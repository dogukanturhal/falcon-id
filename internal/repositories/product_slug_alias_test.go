// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
)

func TestListTemplateDerivedRolesByModule_SlugAlias(t *testing.T) {
	for _, module := range []string{"acmeweb", "acmeapp"} {
		t.Run(module, func(t *testing.T) {
			repo, mock := newRoleRepoMock(t)
			tenantID := uuid.New()
			mock.ExpectQuery(`module = ANY\(\$2\)`).
				WithArgs(tenantID, []string{"acmeapp", "acmeweb"}).
				WillReturnRows(pgxmock.NewRows([]string{"id"}))
			_, _ = repo.ListTemplateDerivedRolesByModule(context.Background(), tenantID, module)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestListLatestActiveByModules_SlugAlias(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	repo := &RoleTemplateRepository{db: mock}
	mock.ExpectQuery(`module = ANY\(\$1\)`).
		WithArgs([]string{"acmeapp", "acmeweb", "crm"}).
		WillReturnRows(pgxmock.NewRows([]string{"id"}))
	_, _ = repo.ListLatestActiveByModules(context.Background(), []string{"acmeapp", "crm"})
	require.NoError(t, mock.ExpectationsWereMet())
}
