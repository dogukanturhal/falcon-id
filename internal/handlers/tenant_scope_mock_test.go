// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
)

// expectTenantScope scripts the two statements repositories.WithTenantScope
// issues right after Begin: set_config, then the verify read-back.
func expectTenantScope(mock pgxmock.PgxCommonIface, tenantID uuid.UUID) {
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).WithArgs(tenantID.String()).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectQuery(`SELECT current_setting\('app.current_tenant_id', true\)`).
		WillReturnRows(pgxmock.NewRows([]string{"current_setting"}).AddRow(tenantID.String()))
}
