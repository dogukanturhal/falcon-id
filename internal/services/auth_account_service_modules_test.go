// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveEntitledModules_IncludesPreaccountingAndPayroll(t *testing.T) {
	all := deriveEntitledModules(nil, nil, true)
	assert.Contains(t, all, "preaccounting")
	assert.Contains(t, all, "payroll")

	got := deriveEntitledModules(nil, []string{"preaccounting:invoices:read", "payroll:runs:read"}, false)
	assert.ElementsMatch(t, []string{"preaccounting", "payroll"}, got)
}
