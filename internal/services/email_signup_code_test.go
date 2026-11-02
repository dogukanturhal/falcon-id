// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatSignupCode_GroupsDigitsForReadability(t *testing.T) {
	assert.Equal(t, "482 913", formatSignupCode("482913"))
	assert.Equal(t, "012 345", formatSignupCode("012345"))
	assert.Equal(t, "1234", formatSignupCode("1234"), "non-6-digit input is left alone")
}
