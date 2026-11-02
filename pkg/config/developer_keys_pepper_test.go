// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeveloperKeyPeppers(t *testing.T) {
	c := &Config{DeveloperKeysPepper: "one", DeveloperKeysPeppers: parseVersionedSecrets("v2=two, v3 = three ,bad,=x,v4=")}
	peppers, current := c.DeveloperKeyPeppers()
	assert.Equal(t, map[string]string{"v1": "one", "v2": "two", "v3": "three"}, peppers)
	assert.Equal(t, "v1", current)

	c.DeveloperKeysPepperCurrent = "v2"
	_, current = c.DeveloperKeyPeppers()
	assert.Equal(t, "v2", current)

	empty := &Config{}
	peppers, current = empty.DeveloperKeyPeppers()
	assert.Empty(t, peppers[current], "no pepper configured fails closed")
}
