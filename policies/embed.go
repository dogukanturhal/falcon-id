// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policies embeds the Rego policy set evaluated by the in-process
// OPA service. Policies are compiled into the binary so a missing or
// tampered directory on disk can never change an authorization outcome.
package policies

import "embed"

// PDP holds the policy decision point Rego modules (and their *_test.rego
// files, which the runtime loader skips).
//
//go:embed pdp/v1/*.rego
var PDP embed.FS

// PDPDir is the directory inside PDP that holds the v1 modules.
const PDPDir = "pdp/v1"
