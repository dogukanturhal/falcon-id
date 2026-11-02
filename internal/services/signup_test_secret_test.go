// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// testCompletionSecret is the completion secret every legacy CompleteSignup
// fixture presents; testCompletionSecretHash is what its stored request holds.
const testCompletionSecret = "test-completion-secret"

func testCompletionSecretHash() *string {
	h := hashCompletionSecret(testCompletionSecret)
	return &h
}
