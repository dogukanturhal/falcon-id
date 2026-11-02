// SPDX-License-Identifier: AGPL-3.0-or-later

package opsaudit

import (
	"encoding/json"
	"testing"
)

func TestWithApprovalMode(t *testing.T) {
	got := withApprovalMode([]byte(`{"a":1}`), "platform_admin_bypass")
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["approval_mode"] != "platform_admin_bypass" || m["a"] != float64(1) {
		t.Fatalf("unexpected details: %s", got)
	}
	if got := string(withApprovalMode([]byte(`{}`), "")); got != `{}` {
		t.Fatalf("empty mode must not change details: %s", got)
	}
	if got := string(withApprovalMode([]byte(`{"approval_mode":"four_eyes"}`), "platform_admin_bypass")); got != `{"approval_mode":"four_eyes"}` {
		t.Fatalf("existing mode must win: %s", got)
	}
	if got := string(withApprovalMode([]byte(`[1]`), "four_eyes")); got != `[1]` {
		t.Fatalf("non-object details must be untouched: %s", got)
	}
}
