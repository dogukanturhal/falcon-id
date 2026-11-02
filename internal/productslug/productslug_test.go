// SPDX-License-Identifier: AGPL-3.0-or-later

package productslug

import (
	"reflect"
	"testing"
)

func TestEquivalent(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"acmeweb", "acmeweb", true},
		{"acmeapp", "acmeapp", true},
		{"acmeweb", "acmeapp", true},
		{"acmeapp", "acmeweb", true},
		{"ACMEWEB", " acmeapp ", true},
		{"acmeweb", "crm", false},
		{"crm", "acmeapp", false},
		{"crm", "crm", true},
		{"", "acmeweb", false},
	}
	for _, tc := range tests {
		if got := Equivalent(tc.a, tc.b); got != tc.want {
			t.Errorf("Equivalent(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAliases(t *testing.T) {
	if got := Aliases("AcmeWeb"); !reflect.DeepEqual(got, []string{"acmeapp", "acmeweb"}) {
		t.Errorf("got %v", got)
	}
	if got := Aliases("acmeapp"); !reflect.DeepEqual(got, []string{"acmeapp", "acmeweb"}) {
		t.Errorf("got %v", got)
	}
	if got := Aliases("CRM"); !reflect.DeepEqual(got, []string{"CRM"}) {
		t.Errorf("got %v", got)
	}
}

func TestExpand(t *testing.T) {
	if got := Expand(nil); got != nil {
		t.Errorf("nil in must stay nil, got %v", got)
	}
	got := Expand([]string{"crm", "acmeweb", "acmeapp"})
	want := []string{"crm", "acmeweb", "acmeapp"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	got = Expand([]string{"acmeapp", "crm"})
	want = []string{"acmeapp", "acmeweb", "crm"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestContains(t *testing.T) {
	if !Contains([]string{"crm", "acmeapp"}, "acmeweb") {
		t.Error("want true")
	}
	if Contains([]string{"crm"}, "acmeweb") {
		t.Error("want false")
	}
}
