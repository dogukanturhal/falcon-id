// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Platform-default SoD rules match permission names exactly (services.SoDService.EvaluateUser). A seed that names a
// permission nobody holds can never fire (FLOW-9 / S7: mm:requisition:* vs mm:purchase_requisitions:*). This pins every
// still-active seeded default to the canonical permission catalogue, the SpiceDB schema, whose permission names are the
// "<resource>_<action>" form of the <module>:<resource>:<action> catalogue names the business manifests register.

var (
	sodSeedTuple   = regexp.MustCompile(`\(NULL,\s*'[a-z_]+',\s*'([^']+)',\s*'([^']+)',\s*'(?:warn|block)'`)
	sodDisablePair = regexp.MustCompile(`(?s)disabled_at\s*=\s*now\(\).*?permission_a\s*=\s*'([^']+)'\s*AND\s*permission_b\s*=\s*'([^']+)'`)
	zedPermission  = regexp.MustCompile(`(?m)^\s*permission\s+([a-z0-9_]+)\s*=`)
)

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// activeSeededSoDPairs replays every migration that touches the platform SoD defaults, in file order: seeds add a pair,
// a later migration's disabling UPDATE removes it again.
func activeSeededSoDPairs(t *testing.T) map[[2]string]bool {
	t.Helper()
	files, err := filepath.Glob("0*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	active := map[[2]string]bool{}
	for _, f := range files {
		sql := readFile(t, f)
		if !strings.Contains(sql, "iam_sod_rules") {
			continue
		}
		for _, m := range sodSeedTuple.FindAllStringSubmatch(sql, -1) {
			active[[2]string{m[1], m[2]}] = true
		}
		for _, m := range sodDisablePair.FindAllStringSubmatch(sql, -1) {
			delete(active, [2]string{m[1], m[2]})
		}
	}
	return active
}

func catalogueHasPermission(zed map[string]bool, name string) bool {
	parts := strings.Split(name, ":")
	if len(parts) != 3 {
		return false
	}
	return zed[strings.ReplaceAll(parts[1]+"_"+parts[2], "-", "_")]
}

func TestSeededSoDRulesReferenceCataloguePermissions(t *testing.T) {
	zed := map[string]bool{}
	for _, m := range zedPermission.FindAllStringSubmatch(readFile(t, "../../deploy/helm/spicedb-schema/files/spicedb.zed"), -1) {
		zed[m[1]] = true
	}
	if len(zed) == 0 {
		t.Fatal("no permissions parsed from spicedb.zed")
	}

	active := activeSeededSoDPairs(t)
	if len(active) < 9 {
		t.Fatalf("expected at least 9 active seeded SoD rules, parsed %d", len(active))
	}
	for pair := range active {
		for _, p := range pair {
			if !catalogueHasPermission(zed, p) {
				t.Errorf("seeded SoD rule %s <-> %s references %q, which is not in the permission catalogue", pair[0], pair[1], p)
			}
		}
	}
}

func TestSeededSoDRulesDeadDefaultDisabledAndFlow9PairsPresent(t *testing.T) {
	active := activeSeededSoDPairs(t)
	if active[[2]string{"mm:requisition:create", "mm:requisition:approve"}] {
		t.Error("dead default mm:requisition:create <-> approve must be disabled")
	}
	for _, want := range [][2]string{
		{"mm:purchase_requisitions:create", "mm:purchase_requisitions:approve"},
		{"mm:purchase_orders:create", "mm:invoice-match:override"},
		{"mm:vendors:update", "preaccounting:payments:create"},
		{"payroll:runs:calculate", "payroll:runs:pay"},
		{"preaccounting:expenses:create", "preaccounting:expenses:approve"},
	} {
		if !active[want] {
			t.Errorf("missing active seeded SoD rule %s <-> %s", want[0], want[1])
		}
	}
}
