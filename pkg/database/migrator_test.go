// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"
	"testing/fstest"
)

func TestIsUpMigration(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"plain sql", "001_create_tables.sql", true},
		{"up sql", "045_add_fks.up.sql", true},
		{"down sql", "001_create_tables.down.sql", false},
		{"verify sql", "verify_040_migration.sql", false},
		{"no version prefix", "readme.sql", false},
		{"markdown file", "040_README.md", false},
		{"empty name", "", false},
		{"nested down", "030_realms.down.sql", false},
		{"single digit version", "1_test.sql", true},
		{"three digit version", "100_future.sql", true},
		{"up suffix with description", "057_clear_iam_settings_ldap_password.up.sql", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUpMigration(tt.filename)
			if got != tt.want {
				t.Errorf("isUpMigration(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     int
		wantErr  bool
	}{
		{"three digit", "001_create_tables.sql", 1, false},
		{"two digit", "45_add_fks.up.sql", 45, false},
		{"large number", "999_future.sql", 999, false},
		{"invalid", "readme.sql", 0, true},
		{"no underscore", "001.sql", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVersion(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVersion(%q) error = %v, wantErr %v", tt.filename, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseVersion(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestChecksumBytes(t *testing.T) {
	data := []byte("CREATE TABLE users (id SERIAL PRIMARY KEY);")
	got := checksumBytes(data)

	// Verify against standard library directly
	h := sha256.Sum256(data)
	want := fmt.Sprintf("%x", h)

	if got != want {
		t.Errorf("checksumBytes() = %q, want %q", got, want)
	}

	// Verify deterministic
	got2 := checksumBytes(data)
	if got != got2 {
		t.Error("checksumBytes() is not deterministic")
	}

	// Verify different data produces different checksum
	other := checksumBytes([]byte("DROP TABLE users;"))
	if got == other {
		t.Error("different data produced same checksum")
	}
}

func TestGetAvailableMigrations_SortingAndFiltering(t *testing.T) {
	// Create an in-memory filesystem with test migration files
	fsys := fstest.MapFS{
		"003_seed_data.sql":               {Data: []byte("INSERT INTO t VALUES (1);")},
		"001_create_tables.sql":           {Data: []byte("CREATE TABLE t (id INT);")},
		"002_add_columns.sql":             {Data: []byte("ALTER TABLE t ADD col TEXT;")},
		"001_create_tables.down.sql":      {Data: []byte("DROP TABLE t;")},
		"verify_001_migration.sql":        {Data: []byte("SELECT 1;")},
		"010_add_index.up.sql":            {Data: []byte("CREATE INDEX idx ON t(id);")},
		"010_add_index.down.sql":          {Data: []byte("DROP INDEX idx;")},
		"040_README.md":                   {Data: []byte("# Migration guide")},
		"040_IMPLEMENTATION_CHECKLIST.md": {Data: []byte("- [ ] Done")},
	}

	migrator := NewMigrator(nil, fsys, nil)
	migrations, err := migrator.getAvailableMigrations()
	if err != nil {
		t.Fatalf("getAvailableMigrations() error = %v", err)
	}

	// Should only include up migrations: 001, 002, 003, 010
	if len(migrations) != 4 {
		t.Fatalf("expected 4 migrations, got %d", len(migrations))
	}

	// Verify sorted by version ascending
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			t.Errorf("migrations not sorted: version %d after version %d",
				migrations[i].Version, migrations[i-1].Version)
		}
	}

	// Verify versions
	expectedVersions := []int{1, 2, 3, 10}
	for i, want := range expectedVersions {
		if migrations[i].Version != want {
			t.Errorf("migration[%d].Version = %d, want %d", i, migrations[i].Version, want)
		}
	}

	// Verify checksums are populated
	for _, mig := range migrations {
		if mig.Checksum == "" {
			t.Errorf("migration %d has empty checksum", mig.Version)
		}
		if len(mig.Checksum) != 64 { // SHA-256 hex = 64 chars
			t.Errorf("migration %d checksum length = %d, want 64", mig.Version, len(mig.Checksum))
		}
	}

	// Verify SQL content is loaded
	if migrations[0].SQL != "CREATE TABLE t (id INT);" {
		t.Errorf("migration 1 SQL = %q, want %q", migrations[0].SQL, "CREATE TABLE t (id INT);")
	}
}

func TestGetAvailableMigrations_DuplicateVersionHandling(t *testing.T) {
	// When both NNN_desc.sql and NNN_desc.up.sql exist for the same version,
	// we expect the plain .sql to be included (it matches first alphabetically
	// and isUpMigration accepts it). The .up.sql variant also matches.
	// The migrator should include both — but in practice the codebase doesn't
	// have both for the same version. This test documents the behavior.
	fsys := fstest.MapFS{
		"001_create.sql":    {Data: []byte("CREATE TABLE a;")},
		"001_create.up.sql": {Data: []byte("CREATE TABLE b;")},
	}

	migrator := NewMigrator(nil, fsys, nil)
	migrations, err := migrator.getAvailableMigrations()
	if err != nil {
		t.Fatalf("getAvailableMigrations() error = %v", err)
	}

	// Both files match isUpMigration and have version 1
	// The migrator will include both — this is technically a misconfiguration
	// In the real codebase, each version has only one up migration
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations (both match), got %d", len(migrations))
	}
}

func TestMigrationSorting(t *testing.T) {
	migrations := []Migration{
		{Version: 50},
		{Version: 1},
		{Version: 100},
		{Version: 25},
		{Version: 3},
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	expected := []int{1, 3, 25, 50, 100}
	for i, want := range expected {
		if migrations[i].Version != want {
			t.Errorf("sorted[%d].Version = %d, want %d", i, migrations[i].Version, want)
		}
	}
}

func TestGetAvailableMigrations_EmptyFS(t *testing.T) {
	fsys := fstest.MapFS{}

	migrator := NewMigrator(nil, fsys, nil)
	migrations, err := migrator.getAvailableMigrations()
	if err != nil {
		t.Fatalf("getAvailableMigrations() error = %v", err)
	}

	if len(migrations) != 0 {
		t.Errorf("expected 0 migrations from empty FS, got %d", len(migrations))
	}
}

func TestGetAvailableMigrations_OnlyDownFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"001_create.down.sql": {Data: []byte("DROP TABLE t;")},
		"002_add.down.sql":    {Data: []byte("ALTER TABLE t DROP col;")},
	}

	migrator := NewMigrator(nil, fsys, nil)
	migrations, err := migrator.getAvailableMigrations()
	if err != nil {
		t.Fatalf("getAvailableMigrations() error = %v", err)
	}

	if len(migrations) != 0 {
		t.Errorf("expected 0 up migrations, got %d", len(migrations))
	}
}
