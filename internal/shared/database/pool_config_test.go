// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadPoolConfigPrefixed(t *testing.T) {
	for _, k := range []string{"MAX_OPEN_CONNS", "MIN_CONNS", "MAX_IDLE_CONNS"} {
		t.Setenv("DB_"+k, "")
		t.Setenv("CONTROL_PLANE_DB_"+k, "")
	}

	d := LoadPoolConfig()
	if d.MaxOpenConns != 10 || d.MinConns != 0 || d.MaxIdleConns != 10 {
		t.Fatalf("defaults: %+v", d)
	}

	t.Setenv("DB_MAX_OPEN_CONNS", "16")
	t.Setenv("DB_MIN_CONNS", "2")
	cp := LoadPoolConfigPrefixed("CONTROL_PLANE_DB_")
	if cp.MaxOpenConns != 16 || cp.MinConns != 2 {
		t.Fatalf("fallback to DB_*: %+v", cp)
	}

	t.Setenv("CONTROL_PLANE_DB_MAX_OPEN_CONNS", "3")
	t.Setenv("CONTROL_PLANE_DB_MIN_CONNS", "1")
	cp = LoadPoolConfigPrefixed("CONTROL_PLANE_DB_")
	if cp.MaxOpenConns != 3 || cp.MinConns != 1 {
		t.Fatalf("prefixed precedence: %+v", cp)
	}
	if dp := LoadPoolConfig(); dp.MaxOpenConns != 16 || dp.MinConns != 2 {
		t.Fatalf("LoadPoolConfig: %+v", dp)
	}
}

func TestApplyToPgxPoolUsesMinConns(t *testing.T) {
	c := DefaultPoolConfig()
	c.MaxIdleConns = 10
	c.MinConns = 1
	var pc pgxpool.Config
	c.ApplyToPgxPool(&pc)
	if pc.MinConns != 1 || pc.MaxConns != 10 {
		t.Fatalf("min=%d max=%d", pc.MinConns, pc.MaxConns)
	}
}
