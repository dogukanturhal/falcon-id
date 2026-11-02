// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsTransientConnectError(t *testing.T) {
	pg := func(code string) error { return fmt.Errorf("ping: %w", &pgconn.PgError{Code: code}) }
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"53300", pg("53300"), true},
		{"57P03", pg("57P03"), true},
		{"08006", pg("08006"), true},
		{"28P01", pg("28P01"), false},
		{"3D000", pg("3D000"), false},
		{"net", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"parse", errors.New("cannot parse"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isTransientConnectError(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestRetryTransient(t *testing.T) {
	var clock time.Time
	var sleeps []time.Duration
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { sleeps = append(sleeps, d); clock = clock.Add(d) }
	transient := &pgconn.PgError{Code: "53300"}

	t.Run("succeeds after retries with capped backoff", func(t *testing.T) {
		clock, sleeps = time.Time{}, nil
		n := 0
		err := retryTransient(time.Minute, now, sleep, func() error {
			if n++; n < 6 {
				return transient
			}
			return nil
		})
		if err != nil || n != 6 {
			t.Fatalf("err=%v n=%d", err, n)
		}
		want := []time.Duration{1, 2, 4, 8, 8}
		for i, w := range want {
			if sleeps[i] != w*time.Second {
				t.Fatalf("sleeps=%v", sleeps)
			}
		}
	})

	t.Run("stops at budget", func(t *testing.T) {
		clock, sleeps = time.Time{}, nil
		n := 0
		err := retryTransient(10*time.Second, now, sleep, func() error { n++; return transient })
		if err == nil || !errors.Is(err, transient) {
			t.Fatalf("err=%v", err)
		}
		if clock.Sub(time.Time{}) > 10*time.Second || n < 2 {
			t.Fatalf("elapsed=%v n=%d", clock.Sub(time.Time{}), n)
		}
	})

	t.Run("non-transient fails immediately", func(t *testing.T) {
		clock, sleeps = time.Time{}, nil
		n := 0
		err := retryTransient(time.Minute, now, sleep, func() error { n++; return &pgconn.PgError{Code: "28P01"} })
		if err == nil || n != 1 || len(sleeps) != 0 {
			t.Fatalf("err=%v n=%d sleeps=%v", err, n, sleeps)
		}
	})
}
