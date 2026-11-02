// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestReadyReturns503WhenDraining(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { draining.Store(false) })
	router := gin.New()
	registerHealthRoutes(router, &Infrastructure{})

	draining.Store(true)
	for _, path := range []string{"/health/ready", "/ready"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s while draining: got %d, want 503", path, w.Code)
		}
	}

	// Liveness stays up while draining.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/health while draining: got %d, want 200", w.Code)
	}
}

func TestGracefulShutdownOrder(t *testing.T) {
	t.Cleanup(func() { draining.Store(false) })
	draining.Store(false)
	var order []string
	gracefulShutdown(
		7*time.Second, 3*time.Second,
		func(d time.Duration) {
			if !draining.Load() {
				t.Error("draining flag must be set before the drain sleep")
			}
			if d != 7*time.Second {
				t.Errorf("sleep = %v, want 7s", d)
			}
			order = append(order, "drain")
		},
		func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("shutdown ctx must carry a deadline")
			}
			order = append(order, "shutdown")
			return nil
		},
		func() { order = append(order, "background") },
		func(context.Context) { order = append(order, "flush") },
	)
	want := []string{"drain", "shutdown", "background", "flush"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestDurationFromEnv(t *testing.T) {
	t.Setenv("X_DUR", "")
	if got := durationFromEnv("X_DUR", 5*time.Second); got != 5*time.Second {
		t.Fatalf("unset: %v", got)
	}
	t.Setenv("X_DUR", "2s")
	if got := durationFromEnv("X_DUR", 5*time.Second); got != 2*time.Second {
		t.Fatalf("set: %v", got)
	}
	t.Setenv("X_DUR", "bogus")
	if got := durationFromEnv("X_DUR", 5*time.Second); got != 5*time.Second {
		t.Fatalf("bogus: %v", got)
	}
}
