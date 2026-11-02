// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func TestRedactedRedisURL(t *testing.T) {
	for in, want := range map[string]string{
		"redis://falcon-id:s3cret@redis.falcon-id.svc:6379/0": "redis://falcon-id:xxxxx@redis.falcon-id.svc:6379/0",
		"redis://:s3cret@redis:6379":                          "redis://:xxxxx@redis:6379",
		"redis://redis:6379/0":                                "redis://redis:6379/0",
		"redis://%zz":                                         "<unparseable redis url>",
	} {
		if got := redactedRedisURL(in); got != want {
			t.Errorf("redactedRedisURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedisRequiredError(t *testing.T) {
	down := errors.New("dial tcp: connection refused")
	if err := redisRequiredError(&config.Config{}, nil); err != nil {
		t.Errorf("not required, empty URL: got %v", err)
	}
	if err := redisRequiredError(&config.Config{}, down); err != nil {
		t.Errorf("not required, connect failure: got %v", err)
	}
	if err := redisRequiredError(&config.Config{RedisRequired: true}, nil); err == nil {
		t.Error("required, empty URL: want error")
	}
	if err := redisRequiredError(&config.Config{RedisRequired: true}, down); err == nil {
		t.Error("required, connect failure: want error")
	}
}
