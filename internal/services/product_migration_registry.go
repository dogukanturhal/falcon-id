// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ProductMigrationResolver resolves product migration sources to an fs.FS
// containing the SQL migration files.
//
// Resolution order:
//  1. Static registry (map[string]fs.FS) — for compile-time embedded migrations
//     or test overrides.
//  2. Filesystem discovery — reads SQL files from basePath/<migration_source>/
//     at runtime, matching the db-migrator pattern.
//
// To add migrations for a new product or module:
//   - Add SQL files to <PRODUCT_MIGRATIONS_PATH>/<migration_source>/ directory
//   - Set the product's manifest.database.migration_source to the directory name
//   - No Go code changes required
type ProductMigrationResolver struct {
	mu       sync.RWMutex
	registry map[string]fs.FS
	basePath string // filesystem base path for migration discovery
}

// NewProductMigrationResolver creates a resolver with the given filesystem base path.
// If basePath is empty, only the static registry will be used.
func NewProductMigrationResolver(basePath string) *ProductMigrationResolver {
	return &ProductMigrationResolver{
		registry: make(map[string]fs.FS),
		basePath: basePath,
	}
}

// Register adds an embedded fs.FS for a migration source. This takes priority
// over filesystem discovery. Useful for testing and for products whose migrations
// are compiled into the binary.
func (r *ProductMigrationResolver) Register(name string, fsys fs.FS) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fsys == nil {
		panic(fmt.Sprintf("product_migration_resolver: Register called with nil FS for %q", name))
	}
	if _, dup := r.registry[name]; dup {
		panic(fmt.Sprintf("product_migration_resolver: Register called twice for %q", name))
	}
	r.registry[name] = fsys
}

// Resolve returns the migration fs.FS for the given migration source name.
// It checks the static registry first, then falls back to filesystem discovery.
func (r *ProductMigrationResolver) Resolve(name string) (fs.FS, bool) {
	// Check static registry first.
	r.mu.RLock()
	fsys, ok := r.registry[name]
	r.mu.RUnlock()
	if ok {
		return fsys, true
	}

	// Fall back to filesystem discovery.
	if r.basePath == "" {
		return nil, false
	}

	dir := filepath.Join(r.basePath, name)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, false
	}

	// Verify there are actually SQL files in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Log.Warn("Failed to read product migrations directory",
			zap.String("path", dir),
			zap.Error(err),
		)
		return nil, false
	}

	hasSQLFiles := false
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			hasSQLFiles = true
			break
		}
	}

	if !hasSQLFiles {
		logger.Log.Warn("Product migrations directory has no SQL files",
			zap.String("path", dir),
			zap.String("migration_source", name),
		)
		return nil, false
	}

	return os.DirFS(dir), true
}

// RegisteredNames returns all statically registered migration source names
// (for diagnostics and health checks).
func (r *ProductMigrationResolver) RegisteredNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.registry))
	for name := range r.registry {
		names = append(names, name)
	}
	return names
}

// AvailableSources returns all migration sources available through both
// the static registry and filesystem discovery (for diagnostics).
func (r *ProductMigrationResolver) AvailableSources() []string {
	sources := r.RegisteredNames()
	seen := make(map[string]bool, len(sources))
	for _, s := range sources {
		seen[s] = true
	}

	if r.basePath != "" {
		sources = r.discoverFSMigrationSources(sources, seen)
	}

	return sources
}

// discoverFSMigrationSources scans r.basePath for subdirectories containing .sql files
// and appends any not already in seen to sources.
func (r *ProductMigrationResolver) discoverFSMigrationSources(sources []string, seen map[string]bool) []string {
	entries, err := os.ReadDir(r.basePath)
	if err != nil {
		return sources
	}
	for _, entry := range entries {
		if !entry.IsDir() || seen[entry.Name()] {
			continue
		}
		subEntries, err := os.ReadDir(filepath.Join(r.basePath, entry.Name()))
		if err != nil {
			continue
		}
		for _, se := range subEntries {
			if !se.IsDir() && filepath.Ext(se.Name()) == ".sql" {
				sources = append(sources, entry.Name())
				break
			}
		}
	}
	return sources
}
