// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// tenant_backup.go provides TenantBackupService, which creates and restores
// per-tenant database backups using a simple JSON Lines format.
//
// Backup format: a directory tree at {backupDir}/{realmID}/{timestamp}/
//
//   manifest.json          — metadata (realm_id, database_name, tables, row counts, created_at)
//   {table_name}.jsonl     — one JSON-encoded row per line for each table
//
// Why JSON Lines instead of pg_dump?
//   - No dependency on the pg_dump binary (not always in the container image).
//   - Human-readable; easy to inspect and audit.
//   - Portable across PostgreSQL major versions.
//   - Straightforward to implement in pure Go using pgx and encoding/json.
//
// Trade-off: large text objects (bytea, text[]) are less compact than pg_dump's
// custom format. For production use consider chunked streaming; this implementation
// keeps each table in memory only one row at a time.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// defaultBackupDir is used when no backupDir is passed to the constructor.
const defaultBackupDir = "/tmp/hexxlock-backups"

// BackupResult describes a completed backup operation.
type BackupResult struct {
	RealmID      uuid.UUID `json:"realm_id"`
	DatabaseName string    `json:"database_name"`
	BackupFile   string    `json:"backup_file"` // absolute path to the backup directory
	Size         int64     `json:"size_bytes"`
	Tables       int       `json:"tables"`
	Rows         int64     `json:"rows"`
	CreatedAt    time.Time `json:"created_at"`
	Duration     string    `json:"duration"`
}

// RestoreResult describes a completed restore operation.
type RestoreResult struct {
	RealmID      uuid.UUID `json:"realm_id"`
	DatabaseName string    `json:"database_name"`
	RestoredFrom string    `json:"restored_from"` // absolute path of the source backup dir
	Tables       int       `json:"tables"`
	Rows         int64     `json:"rows"`
	Duration     string    `json:"duration"`
}

// backupManifest is written to manifest.json inside each backup directory.
type backupManifest struct {
	RealmID      string           `json:"realm_id"`
	DatabaseName string           `json:"database_name"`
	Tables       []string         `json:"tables"`
	RowCounts    map[string]int64 `json:"row_counts"`
	CreatedAt    time.Time        `json:"created_at"`
}

// TenantBackupService creates and restores per-tenant database backups.
type TenantBackupService struct {
	realmDBRepo RealmDatabaseRepository
	encryption  *crypto.EncryptionService
	backupDir   string
	log         *zap.SugaredLogger
}

// NewTenantBackupService constructs a TenantBackupService.
// When backupDir is empty the default /tmp/hexxlock-backups is used.
// encryption may be nil (dev mode — passwords stored in plaintext).
func NewTenantBackupService(
	realmDBRepo RealmDatabaseRepository,
	encryption *crypto.EncryptionService,
	log *zap.SugaredLogger,
) *TenantBackupService {
	return &TenantBackupService{
		realmDBRepo: realmDBRepo,
		encryption:  encryption,
		backupDir:   defaultBackupDir,
		log:         log,
	}
}

// SetBackupDir overrides the directory used for backup files.
func (s *TenantBackupService) SetBackupDir(dir string) {
	s.backupDir = dir
}

// ---------------------------------------------------------------------------
// BackupRealm
// ---------------------------------------------------------------------------

// BackupRealm creates a backup of a realm's dedicated database to a local
// directory under backupDir.
//
// The backup directory is: {backupDir}/{realmID}/{timestamp}/
// Each table is written to a separate .jsonl file; one JSON object per line.
// A manifest.json records table names, row counts, and metadata.
//
// BackupRealm returns an error when:
//   - the realm has no dedicated database record,
//   - the encrypted password cannot be decrypted,
//   - the target backup directory cannot be created, or
//   - any table export fails.
func (s *TenantBackupService) BackupRealm(ctx context.Context, realmID uuid.UUID) (*BackupResult, error) {
	startedAt := time.Now()

	s.log.Infow("Starting realm database backup", "realm_id", realmID)

	// Resolve the realm's dedicated database record.
	rd, err := s.realmDBRepo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("BackupRealm: get realm database: %w", err)
	}
	if rd == nil {
		return nil, fmt.Errorf("BackupRealm: realm %s has no dedicated database", realmID)
	}

	// Decrypt the password.
	password, err := s.decryptPassword(rd.PasswordEncrypted)
	if err != nil {
		return nil, fmt.Errorf("BackupRealm: decrypt password: %w", err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.PathEscape(rd.Username), url.PathEscape(password),
		rd.Host, rd.Port, rd.DatabaseName, rd.SSLMode,
	)

	// Open a dedicated connection (pool is overkill for a single backup operation).
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("BackupRealm: connect to realm database: %w", err)
	}
	defer conn.Close(ctx) //nolint:errcheck

	// Enumerate tables.
	tables, err := listPublicTables(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("BackupRealm: list tables: %w", err)
	}

	// Create the backup directory.
	timestamp := startedAt.UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(s.backupDir, realmID.String(), timestamp)
	if mkErr := os.MkdirAll(backupPath, 0o700); mkErr != nil {
		return nil, fmt.Errorf("BackupRealm: create backup directory %s: %w", backupPath, mkErr)
	}

	// Export each table.
	rowCounts := make(map[string]int64, len(tables))
	var totalRows int64

	for _, tbl := range tables {
		n, exportErr := s.exportTable(ctx, conn, backupPath, tbl)
		if exportErr != nil {
			// Clean up on failure.
			_ = os.RemoveAll(backupPath)
			return nil, fmt.Errorf("BackupRealm: export table %q: %w", tbl, exportErr)
		}
		rowCounts[tbl] = n
		totalRows += n

		s.log.Debugw("Table exported", "table", tbl, "rows", n)
	}

	// Write manifest.
	manifest := backupManifest{
		RealmID:      realmID.String(),
		DatabaseName: rd.DatabaseName,
		Tables:       tables,
		RowCounts:    rowCounts,
		CreatedAt:    startedAt.UTC(),
	}
	if err := writeJSONFile(filepath.Join(backupPath, "manifest.json"), manifest); err != nil {
		_ = os.RemoveAll(backupPath)
		return nil, fmt.Errorf("BackupRealm: write manifest: %w", err)
	}

	// Calculate total size of the backup directory.
	size, _ := dirSize(backupPath)

	elapsed := time.Since(startedAt)
	s.log.Infow("Realm database backup completed",
		"realm_id", realmID,
		"database", rd.DatabaseName,
		"tables", len(tables),
		"rows", totalRows,
		"size_bytes", size,
		"duration", elapsed,
	)

	return &BackupResult{
		RealmID:      realmID,
		DatabaseName: rd.DatabaseName,
		BackupFile:   backupPath,
		Size:         size,
		Tables:       len(tables),
		Rows:         totalRows,
		CreatedAt:    startedAt.UTC(),
		Duration:     elapsed.String(),
	}, nil
}

// ---------------------------------------------------------------------------
// RestoreRealm
// ---------------------------------------------------------------------------

// RestoreRealm restores a realm's database from a backup directory.
//
// WARNING: This TRUNCATES all tables before restoring data. All existing data
// in the realm's database will be lost.
//
// Steps:
//  1. Read and parse manifest.json from backupFile.
//  2. Connect to the realm's dedicated database as admin (hexxlock superuser) so
//     that ALTER TABLE DISABLE TRIGGER ALL succeeds.
//  3. Disable triggers on all tables.
//  4. For each table in the manifest: TRUNCATE ... CASCADE, then INSERT rows from
//     the corresponding .jsonl file.
//  5. Re-enable triggers.
func (s *TenantBackupService) RestoreRealm(ctx context.Context, realmID uuid.UUID, backupFile string) (*RestoreResult, error) {
	startedAt := time.Now()

	s.log.Infow("Starting realm database restore", "realm_id", realmID, "backup_file", backupFile)

	// Read manifest.
	manifest, err := readManifest(filepath.Join(backupFile, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("RestoreRealm: read manifest: %w", err)
	}

	// Validate that the manifest belongs to this realm.
	if manifest.RealmID != realmID.String() {
		return nil, fmt.Errorf("RestoreRealm: manifest realm_id %s does not match requested realm_id %s",
			manifest.RealmID, realmID)
	}

	// Resolve database credentials.
	rd, err := s.realmDBRepo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("RestoreRealm: get realm database: %w", err)
	}
	if rd == nil {
		return nil, fmt.Errorf("RestoreRealm: realm %s has no dedicated database", realmID)
	}

	password, err := s.decryptPassword(rd.PasswordEncrypted)
	if err != nil {
		return nil, fmt.Errorf("RestoreRealm: decrypt password: %w", err)
	}

	// Connect as the realm owner (has full access to its own database).
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.PathEscape(rd.Username), url.PathEscape(password),
		rd.Host, rd.Port, rd.DatabaseName, rd.SSLMode,
	)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("RestoreRealm: connect to realm database: %w", err)
	}
	defer conn.Close(ctx) //nolint:errcheck

	// Validate table names from the manifest against a strict allowlist to prevent
	// SQL injection via crafted backup files. Table names must be valid PostgreSQL
	// identifiers: letters, digits, underscores only, starting with a letter or underscore.
	for _, tbl := range manifest.Tables {
		if !isValidTableName(tbl) {
			return nil, fmt.Errorf("RestoreRealm: invalid table name in manifest: %q", tbl)
		}
	}

	// Disable triggers (suppresses FK checks during bulk restore).
	for _, tbl := range manifest.Tables {
		if _, execErr := conn.Exec(ctx,
			fmt.Sprintf("ALTER TABLE %s DISABLE TRIGGER ALL", quoteIdent(tbl)),
		); execErr != nil {
			s.log.Warnw("Failed to disable triggers on table", "table", tbl, "error", execErr)
		}
	}

	var totalRows int64

	// Restore each table.
	for _, tbl := range manifest.Tables {
		n, restoreErr := s.importTable(ctx, conn, backupFile, tbl)
		if restoreErr != nil {
			// Re-enable triggers even on failure (best-effort cleanup).
			s.reenableTriggers(ctx, conn, manifest.Tables)
			return nil, fmt.Errorf("RestoreRealm: restore table %q: %w", tbl, restoreErr)
		}
		totalRows += n

		s.log.Debugw("Table restored", "table", tbl, "rows", n)
	}

	// Re-enable triggers.
	s.reenableTriggers(ctx, conn, manifest.Tables)

	elapsed := time.Since(startedAt)
	s.log.Infow("Realm database restore completed",
		"realm_id", realmID,
		"database", rd.DatabaseName,
		"tables", len(manifest.Tables),
		"rows", totalRows,
		"duration", elapsed,
	)

	return &RestoreResult{
		RealmID:      realmID,
		DatabaseName: rd.DatabaseName,
		RestoredFrom: backupFile,
		Tables:       len(manifest.Tables),
		Rows:         totalRows,
		Duration:     elapsed.String(),
	}, nil
}

// ---------------------------------------------------------------------------
// ListBackups
// ---------------------------------------------------------------------------

// ListBackups returns the available backups for a realm by scanning the backup
// directory structure: {backupDir}/{realmID}/*/ where each subdirectory is a
// timestamped backup containing a manifest.json.
//
// Backups are returned in reverse chronological order (newest first).
func (s *TenantBackupService) ListBackups(_ context.Context, realmID uuid.UUID) ([]BackupResult, error) {
	realmDir := filepath.Join(s.backupDir, realmID.String())

	entries, err := os.ReadDir(realmDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupResult{}, nil
		}
		return nil, fmt.Errorf("ListBackups: read realm backup dir: %w", err)
	}

	var results []BackupResult

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		backupPath := filepath.Join(realmDir, entry.Name())
		manifestPath := filepath.Join(backupPath, "manifest.json")

		manifest, err := readManifest(manifestPath)
		if err != nil {
			// Skip directories without a valid manifest (partial / corrupt backups).
			s.log.Warnw("Skipping backup directory with invalid manifest",
				"path", backupPath, "error", err)
			continue
		}

		size, _ := dirSize(backupPath)

		var totalRows int64
		for _, n := range manifest.RowCounts {
			totalRows += n
		}

		results = append(results, BackupResult{
			RealmID:      realmID,
			DatabaseName: manifest.DatabaseName,
			BackupFile:   backupPath,
			Size:         size,
			Tables:       len(manifest.Tables),
			Rows:         totalRows,
			CreatedAt:    manifest.CreatedAt,
		})
	}

	// Sort newest first by reversing (entries from ReadDir are alphabetical;
	// our timestamp format "20060102T150405Z" sorts lexicographically = chronologically).
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// decryptPassword decrypts an encrypted realm database password.
// Returns the raw value unchanged when no encryption service is configured (dev mode).
func (s *TenantBackupService) decryptPassword(enc string) (string, error) {
	if s.encryption == nil {
		return enc, nil
	}
	if !crypto.IsEncrypted(enc) {
		return enc, nil
	}
	return s.encryption.Decrypt(enc)
}

// reenableTriggers re-enables triggers on all tables (best-effort).
func (s *TenantBackupService) reenableTriggers(ctx context.Context, conn *pgx.Conn, tables []string) {
	for _, tbl := range tables {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf("ALTER TABLE %s ENABLE TRIGGER ALL", quoteIdent(tbl)),
		); err != nil {
			s.log.Warnw("Failed to re-enable triggers", "table", tbl, "error", err)
		}
	}
}

// exportTable writes all rows of tableName from conn to a .jsonl file in dir.
// Each line is a JSON object whose keys are column names.
// Returns the number of rows written.
func (s *TenantBackupService) exportTable(ctx context.Context, conn *pgx.Conn, dir, tableName string) (int64, error) {
	rows, err := conn.Query(ctx, fmt.Sprintf("SELECT * FROM %s", quoteIdent(tableName)))
	if err != nil {
		return 0, fmt.Errorf("exportTable %q: query: %w", tableName, err)
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	if fields == nil {
		// Table exists but has no columns — write an empty file.
		f, createErr := os.Create(filepath.Join(dir, tableName+".jsonl")) //nolint:gosec // path is validated before use
		if createErr != nil {
			return 0, fmt.Errorf("exportTable %q: create file: %w", tableName, createErr)
		}
		_ = f.Close()
		return 0, nil
	}

	// Pre-build column name slice once.
	cols := make([]string, len(fields))
	for i, fd := range fields {
		cols[i] = fd.Name
	}

	f, err := os.Create(filepath.Join(dir, tableName+".jsonl")) //nolint:gosec // path is validated before use
	if err != nil {
		return 0, fmt.Errorf("exportTable %q: create file: %w", tableName, err)
	}
	defer f.Close() //nolint:errcheck

	enc := json.NewEncoder(f)
	var rowCount int64

	for rows.Next() {
		values, scanErr := rows.Values()
		if scanErr != nil {
			return rowCount, fmt.Errorf("exportTable %q: scan row: %w", tableName, scanErr)
		}

		// Build a map[string]any for JSON serialisation.
		rowMap := make(map[string]any, len(cols))
		for i, col := range cols {
			rowMap[col] = values[i]
		}

		if encErr := enc.Encode(rowMap); encErr != nil {
			return rowCount, fmt.Errorf("exportTable %q: encode row: %w", tableName, encErr)
		}
		rowCount++
	}

	if err := rows.Err(); err != nil {
		return rowCount, fmt.Errorf("exportTable %q: rows error: %w", tableName, err)
	}

	return rowCount, nil
}

// importTable truncates tableName and reloads it from {dir}/{tableName}.jsonl.
// Returns the number of rows inserted.
func (s *TenantBackupService) importTable(ctx context.Context, conn *pgx.Conn, dir, tableName string) (int64, error) {
	// Truncate with CASCADE to handle FK references between tables.
	if _, err := conn.Exec(ctx,
		fmt.Sprintf("TRUNCATE TABLE %s CASCADE", quoteIdent(tableName)),
	); err != nil {
		return 0, fmt.Errorf("importTable %q: truncate: %w", tableName, err)
	}

	f, err := os.Open(filepath.Join(dir, tableName+".jsonl")) //nolint:gosec // path is validated before use
	if err != nil {
		if os.IsNotExist(err) {
			// Backup file for this table is missing — treat as empty table.
			return 0, nil
		}
		return 0, fmt.Errorf("importTable %q: open file: %w", tableName, err)
	}
	defer f.Close() //nolint:errcheck

	dec := json.NewDecoder(f)
	var rowCount int64

	for dec.More() {
		var rowMap map[string]any
		if decErr := dec.Decode(&rowMap); decErr != nil {
			return rowCount, fmt.Errorf("importTable %q: decode row %d: %w", tableName, rowCount+1, decErr)
		}

		if len(rowMap) == 0 {
			continue
		}

		// Build the INSERT statement dynamically.
		cols := make([]string, 0, len(rowMap))
		vals := make([]any, 0, len(rowMap))
		placeholders := make([]string, 0, len(rowMap))
		i := 1
		for col, val := range rowMap {
			cols = append(cols, quoteIdent(col))
			vals = append(vals, val)
			placeholders = append(placeholders, fmt.Sprintf("$%d", i))
			i++
		}

		query := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s)",
			quoteIdent(tableName),
			strings.Join(cols, ", "),
			strings.Join(placeholders, ", "),
		)

		if _, execErr := conn.Exec(ctx, query, vals...); execErr != nil {
			return rowCount, fmt.Errorf("importTable %q: insert row %d: %w", tableName, rowCount+1, execErr)
		}
		rowCount++
	}

	return rowCount, nil
}

// writeJSONFile serialises v as pretty-printed JSON and writes it to path.
func writeJSONFile(path string, v any) error {
	f, err := os.Create(path) //nolint:gosec // path is validated before use
	if err != nil {
		return fmt.Errorf("writeJSONFile: create %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("writeJSONFile: encode to %s: %w", path, err)
	}
	return nil
}

// readManifest deserialises the manifest.json file at path.
func readManifest(path string) (*backupManifest, error) {
	f, err := os.Open(path) //nolint:gosec // path is validated before use
	if err != nil {
		return nil, fmt.Errorf("readManifest: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	var m backupManifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, fmt.Errorf("readManifest: decode %s: %w", path, err)
	}
	return &m, nil
}

// dirSize walks dir and returns the total byte size of all regular files.
func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}

// isValidTableName validates that a table name is a safe PostgreSQL identifier.
// Prevents SQL injection via crafted backup manifest files.
func isValidTableName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for i, r := range name {
		if i == 0 && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}
